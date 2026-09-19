from __future__ import annotations

import os
from pathlib import Path

from fastapi import Body, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from mediacovergenerator.auth import AuthenticationError, AuthenticationManager
from mediacovergenerator.jobs import JobManager
from mediacovergenerator.models import (
    AppConfig,
    AuthCredentials,
    DeleteRequest,
    GenerateRequest,
    HealthResponse,
    HistoryRecord,
    JobSummary,
    LibraryInfo,
)
from mediacovergenerator.scheduler import AppScheduler
from mediacovergenerator.storage import ConfigRepository, HistoryRepository, WebhookRepository
from mediacovergenerator.webhooks import EmbyWebhookManager


PROJECT_ROOT = Path(__file__).resolve().parent.parent
config_repository = ConfigRepository(PROJECT_ROOT)
history_repository = HistoryRepository(PROJECT_ROOT)
webhook_repository = WebhookRepository(PROJECT_ROOT)
auth_manager = AuthenticationManager(PROJECT_ROOT)
job_manager = JobManager(PROJECT_ROOT, config_repository, history_repository)
scheduler = AppScheduler(PROJECT_ROOT, config_repository, job_manager)
webhook_manager = EmbyWebhookManager(PROJECT_ROOT, config_repository, job_manager)

app = FastAPI(title="MediaCoverGenerator", version="1.0.0")
app.mount(
    "/assets/images",
    StaticFiles(directory=PROJECT_ROOT / "mediacovergenerator" / "assets" / "images"),
    name="images",
)

SESSION_COOKIE = "mcg_session"
PUBLIC_PATHS = {"/", "/favicon.ico", "/webhooks/emby"}


def _use_secure_cookie(request: Request) -> bool:
    configured = os.getenv("MCG_COOKIE_SECURE", "").strip().lower()
    if configured in {"1", "true", "yes"}:
        return True
    if configured in {"0", "false", "no"}:
        return False
    return request.url.scheme == "https"


def _set_session_cookie(response: JSONResponse, request: Request, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=auth_manager.session_max_age,
        httponly=True,
        secure=_use_secure_cookie(request),
        samesite="lax",
        path="/",
    )


@app.middleware("http")
async def require_authenticated_session(request: Request, call_next):
    path = request.url.path
    if (
        path in PUBLIC_PATHS
        or path.startswith("/assets/")
        or path.startswith("/auth/")
    ):
        response = await call_next(request)
        if path.startswith("/auth/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    if not auth_manager.get_session_user(request.cookies.get(SESSION_COOKIE)):
        return JSONResponse(
            status_code=401,
            content={"detail": "需要登录后才能访问"},
            headers={"Cache-Control": "no-store"},
        )
    response = await call_next(request)
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.on_event("startup")
def on_startup() -> None:
    scheduler.start()


@app.on_event("shutdown")
def on_shutdown() -> None:
    scheduler.shutdown()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(PROJECT_ROOT / "mediacovergenerator" / "web" / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    return FileResponse(
        PROJECT_ROOT / "mediacovergenerator" / "assets" / "images" / "favicon.svg",
        media_type="image/svg+xml",
    )


@app.get("/auth/status")
def get_auth_status(request: Request) -> dict[str, object]:
    username = auth_manager.get_session_user(request.cookies.get(SESSION_COOKIE))
    return {
        "configured": auth_manager.is_configured(),
        "authenticated": bool(username),
        "username": username or "",
    }


@app.post("/auth/setup")
def setup_authentication(credentials: AuthCredentials, request: Request) -> JSONResponse:
    try:
        username = auth_manager.setup(credentials.username, credentials.password)
    except AuthenticationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    token = auth_manager.create_session(username)
    response = JSONResponse(content={"username": username})
    _set_session_cookie(response, request, token)
    return response


@app.post("/auth/login")
def login(credentials: AuthCredentials, request: Request) -> JSONResponse:
    username = auth_manager.authenticate(credentials.username, credentials.password)
    if not username:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    token = auth_manager.create_session(username)
    response = JSONResponse(content={"username": username})
    _set_session_cookie(response, request, token)
    return response


@app.post("/auth/logout")
def logout(request: Request) -> JSONResponse:
    auth_manager.delete_session(request.cookies.get(SESSION_COOKIE))
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(key=SESSION_COOKIE, path="/")
    return response


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    config = config_repository.load()
    from mediacovergenerator.emby import EmbyClient

    client = EmbyClient(config.emby)
    reachable = client.ping() if client.is_configured() else False
    return HealthResponse(
        status="ok" if reachable or not client.is_configured() else "degraded",
        configured=client.is_configured(),
        emby_reachable=reachable,
        active_jobs=job_manager.active_jobs(),
    )


@app.get("/config", response_model=AppConfig)
def get_config() -> AppConfig:
    return config_repository.load()


@app.put("/config", response_model=AppConfig)
def put_config(config: AppConfig) -> AppConfig:
    if config.webhook.enabled and not config.webhook.token.strip():
        raise HTTPException(status_code=422, detail="启用入库监控时必须设置 Webhook Token")
    saved = config_repository.save(config)
    scheduler.reload()
    return saved


@app.get("/libraries", response_model=list[LibraryInfo])
def get_libraries() -> list[LibraryInfo]:
    config = config_repository.load()
    from mediacovergenerator.emby import EmbyClient

    client = EmbyClient(config.emby)
    if not client.is_configured():
        raise HTTPException(status_code=400, detail="Emby is not configured")
    try:
        return client.list_libraries()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/jobs/generate", response_model=JobSummary)
def generate(request: GenerateRequest | None = Body(default=None)) -> JobSummary:
    payload = request or GenerateRequest()
    return job_manager.start(payload.library_ids or None)


@app.post("/jobs/generate/{library_id}", response_model=JobSummary)
def generate_single(library_id: str) -> JobSummary:
    return job_manager.start([library_id], title="生成单个媒体库封面")


@app.get("/jobs", response_model=list[JobSummary])
def list_jobs() -> list[JobSummary]:
    return job_manager.list_jobs()


@app.post("/jobs/{job_id}/cancel", response_model=JobSummary)
def cancel_job(job_id: str) -> JobSummary:
    try:
        return job_manager.cancel(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc


@app.delete("/jobs/{job_id}")
def delete_job(job_id: str) -> dict[str, bool]:
    try:
        job_manager.delete(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"deleted": True}


@app.post("/jobs/delete")
def delete_jobs(request: DeleteRequest) -> dict[str, object]:
    deleted, blocked, missing = job_manager.delete_many(request.ids)
    return {
        "deleted": deleted,
        "blocked_ids": blocked,
        "missing_ids": missing,
    }


@app.get("/history", response_model=list[HistoryRecord])
def get_history(limit: int = 10) -> list[HistoryRecord]:
    return history_repository.list_recent(limit=limit)


@app.get("/history/{record_id}/image")
def get_history_image(record_id: str) -> FileResponse:
    record = history_repository.get(record_id)
    if not record or not record.saved_path:
        raise HTTPException(status_code=404, detail="History image not found")
    path = Path(record.saved_path)
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="History image file not found")
    return FileResponse(path)


@app.delete("/history/{record_id}")
def delete_history(record_id: str) -> dict[str, bool]:
    deleted = history_repository.delete(record_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="History record not found")
    return {"deleted": True}


@app.post("/history/delete")
def delete_history_many(request: DeleteRequest) -> dict[str, int]:
    return {"deleted": history_repository.delete_many(request.ids)}


@app.delete("/history")
def clear_history() -> dict[str, int]:
    return {"deleted": history_repository.clear()}


@app.get("/webhooks/last")
def get_last_webhook() -> dict[str, object]:
    return webhook_repository.load() or {}


@app.post("/webhooks/emby")
async def emby_webhook(
    request: Request,
    token: str | None = Query(default=None),
    x_webhook_token: str | None = Header(default=None),
) -> dict[str, object]:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    effective_token = token or x_webhook_token
    webhook_repository.save(payload, token_provided=bool(effective_token))
    try:
        return webhook_manager.handle(payload, effective_token)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except LookupError as exc:
        return JSONResponse(
            status_code=202,
            content={
                "accepted": False,
                "scheduled": False,
                "reason": str(exc),
            },
        )
