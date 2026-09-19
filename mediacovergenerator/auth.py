from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path


class AuthenticationError(ValueError):
    """Raised when a supplied account value cannot be used."""


class AuthenticationManager:
    """Persist one local administrator and keep short-lived server sessions."""

    _iterations = 600_000
    _session_lifetime = timedelta(hours=12)

    def __init__(self, project_root: Path):
        self.auth_path = project_root / "data" / "auth.json"
        self._lock = threading.RLock()
        self._sessions: dict[str, tuple[str, datetime]] = {}

    def is_configured(self) -> bool:
        with self._lock:
            return self.auth_path.exists()

    def setup(self, username: str, password: str) -> str:
        username = self._validate_username(username)
        self._validate_password(password)
        with self._lock:
            if self.auth_path.exists():
                raise AuthenticationError("管理员账号已经初始化")
            salt = secrets.token_bytes(16)
            payload = {
                "username": username,
                "password_hash": self._hash_password(password, salt),
                "salt": base64.b64encode(salt).decode("ascii"),
                "iterations": self._iterations,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self.auth_path.parent.mkdir(parents=True, exist_ok=True)
            self.auth_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            self.auth_path.chmod(0o600)
            return username

    def authenticate(self, username: str, password: str) -> str | None:
        with self._lock:
            payload = self._load()
            if payload is None:
                return None
            stored_username = str(payload.get("username") or "")
            try:
                salt = base64.b64decode(str(payload.get("salt") or ""), validate=True)
                iterations = int(payload.get("iterations") or self._iterations)
            except (ValueError, TypeError):
                return None
            candidate = self._hash_password(password, salt, iterations)
            password_matches = hmac.compare_digest(candidate, str(payload.get("password_hash") or ""))
            username_matches = hmac.compare_digest(username.strip(), stored_username)
            return stored_username if username_matches and password_matches else None

    def create_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge_expired_sessions()
            self._sessions[token] = (username, datetime.now(timezone.utc) + self._session_lifetime)
        return token

    def get_session_user(self, token: str | None) -> str | None:
        if not token:
            return None
        with self._lock:
            self._purge_expired_sessions()
            session = self._sessions.get(token)
            return session[0] if session else None

    def delete_session(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    @property
    def session_max_age(self) -> int:
        return int(self._session_lifetime.total_seconds())

    def _load(self) -> dict[str, object] | None:
        if not self.auth_path.exists():
            return None
        try:
            value = json.loads(self.auth_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    @classmethod
    def _hash_password(cls, password: str, salt: bytes, iterations: int | None = None) -> str:
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations or cls._iterations,
        )
        return base64.b64encode(digest).decode("ascii")

    @staticmethod
    def _validate_username(username: str) -> str:
        value = username.strip()
        if not 3 <= len(value) <= 64:
            raise AuthenticationError("用户名长度应为 3 到 64 个字符")
        return value

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 10:
            raise AuthenticationError("密码至少需要 10 个字符")

    def _purge_expired_sessions(self) -> None:
        now = datetime.now(timezone.utc)
        for token, (_, expires_at) in list(self._sessions.items()):
            if expires_at <= now:
                self._sessions.pop(token, None)
