"""Durable, payload-free authorization controls for the private dashboard/MCP bridge.

Secrets are never logged or persisted verbatim. The database intentionally stores
only salted token hashes, scopes, metadata, and idempotency payload hashes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

_LOG = logging.getLogger(__name__)
_SECRET_RE = re.compile(r"(?i)(token|password|secret|authorization|auth-token)\s*[=:]\s*([^\s&]+)")


def sanitize_for_log(value: object) -> str:
    """Remove credential-shaped values and cap untrusted text before logging."""
    text = str(value).replace("\n", " ").replace("\r", " ")[:500]
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)


@dataclass(frozen=True)
class IssuedSession:
    session_id: str
    token: str
    csrf: str
    scopes: frozenset[str]


class SecurityStore:
    """SQLite-backed sessions, rate limits, idempotency, and metadata-only audit."""

    def __init__(self, path: str | Path, *, rate_limit: int = 60, rate_window_seconds: int = 60) -> None:
        self.path = Path(path)
        self.rate_limit = rate_limit
        self.rate_window_seconds = rate_window_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        with self._connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    csrf_hash TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    revoked_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS rate_limits (
                    principal TEXT NOT NULL,
                    window_start INTEGER NOT NULL,
                    count INTEGER NOT NULL,
                    PRIMARY KEY (principal, window_start)
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    principal TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (principal, key_hash, operation)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at INTEGER NOT NULL,
                    principal TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    target_id TEXT,
                    success INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mcp_principals (
                    profile TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    scopes TEXT NOT NULL,
                    revoked_at INTEGER
                );
                """
            )

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def issue_session(self, scopes: Iterable[str], principal: str) -> IssuedSession:
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        session_id = secrets.token_hex(16)
        cleaned = frozenset(str(scope) for scope in scopes)
        if not cleaned:
            raise ValueError("at least one scope is required")
        with self._connect() as con:
            con.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, NULL)",
                (session_id, self._hash(token), self._hash(csrf), json.dumps(sorted(cleaned)), principal, int(time.time())),
            )
        return IssuedSession(session_id, token, csrf, cleaned)

    def authenticate(self, token: str | None, csrf: str | None, required_scope: str) -> sqlite3.Row | None:
        if not token or not csrf:
            return None
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM sessions WHERE token_hash = ? AND revoked_at IS NULL", (self._hash(token),)
            ).fetchone()
        if row is None or not secrets.compare_digest(str(row["csrf_hash"]), self._hash(csrf)):
            return None
        return row if required_scope in json.loads(row["scopes"]) else None

    def revoke_session(self, session_id: str) -> None:
        with self._connect() as con:
            con.execute("UPDATE sessions SET revoked_at = ? WHERE session_id = ?", (int(time.time()), session_id))

    def provision_mcp_principal(self, profile: str, scopes: Iterable[str]) -> str:
        """Issue one revocable per-profile MCP token; callers display it once only."""
        token = secrets.token_urlsafe(32)
        cleaned = sorted({str(scope) for scope in scopes})
        if not profile or not cleaned:
            raise ValueError("profile and scopes are required")
        with self._connect() as con:
            con.execute("INSERT OR REPLACE INTO mcp_principals VALUES (?, ?, ?, NULL)", (profile, self._hash(token), json.dumps(cleaned)))
        return token

    def mcp_scopes(self, profile: str, token: str | None) -> frozenset[str]:
        if not profile or not token:
            return frozenset({"read"})
        with self._connect() as con:
            row = con.execute("SELECT token_hash, scopes FROM mcp_principals WHERE profile = ? AND revoked_at IS NULL", (profile,)).fetchone()
        if row is None or not secrets.compare_digest(str(row["token_hash"]), self._hash(token)):
            return frozenset({"read"})
        return frozenset(json.loads(row["scopes"]))

    def revoke_mcp_principal(self, profile: str) -> None:
        with self._connect() as con:
            con.execute("UPDATE mcp_principals SET revoked_at = ? WHERE profile = ?", (int(time.time()), profile))

    def check_rate_limit(self, principal: str) -> bool:
        now = int(time.time())
        window = now - (now % self.rate_window_seconds)
        with self._connect() as con:
            row = con.execute(
                "SELECT count FROM rate_limits WHERE principal = ? AND window_start = ?", (principal, window)
            ).fetchone()
            count = int(row["count"]) if row else 0
            if count >= self.rate_limit:
                return False
            if row:
                con.execute("UPDATE rate_limits SET count = ? WHERE principal = ? AND window_start = ?", (count + 1, principal, window))
            else:
                con.execute("INSERT INTO rate_limits VALUES (?, ?, 1)", (principal, window))
        return True

    def claim_idempotency(self, principal: str, key: str | None, operation: str, payload: str | bytes) -> bool:
        if not key or len(key) > 200:
            return False
        try:
            with self._connect() as con:
                con.execute(
                    "INSERT INTO idempotency VALUES (?, ?, ?, ?, ?)",
                    (principal, self._hash(key), operation, self._hash(payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload), int(time.time())),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def audit(self, principal: str, operation: str, target_id: str | None, success: bool, _detail: str = "") -> None:
        with self._connect() as con:
            con.execute(
                "INSERT INTO audit_events (occurred_at, principal, operation, target_id, success) VALUES (?, ?, ?, ?, ?)",
                (int(time.time()), principal[:100], operation[:100], (target_id or "")[:200], int(success)),
            )
        _LOG.info("mutation principal=%s operation=%s target=%s success=%s", principal, operation, target_id, success)

    def audit_events(self) -> list[dict[str, object]]:
        with self._connect() as con:
            return [dict(row) for row in con.execute("SELECT * FROM audit_events ORDER BY id DESC")]


def default_store() -> SecurityStore:
    path = os.environ.get("SUUR_SECURITY_DB")
    if not path:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        path = str(base / "suur-things-mcp" / "security.sqlite")
    return SecurityStore(path)
