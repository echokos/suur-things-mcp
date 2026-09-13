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
import stat
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
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # mkdir and SQLite creation both honor the caller's umask, which may be
        # deliberately permissive in a service manager. Tighten existing and new
        # paths explicitly before accepting any secrets.
        os.chmod(self.path.parent, 0o700)
        self._init()
        os.chmod(self.path, 0o600)

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
                CREATE TABLE IF NOT EXISTS grace_proposals (
                    proposal_id TEXT PRIMARY KEY,
                    browser_session_id TEXT NOT NULL,
                    browser_principal TEXT NOT NULL,
                    change_json TEXT NOT NULL,
                    browser_approved_at INTEGER,
                    grace_decision_id TEXT UNIQUE,
                    grace_profile TEXT,
                    grace_scopes TEXT,
                    grace_approved INTEGER,
                    execution_state TEXT NOT NULL DEFAULT 'pending',
                    created_at INTEGER NOT NULL,
                    completed_at INTEGER
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

    def create_grace_proposal(
        self, proposal_id: str, browser_session_id: str, browser_principal: str, change: dict[str, str]
    ) -> None:
        """Persist a browser-bound proposal before delivering it to Grace."""
        with self._connect() as con:
            con.execute(
                "INSERT INTO grace_proposals (proposal_id, browser_session_id, browser_principal, change_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (proposal_id, browser_session_id, browser_principal, json.dumps(change, sort_keys=True), int(time.time())),
            )

    def approve_grace_proposal_from_browser(self, proposal_id: str, browser_session_id: str) -> bool:
        """One browser session may approve its own proposal once, never execute it."""
        with self._connect() as con:
            row = con.execute(
                "SELECT browser_approved_at, execution_state FROM grace_proposals "
                "WHERE proposal_id = ? AND browser_session_id = ?",
                (proposal_id, browser_session_id),
            ).fetchone()
            if row is None or row["browser_approved_at"] is not None or row["execution_state"] != "pending":
                return False
            con.execute("UPDATE grace_proposals SET browser_approved_at = ? WHERE proposal_id = ?", (int(time.time()), proposal_id))
        return True

    def record_grace_decision(
        self, proposal_id: str, decision_id: str, profile: str, scopes: Iterable[str], approved: bool
    ) -> bool:
        """Accept exactly one signed, update-scoped decision from the Grace profile."""
        cleaned_scopes = sorted({str(scope) for scope in scopes})
        if not decision_id or profile != "grace" or "update" not in cleaned_scopes:
            return False
        with self._connect() as con:
            row = con.execute(
                "SELECT grace_decision_id, execution_state FROM grace_proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
            if row is None or row["grace_decision_id"] is not None or row["execution_state"] != "pending":
                return False
            try:
                con.execute(
                    "UPDATE grace_proposals SET grace_decision_id = ?, grace_profile = ?, grace_scopes = ?, grace_approved = ? "
                    "WHERE proposal_id = ?",
                    (decision_id, profile, json.dumps(cleaned_scopes), int(approved), proposal_id),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def claim_ready_grace_mutation(self, proposal_id: str) -> dict[str, str] | None:
        """Atomically claim a proposal only after both independent approvals exist."""
        with self._connect() as con:
            row = con.execute(
                "SELECT change_json FROM grace_proposals WHERE proposal_id = ? AND browser_approved_at IS NOT NULL "
                "AND grace_approved = 1 AND execution_state = 'pending'",
                (proposal_id,),
            ).fetchone()
            if row is None:
                return None
            changed = con.execute(
                "UPDATE grace_proposals SET execution_state = 'executing' WHERE proposal_id = ? AND execution_state = 'pending'",
                (proposal_id,),
            ).rowcount
            if changed != 1:
                return None
        return json.loads(str(row["change_json"]))

    def finish_grace_mutation(self, proposal_id: str, success: bool) -> None:
        state = "executed" if success else "failed"
        with self._connect() as con:
            con.execute(
                "UPDATE grace_proposals SET execution_state = ?, completed_at = ? WHERE proposal_id = ? AND execution_state = 'executing'",
                (state, int(time.time()), proposal_id),
            )

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


def service_secret(name: str, env_name: str) -> str | None:
    """Read a launchd-safe secret file, with an env fallback for local development.

    Installations set only ``SUUR_SECRET_DIR`` on their LaunchAgent.  Secret
    values stay in regular 0600 files under that private directory and therefore
    never appear in a plist command line or process arguments.
    """
    explicit = os.environ.get(f"{env_name}_FILE")
    root = Path(os.environ.get("SUUR_SECRET_DIR") or Path.home() / ".config" / "suur-things-mcp" / "secrets")
    path = Path(explicit) if explicit else root / name
    try:
        st = path.lstat()
        if not path.is_file() or stat.S_IMODE(st.st_mode) != 0o600:
            raise OSError("service secret must be a regular 0600 file")
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    except OSError:
        pass
    return os.environ.get(env_name) or None
