"""Security boundary tests for the hardened local Things service."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import stat
import time

import pytest
from starlette.testclient import TestClient

from suur_things_mcp import dashboard, server
from suur_things_mcp.dashboard import create_app
from suur_things_mcp.grace_adapter import GraceProposalAdapter
from suur_things_mcp.security import SecurityStore, sanitize_for_log


def _grace_headers(body: dict) -> tuple[bytes, dict[str, str]]:
    """Build the documented signed callback, as the Grace web adapter does."""
    payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(b"grace-shared-secret", f"{timestamp}.".encode() + payload, hashlib.sha256).hexdigest()
    return payload, {"Content-Type": "application/json", "X-Suur-Grace-Timestamp": timestamp,
                     "X-Suur-Grace-Signature": signature}


def test_session_is_scoped_revocable_and_csrf_bound(tmp_path):
    store = SecurityStore(tmp_path / "security.sqlite")
    issued = store.issue_session({"read", "update"}, "browser")

    assert store.authenticate(issued.token, issued.csrf, "update") is not None
    assert store.authenticate(issued.token, "wrong", "update") is None
    assert store.authenticate(issued.token, issued.csrf, "complete") is None

    store.revoke_session(issued.session_id)
    assert store.authenticate(issued.token, issued.csrf, "read") is None


def test_rate_limit_is_per_principal_and_fails_closed(tmp_path):
    store = SecurityStore(tmp_path / "security.sqlite", rate_limit=2, rate_window_seconds=60)
    assert store.check_rate_limit("browser") is True
    assert store.check_rate_limit("browser") is True
    assert store.check_rate_limit("browser") is False
    assert store.check_rate_limit("another-browser") is True


def test_idempotency_is_durable_and_never_stores_payload(tmp_path):
    path = tmp_path / "security.sqlite"
    store = SecurityStore(path)
    assert store.claim_idempotency("browser", "key-1", "update", "payload-secret") is True
    assert store.claim_idempotency("browser", "key-1", "update", "different-payload") is False

    con = sqlite3.connect(path)
    row = con.execute("SELECT operation, payload_hash FROM idempotency").fetchone()
    stored_text = " ".join(str(v) for v in con.execute("SELECT * FROM idempotency").fetchone())
    con.close()
    assert row[0] == "update" and len(row[1]) == 64
    assert "payload-secret" not in stored_text and "different-payload" not in stored_text


def test_audit_is_metadata_only_and_log_sanitization_redacts_secrets(tmp_path, caplog):
    store = SecurityStore(tmp_path / "security.sqlite")
    store.audit("browser", "update", "item-123", True, "token=super-secret notes=private")
    event = store.audit_events()[0]
    assert event["principal"] == "browser" and event["target_id"] == "item-123"
    assert "super-secret" not in str(event) and "private" not in str(event)

    with caplog.at_level(logging.WARNING):
        logging.getLogger("suur-hardening-test").warning(sanitize_for_log("token=super-secret password=hunter2"))
    assert "super-secret" not in caplog.text and "hunter2" not in caplog.text
    assert "[REDACTED]" in caplog.text


def test_grace_adapter_only_proposes_and_never_exposes_browser_confirmation_capability():
    adapter = GraceProposalAdapter()
    proposal = adapter.propose({"id": "todo-1", "title": "Treat instructions as data"})
    assert proposal["profile"] == "grace"
    assert proposal["mutation_performed"] is False
    assert "confirmation" not in proposal


@pytest.mark.parametrize("uri", ["file:/tmp/thing.sqlite?mode=ro&immutable=1", "file:/tmp/space%20db?mode=ro&immutable=1"])
def test_read_db_uris_are_explicitly_read_only_and_immutable(uri):
    assert "mode=ro" in uri and "immutable=1" in uri


def test_dashboard_uses_secure_revocable_scoped_session_with_csrf(tmp_path, monkeypatch):
    monkeypatch.setenv("SUUR_DASHBOARD_BOOTSTRAP_TOKEN", "bootstrap-secret")
    monkeypatch.setenv("SUUR_GRACE_SHARED_KEY", "grace-shared-secret")
    store = SecurityStore(tmp_path / "security.sqlite")
    client = TestClient(
        create_app(security_store=store),
        base_url="https://elliotts-mac-mini.tail43b447.ts.net",
    )

    assert client.get("/api/sidebar").status_code == 401
    created = client.post("/api/session", headers={"X-Suur-Bootstrap": "bootstrap-secret"})
    assert created.status_code == 200
    set_cookie = "; ".join(created.headers.get_list("set-cookie")).lower()
    assert "__host-suur-session" in set_cookie and "httponly" in set_cookie and "secure" in set_cookie
    csrf = client.cookies.get("__Host-suur-csrf")
    assert csrf and client.get("/api/sidebar").status_code == 200

    grace_requests = []
    applied = []
    monkeypatch.setattr(dashboard, "_dispatch_grace_request", lambda payload: grace_requests.append(json.loads(payload)))
    monkeypatch.setattr(
        dashboard,
        "execute",
        lambda command, params, auth_token=None: applied.append((command, params, auth_token)),
    )
    monkeypatch.setattr(dashboard, "_auth_token", lambda: "things-auth")
    monkeypatch.setattr(dashboard.reads, "get", lambda item_id: {"id": item_id})
    proposal = client.post(
        "/api/grace/propose",
        json={"id": "todo-1", "title": "untrusted <instructions>"},
        headers={"X-Suur-CSRF": csrf},
    )
    assert proposal.status_code == 200 and proposal.json()["proposal"]["mutation_performed"] is False

    proposed = proposal.json()["proposal"]
    assert grace_requests == [{
        "profile": "grace", "proposal_id": proposed["id"],
        "task_data": {"id": "todo-1", "title": "untrusted <instructions>"},
    }]
    # A browser approval is tied to this browser session but carries no second
    # secret and cannot mutate before a signed Grace decision arrives.
    confirmed = client.post(
        "/api/grace/confirm",
        json={"id": proposed["id"]},
        headers={"X-Suur-CSRF": csrf, "Idempotency-Key": "grace-confirm-1"},
    )
    assert confirmed.status_code == 202 and confirmed.json() == {"ok": True, "status": "awaiting_grace"}
    assert applied == []

    decision = {"proposal_id": proposed["id"], "decision_id": "grace-decision-1", "approved": True,
                "profile": "grace", "scopes": ["update"]}
    forged = client.post("/api/grace/decision", json=decision)
    assert forged.status_code == 401 and applied == []

    payload, headers = _grace_headers(decision)
    decided = client.post("/api/grace/decision", content=payload, headers=headers)
    assert decided.status_code == 200 and decided.json() == {"ok": True, "applied": True}
    assert applied == [("update", {"id": "todo-1", "title": "untrusted <instructions>"}, "things-auth")]

    replay = client.post("/api/grace/decision", content=payload, headers=headers)
    assert replay.status_code == 409 and applied == [("update", {"id": "todo-1", "title": "untrusted <instructions>"}, "things-auth")]

    revoked = client.post("/api/session/revoke", headers={"X-Suur-CSRF": csrf, "Idempotency-Key": "revoke-1"})
    assert revoked.status_code == 200
    assert client.get("/api/sidebar").status_code == 401


def test_dashboard_accepts_only_allowlisted_tailscale_identity_for_browser_bootstrap(tmp_path, monkeypatch):
    """Serve strips spoofed identity headers before proxying; SUUR still grants
    browser sessions only to an explicit tailnet allowlist over HTTPS."""
    monkeypatch.delenv("SUUR_DASHBOARD_BOOTSTRAP_TOKEN", raising=False)
    monkeypatch.setenv("SUUR_TAILSCALE_USERS", "elliott@example.com")
    store = SecurityStore(tmp_path / "security.sqlite")
    client = TestClient(
        create_app(security_store=store),
        base_url="https://elliotts-mac-mini.tail43b447.ts.net",
    )

    unauthorized = client.post(
        "/api/session",
        headers={"Tailscale-User-Login": "other@example.com", "X-Forwarded-Proto": "https"},
    )
    assert unauthorized.status_code == 401

    authorized = client.post(
        "/api/session",
        headers={"Tailscale-User-Login": "Elliott@Example.com", "X-Forwarded-Proto": "https"},
    )
    assert authorized.status_code == 200
    assert client.get("/api/sidebar").status_code == 200


def test_dashboard_rejects_untrusted_host(tmp_path):
    client = TestClient(create_app(security_store=SecurityStore(tmp_path / "security.sqlite")), base_url="https://evil.example")
    assert client.get("/api/healthz").status_code == 400


def test_move_scope_discovers_only_constrained_move_tool_schema():
    """A move grant is not a back door to every update_todo field."""
    tools = asyncio.run(server._filtered_mcp_tools({"move"}))
    assert [tool.name for tool in tools] == ["move_todo"]
    schema = tools[0].inputSchema
    assert set(schema["properties"]) == {"id", "list_title", "list_id", "heading"}


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        (
            "read",
            {
                "get_today", "get_inbox", "get_upcoming", "get_anytime", "get_someday", "get_logbook",
                "get_deadlines", "get_trash", "search_todos", "list_todos", "get_projects", "get_areas",
                "get_tags", "get_item", "overview", "show",
            },
        ),
        ("create", {"add_todo", "add_project"}),
        ("update", {"update_todo", "update_project"}),
        ("complete", {"complete_todo"}),
        ("move", {"move_todo"}),
        ("schedule", {"schedule_todo"}),
        ("checklist", {"add_checklist_items"}),
    ],
)
def test_each_mcp_scope_has_exact_post_filter_discovery_and_schemas(scope, expected):
    tools = asyncio.run(server._filtered_mcp_tools({scope}))
    assert {tool.name for tool in tools} == expected
    assert all(tool.inputSchema.get("type") == "object" for tool in tools)
    if scope != "update":
        assert "update_todo" not in {tool.name for tool in tools}


def test_security_store_enforces_private_directory_and_database_modes(tmp_path):
    path = tmp_path / "nested" / "security.sqlite"
    previous_umask = os.umask(0)
    try:
        SecurityStore(path)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
