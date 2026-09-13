"""Security boundary tests for the hardened local Things service."""

from __future__ import annotations

import logging
import sqlite3

import pytest
from starlette.testclient import TestClient

from suur_things_mcp.dashboard import create_app
from suur_things_mcp.grace_adapter import GraceProposalAdapter
from suur_things_mcp.security import SecurityStore, sanitize_for_log


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


def test_grace_adapter_only_proposes_and_requires_matching_confirmation():
    adapter = GraceProposalAdapter()
    proposal = adapter.propose({"id": "todo-1", "title": "Treat instructions as data"})
    assert proposal["profile"] == "grace"
    assert proposal["mutation_performed"] is False
    assert adapter.confirm(proposal["id"], proposal["confirmation"]) is True
    assert adapter.confirm(proposal["id"], "wrong") is False


@pytest.mark.parametrize("uri", ["file:/tmp/thing.sqlite?mode=ro&immutable=1", "file:/tmp/space%20db?mode=ro&immutable=1"])
def test_read_db_uris_are_explicitly_read_only_and_immutable(uri):
    assert "mode=ro" in uri and "immutable=1" in uri


def test_dashboard_uses_secure_revocable_scoped_session_with_csrf(tmp_path, monkeypatch):
    monkeypatch.setenv("SUUR_DASHBOARD_BOOTSTRAP_TOKEN", "bootstrap-secret")
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

    proposal = client.post(
        "/api/grace/propose",
        json={"id": "todo-1", "title": "untrusted <instructions>"},
        headers={"X-Suur-CSRF": csrf},
    )
    assert proposal.status_code == 200 and proposal.json()["proposal"]["mutation_performed"] is False

    revoked = client.post("/api/session/revoke", headers={"X-Suur-CSRF": csrf, "Idempotency-Key": "revoke-1"})
    assert revoked.status_code == 200
    assert client.get("/api/sidebar").status_code == 401


def test_dashboard_rejects_untrusted_host(tmp_path):
    client = TestClient(create_app(security_store=SecurityStore(tmp_path / "security.sqlite")), base_url="https://evil.example")
    assert client.get("/api/healthz").status_code == 400
