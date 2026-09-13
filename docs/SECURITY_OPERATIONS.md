# Private deployment and operations

## Boundary

Run SUUR only on the Mac that hosts Things. Bind the application to `127.0.0.1`; expose it only through an HTTPS Tailscale reverse proxy for `elliotts-mac-mini.tail43b447.ts.net`. Do not publish the port to a LAN/WAN interface or use a public tunnel.

The app accepts only `SUUR_ALLOWED_HOSTS` (default: the Tailscale hostname) plus loopback for the local proxy. Its origin guard requires the exact scheme, host, and port. No wildcard origins.

## Browser access

Set `SUUR_DASHBOARD_BOOTSTRAP_TOKEN` in the service environment. The reverse proxy must authenticate the Tailscale identity and inject that value into `X-Suur-Bootstrap` only for an approved browser-session bootstrap request; do not put it in HTML, JavaScript, URLs, local storage, browser configuration, or logs.

`POST /api/session` exchanges that header for `__Host-suur-session` (Secure, HttpOnly, SameSite=Strict) and a non-credential CSRF cookie. All API calls require a scoped session; mutations additionally require `X-Suur-CSRF` and a unique `Idempotency-Key`. `POST /api/session/revoke` revokes the current session immediately. Rotate the bootstrap token after access-policy changes.

`GET /api/healthz` is liveness-only. `GET /api/readyz` returns 503 if Things data cannot be read and never includes paths, task data, tokens, or diagnostics.

## MCP principals

MCP starts read-only unless both `SUUR_MCP_PROFILE` and `SUUR_MCP_TOKEN` match a provisioned principal in the local security SQLite database. Issue different principals per Hermes profile and only grant needed scopes: `read`, `create`, `update`, `complete`, `move`, `schedule`, or `checklist`. Revoking a principal returns it to read-only discovery at the next process start. Cancel, batch, dashboard-overlay, attachment, repository-link, and generic-organizer tools are never exposed by the hardened MCP startup path.

Provision and revoke with a short local-admin Python session using `SecurityStore.provision_mcp_principal()` and `SecurityStore.revoke_mcp_principal()`; display a newly-issued token once, store it in the host service secret store, and never paste it into an agent prompt or browser.

## Data integrity and recovery

Things remains the only task source of truth. All task reads use SQLite read-only URIs; stable snapshot reads add `immutable=1`. Writes use only `things:///` via macOS `open -g`, and modifying writes require the Things URL-scheme token held server-side. A dispatched write is read back by stable item UUID; an unverified result is reported as unverified rather than successful.

Dashboard state is non-authoritative presentation metadata only. Do not use it to mirror or mutate task state. The security store records metadata-only audit rows: time, principal, operation, target ID, and success. It stores salted hashes rather than raw browser or MCP tokens. Keep its directory mode 0700 and database mode 0600.

## Operations

Use Python 3.11 and install exactly from the committed lockfile:

```sh
uv sync --locked --dev
uv run pytest
uv run ruff check .
```

Before upgrade, back up the Things database through Things/macOS tooling and the SUUR configuration/security databases. Test the upgraded service against a copy of Things data. On Things failure, leave writes disabled, inspect `/api/readyz`, and restore service only after a read-only health check passes. There is no production deployment step in this repository.
