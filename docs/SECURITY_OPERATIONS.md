# Private deployment and operations

## Boundary

Run SUUR only on the Mac that hosts Things. Bind the application to `127.0.0.1`; expose it only through an HTTPS Tailscale reverse proxy for `elliotts-mac-mini.tail43b447.ts.net`. Do not publish the port to a LAN/WAN interface or use a public tunnel.

The app accepts only `SUUR_ALLOWED_HOSTS` (default: the Tailscale hostname) plus loopback for the local proxy. Its origin guard requires the exact scheme, host, and port. No wildcard origins.

### Private install

Run `scripts/install_private_tailscale_serve.sh` **locally on the Things Mac**. It uses
`uv sync --locked --no-dev`, exposes a fixed service executable at
`~/Library/Application Support/SUUR Things MCP/venv/bin/suur-things-mcp`, installs the
LaunchAgent, and configures `tailscale serve --https=443` to proxy only to
`127.0.0.1:8765`. The LaunchAgent never invokes `uvx` or resolves a package at startup.

Before installing, arrange the dashboard bootstrap token and (if dashboard write access
is wanted) the Things URL-scheme token in the Mac's local service secret manager. Do not
place either value in the plist, this repository, the shell history, or a browser. The
installer intentionally does not create a public Funnel endpoint or bind the application
to a LAN/WAN interface.

## Browser access

Set `SUUR_DASHBOARD_BOOTSTRAP_TOKEN` in the service environment. The reverse proxy must authenticate the Tailscale identity and inject that value into `X-Suur-Bootstrap` only for an approved browser-session bootstrap request; do not put it in HTML, JavaScript, URLs, local storage, browser configuration, or logs.

`POST /api/session` exchanges that header for `__Host-suur-session` (Secure, HttpOnly, SameSite=Strict) and a non-credential CSRF cookie. All API calls require a scoped session; mutations additionally require `X-Suur-CSRF` and a unique `Idempotency-Key`. `POST /api/session/revoke` revokes the current session immediately. Rotate the bootstrap token after access-policy changes.

Grace proposals are delivered server-side to the configured `SUUR_HERMES_GRACE_URL`.
`SUUR_HERMES_GRACE_TOKEN`, when used, is sent only as a server-side bearer credential.
The browser receives a bounded proposal and must later POST the matching confirmation to
`/api/grace/confirm`; only then does the service apply its whitelisted change through the
same authenticated, idempotency-guarded, stable-ID-readback update path as dashboard edits.
The service never shells out to a general agent runner.

`GET /api/healthz` is liveness-only. `GET /api/readyz` returns 503 if Things data cannot be read and never includes paths, task data, tokens, or diagnostics.

## MCP principals

MCP starts read-only unless both `SUUR_MCP_PROFILE` and `SUUR_MCP_TOKEN` match a provisioned principal in the local security SQLite database. Issue different principals per Hermes profile and only grant needed scopes: `read`, `create`, `update`, `complete`, `move`, `schedule`, or `checklist`. Revoking a principal returns it to read-only discovery at the next process start. Cancel, batch, dashboard-overlay, attachment, repository-link, and generic-organizer tools are never exposed by the hardened MCP startup path.

Provision and revoke with a short local-admin Python session using `SecurityStore.provision_mcp_principal()` and `SecurityStore.revoke_mcp_principal()`; display a newly-issued token once, store it in the host service secret store, and never paste it into an agent prompt or browser.

## Data integrity and recovery

Things remains the only task source of truth. All task reads use SQLite read-only URIs; stable snapshot reads add `immutable=1`. Writes use only `things:///` via macOS `open -g`, and modifying writes require the Things URL-scheme token held server-side. A dispatched write is read back by stable item UUID; an unverified result is reported as unverified rather than successful.

Dashboard state is non-authoritative presentation metadata only. Do not use it to mirror or mutate task state. The security store records metadata-only audit rows: time, principal, operation, target ID, and success. It stores SHA-256 lookup digests of generated high-entropy browser and MCP bearer tokens, never raw tokens. These are not password hashes: SUUR neither accepts nor stores user passwords. Any future password feature must use a memory-hard salted password KDF (such as scrypt or Argon2), not this lookup digest. Keep its directory mode 0700 and database mode 0600.

## Operations

Use Python 3.11 and install exactly from the committed lockfile:

```sh
uv sync --locked --dev
uv run pytest
uv run ruff check .
```

Before upgrade, back up the Things database through Things/macOS tooling and the SUUR configuration/security databases. Test the upgraded service against a copy of Things data. On Things failure, leave writes disabled, inspect `/api/readyz`, and restore service only after a read-only health check passes. There is no production deployment step in this repository.
