# Private deployment and operations

## Boundary

Run SUUR only on the Mac that hosts Things. Bind the application to `127.0.0.1`; expose it only through an HTTPS Tailscale reverse proxy for `elliotts-mac-mini.tail43b447.ts.net`. Do not publish the port to a LAN/WAN interface or use a public tunnel.

The app accepts only `SUUR_ALLOWED_HOSTS` (default: the Tailscale hostname) plus loopback for the local proxy. Its remote origin guard derives the exact HTTPS listener from that host allowlist and `SUUR_TAILSCALE_HTTPS_PORT` (default `8443`); no wildcard origins or default-HTTPS-port fallback.

### Private install

Run `scripts/install_private_tailscale_serve.sh` **locally on the Things Mac**. It uses
`uv sync --locked --no-dev`, exposes a fixed service executable at
`~/Library/Application Support/SUUR Things MCP/venv/bin/suur-things-mcp`, installs the
LaunchAgent, and configures Tailscale Serve to proxy only to the explicitly selected
loopback port. The live-Mac deployment default is `8876`;
it is exposed only on a distinct tailnet HTTPS listener `:8443`, preserving the
existing `:443` root route for job-hunter:

```sh
SUUR_DASHBOARD_PORT=8876 \
SUUR_ALLOWED_HOSTS=elliotts-mac-mini.tail43b447.ts.net \
SUUR_TAILSCALE_HTTPS_PORT=8443 \
SUUR_HERMES_GRACE_URL=https://grace-host.tailnet.ts.net:8444/api/suur/grace/proposals \
scripts/install_private_tailscale_serve.sh
```

The LaunchAgent runs `dashboard --no-open --strict-port --port 8876`; it refuses to
fall back to a different port because that would detach the private proxy from the
dashboard. The LaunchAgent never invokes `uvx` or resolves a package at startup.

The installer creates `~/.config/suur-things-mcp/secrets/` with mode 0700 and
regular 0600 `browser-bootstrap` and `grace-shared-key` files. The LaunchAgent
receives only `SUUR_SECRET_DIR`, never the values. Put the Things URL-scheme
token in its existing protected local file. Do not place any value in the plist,
repository, shell history, browser, or a command line. The installer intentionally
does not create a public Funnel endpoint or bind the application to a LAN/WAN
interface.

## Browser access

Normal browser bootstrap uses the authenticated `Tailscale-User-Login` header
that Tailscale Serve strips and rewrites itself. SUUR requires HTTPS plus an
explicit `SUUR_TAILSCALE_USERS` allowlist; it does not make every tailnet member
an administrator. The local 0600 `browser-bootstrap` value is break-glass only.
Do not put it in HTML, JavaScript, URLs, local storage, browser configuration,
or logs.

`POST /api/session` exchanges that header for `__Host-suur-session` (Secure, HttpOnly, SameSite=Strict) and a non-credential CSRF cookie. All API calls require a scoped session; mutations additionally require `X-Suur-CSRF` and a unique `Idempotency-Key`. `POST /api/session/revoke` revokes the current session immediately. Rotate the bootstrap token after access-policy changes.

Grace proposals are delivered server-side to the configured `SUUR_HERMES_GRACE_URL`
with an HMAC envelope from the 0600 `grace-shared-key` file. The concrete,
profile-bound web-chat decision adapter is `scripts/grace_hermes_decide.py`; its
installation and fixed wire contract are in `GRACE_HERMES_ADAPTER.md`. A browser
approval at `/api/grace/confirm` is bound to the authenticated browser session
but does not mutate. A single signed `profile=grace`, `scope=update` callback
must approve the same proposal before the service applies its whitelisted change
through the authenticated, idempotency-guarded, stable-ID-readback update path.
The service never shells out to a general agent runner.

The private Grace ingress is a separate capability boundary: it runs only the
configured absolute Hermes CLI with `chat --toolsets context_engine`. Its service
unit sets an explicit `GRACE_HERMES_INSTALL_ROOT` and a launcher path contained
by that root. Before binding, the ingress captures and verifies secure identities
for the launcher directory/binary, `venv/bin` Python, resolver modules, Grace
profile, and config; group- or world-writable components are rejected. It runs
the resolver and each chat process through inherited executable descriptors,
revalidating every identity before delivery. Thus a symlink retarget or path
replacement after startup fails closed, while a replacement immediately after
the check cannot redirect execution. CLI `--version` output is not trusted for
install-root discovery. A missing, malformed, changed, or nonzero resolver
result keeps the ingress from binding or delivering; it must never fall back to
default tools, `safe`, `--safe-mode`, or prompt-only restrictions.

`GET /api/healthz` is liveness-only. `GET /api/readyz` returns 503 if Things data cannot be read and never includes paths, task data, tokens, or diagnostics.

## MCP principals

MCP starts with no registered mutation tool unless both `SUUR_MCP_PROFILE` and
`SUUR_MCP_TOKEN` match a provisioned principal in the local security SQLite database.
Issue different principals per Hermes profile and grant only the exact scopes below.
Revoking a principal removes every MCP tool from that principal at the next process start.

| Scope | Exact MCP tools exposed | Authorized operation boundary |
|---|---|---|
| `read` | `get_today`, `get_inbox`, `get_upcoming`, `get_anytime`, `get_someday`, `get_logbook`, `get_deadlines`, `get_trash`, `search_todos`, `list_todos`, `get_projects`, `get_areas`, `get_tags`, `get_item`, `overview`, `show` | Read/discovery only; `show` only reveals an existing Things item/list. |
| `create` | `add_todo`, `add_project` | Create a new Things to-do or project only. |
| `update` | `update_todo`, `update_project` | Modify fields on an existing named item/project through the authenticated URL-scheme path. |
| `complete` | `complete_todo` | Mark exactly one existing to-do complete. |
| `move` | `move_todo` | Move exactly one to-do to a destination list/heading; it has no title, note, tag, completion, or schedule fields. |
| `schedule` | `schedule_todo` | Change scheduling on exactly one existing to-do. |
| `checklist` | `add_checklist_items` | Append checklist items to exactly one existing to-do. |

Scopes compose only by union of these rows. There is no `admin`, `cancel`, `batch`,
dashboard-overlay, attachment, repository-link, or generic-organizer scope/tool in
the hardened MCP startup path.

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

Before upgrade, back up the Things database through Things/macOS tooling and the SUUR configuration/security databases. Test the upgraded service against a copy of Things data. For a Hermes upgrade on the Grace host, also rerun `uv run pytest tests/test_hardening.py -k context_engine`; the ingress startup preflight must revalidate the exact configured binary as zero tools before it becomes ready. On Things failure, leave writes disabled, inspect `/api/readyz`, and restore service only after a read-only health check passes. To roll back, `launchctl bootout gui/$(id -u)/io.suur.things-dashboard`, restore the prior fixed checkout/venv symlink and security database backup, then rerun the private installer. To remove it, run `suur-things-mcp dashboard --uninstall-service` and `tailscale serve reset`; preserve or securely destroy the local secret directory according to whether a later reinstall must retain existing sessions. There is no production deployment step in this repository.
