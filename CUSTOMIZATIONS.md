# Elliott fork customizations

This branch is the deployment source for Elliott's private Things dashboard.
Internal Python package, command, environment-variable, service, and filesystem
names intentionally remain `suur-*` for upstream compatibility. Only the
user-visible product mark is customized.

## Preserved customizations

- Visible top-bar brand: `Things`.
- Private loopback dashboard with Tailscale HTTPS on `:8443` while preserving
  the existing `:443` route.
- Tailscale-identity browser sessions, scoped/revocable per-profile MCP access,
  and fail-closed write authorization.
- Grace-only conversational proposal flow with browser confirmation and signed,
  replay-resistant decisions.
- Fixed-version LaunchAgent installation and a retained rollback release.

The behavior above is covered by the normal test suite, including
`test_fork_branding_stays_things_only` and the hardening/browser tests. CI runs
Ruff and the complete pytest suite on every push.

## Upgrade procedure

1. Create a backup branch/tag at the currently deployed commit.
2. Fetch upstream and merge or rebase it into this customization branch.
3. Resolve conflicts without renaming internal `suur-*` identifiers.
4. Search the whole repository for dropped customization symbols after any
   conflict, especially `test_fork_branding_stays_things_only`, `SUUR_ALLOWED_HOSTS`,
   `SUUR_TAILSCALE_HTTPS_PORT`, `SUUR_HERMES_GRACE_URL`, and `SUUR_MCP_PROFILE`.
5. Run `uv sync --locked`, `uv run ruff check .`, and `uv run pytest -q`.
6. Deploy that exact commit to a new versioned release directory. Do not mutate
   the prior release; keep it as rollback.
7. Verify local readiness, private HTTPS/session bootstrap, profile scopes, one
   Things create/readback/complete canary, service restart, and preserved `:443`.

An upgrade is incomplete if this file, its branding test, or any protected
runtime test disappears.