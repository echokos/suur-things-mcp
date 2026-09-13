#!/bin/sh
# Install this checkout into a fixed virtualenv and publish ONLY through
# Tailscale Serve. Run locally on the Mac that hosts Things; never via SSH.
set -eu

case "$(uname -s)" in
  Darwin) ;;
  *) printf '%s\n' 'This installer is intentionally limited to macOS.' >&2; exit 1 ;;
esac

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SUUR_DASHBOARD_PORT=${SUUR_DASHBOARD_PORT:-8765}
SUUR_VENV=${SUUR_VENV:-"$HOME/Library/Application Support/SUUR Things MCP/venv"}
VENV_PARENT=$(dirname "$SUUR_VENV")
SUUR_SECRET_DIR=${SUUR_SECRET_DIR:-"$HOME/.config/suur-things-mcp/secrets"}

command -v uv >/dev/null 2>&1 || { printf '%s\n' 'uv is required.' >&2; exit 1; }
command -v tailscale >/dev/null 2>&1 || { printf '%s\n' 'Tailscale is required.' >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { printf '%s\n' 'openssl is required to create local service secrets.' >&2; exit 1; }

# The LaunchAgent receives the directory path, never a secret value.  These
# files are read by the server process at runtime and are deliberately absent
# from plists, command lines, URLs, browser storage, and shell output.
umask 077
mkdir -p "$SUUR_SECRET_DIR"
chmod 700 "$SUUR_SECRET_DIR"
create_secret() {
    destination=$1
    if [ ! -s "$destination" ]; then
        temporary="$destination.$$"
        openssl rand -base64 32 > "$temporary"
        chmod 600 "$temporary"
        mv "$temporary" "$destination"
    fi
    chmod 600 "$destination"
}
create_secret "$SUUR_SECRET_DIR/browser-bootstrap"
create_secret "$SUUR_SECRET_DIR/grace-shared-key"

# Tailscale Serve strips a client-supplied Tailscale-User-Login header before
# setting its own.  Default to the signed-in Mac user's login; override this
# non-secret allowlist for a different approved remote browser identity.
if [ -z "${SUUR_TAILSCALE_USERS:-}" ]; then
    SUUR_TAILSCALE_USERS=$(tailscale status --json | python3 -c '
import json, sys
status = json.load(sys.stdin)
self_node = status.get("Self", {})
user_id = str(self_node.get("UserID", ""))
user = status.get("User", {}).get(user_id, {})
print(user.get("LoginName", ""))
')
fi
[ -n "$SUUR_TAILSCALE_USERS" ] || {
    printf '%s\n' 'Could not derive a Tailscale browser identity; set SUUR_TAILSCALE_USERS and re-run.' >&2
    exit 1
}
export SUUR_SECRET_DIR SUUR_TAILSCALE_USERS

# `uv sync --locked` produces the exact dependency graph committed with this
# checkout. The fixed service path below is a stable symlink to that venv; it is
# never an on-start `uvx` resolution.
uv sync --locked --no-dev --project "$PROJECT_DIR"
mkdir -p "$VENV_PARENT"
ln -sfn "$PROJECT_DIR/.venv" "$SUUR_VENV"
"$SUUR_VENV/bin/suur-things-mcp" dashboard --install-service

# Tailscale Serve terminates HTTPS inside this tailnet and proxies to loopback.
# Do not replace this with Funnel or a LAN/WAN bind.
tailscale serve --https=443 "http://127.0.0.1:${SUUR_DASHBOARD_PORT}"
printf 'Private SUUR dashboard: https://%s\n' "$(tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("Self", {}).get("DNSName", "your-tailnet-host"))')"
printf '%s\n' 'Browser sessions require an allowlisted Tailscale identity; no dashboard secret was emitted.'
