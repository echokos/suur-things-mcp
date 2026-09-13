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

command -v uv >/dev/null 2>&1 || { printf '%s\n' 'uv is required.' >&2; exit 1; }
command -v tailscale >/dev/null 2>&1 || { printf '%s\n' 'Tailscale is required.' >&2; exit 1; }

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
