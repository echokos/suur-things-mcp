# Grace Hermes web-chat adapter

This is the required integration contract for a Grace decision about a SUUR
Things proposal. It is deliberately narrow: a dashboard proposal can result in
one update to its original Things item only after both of these independently
authenticated events occur:

1. An allowlisted Tailscale browser session approves its own proposal at
   `POST /api/grace/confirm`.
2. The Grace Hermes web-chat workflow records an explicit approve/deny decision
   through `scripts/grace_hermes_decide.py`.

The browser never receives an approval capability. The adapter never receives a
Things token or arbitrary tool access.

## One-time installation on the Mac

Run `scripts/install_private_tailscale_serve.sh` locally. It creates two regular
0600 files in `~/.config/suur-things-mcp/secrets/`:

- `browser-bootstrap` — a break-glass local bootstrap value; it is not used by
  normal Tailscale browser login and is never printed.
- `grace-shared-key` — shared only with the configured Grace Hermes adapter.

The SUUR LaunchAgent receives only `SUUR_SECRET_DIR`, never either secret. Copy
`grace-shared-key` by a local administrator to the authorized Grace adapter's
own protected secret store; do not put its content in chat, a plist, a repo, or
an agent prompt. The installer also writes the `SUUR_TAILSCALE_USERS` allowlist
into the LaunchAgent from the signed-in Tailscale login, unless an administrator
overrides it before installation.

## Private Grace proposal ingress

Grace's Hermes runtime receives proposals through the checked-in
`scripts/grace_hermes_ingress.py` service. It binds **only** to `127.0.0.1`,
verifies the SUUR `timestamp.body` HMAC envelope with the transferred 0600 key,
rejects stale/invalid/replayed requests, and atomically writes accepted proposal
JSON to a 0700 local spool. The local Grace workflow consumes that spool as data;
it must not execute proposal titles, notes, or task content.

On Grace's Mac, run the ingress behind Tailscale Serve (not Funnel or a public
proxy). This example selects loopback port `8790` for that host:

```sh
python3 /fixed/suur-checkout/scripts/grace_hermes_ingress.py \
  --port 8790 \
  --shared-key-file /path/in/grace-secret-store/grace-shared-key \
  --spool-dir ~/.config/grace-hermes/suur-proposals

tailscale serve --https=443 http://127.0.0.1:8790
```

Set `SUUR_HERMES_GRACE_URL` on the Things Mac to the resulting private Tailscale
HTTPS URL, including the fixed path:

```sh
export SUUR_HERMES_GRACE_URL=https://grace-host.tailnet.ts.net/api/suur/grace/proposals
```

The SUUR installer persists this non-secret URL in its LaunchAgent so proposal
delivery survives restarts. Do not use a generic public webhook, a browser-supplied
URL, or an agent shell-out as an ingress.

## Bind the Grace web-chat decision workflow

Configure exactly one Grace web-chat decision action with the following fixed
command shape, replacing only the proposal and decision IDs with values from
the authenticated workflow:

```sh
SUUR_GRACE_CALLBACK_HOST=elliotts-mac-mini.tail43b447.ts.net \
SUUR_GRACE_SHARED_KEY_FILE=/path/in/grace-secret-store/grace-shared-key \
python3 /fixed/suur-checkout/scripts/grace_hermes_decide.py \
  --proposal-id "$PROPOSAL_ID" --decision-id "$DECISION_ID" --approve \
  --callback-url https://elliotts-mac-mini.tail43b447.ts.net/api/grace/decision
```

For a rejection, replace `--approve` with `--deny`. The adapter fixes
`profile=grace` and `scopes=["update"]`, signs the exact body with HMAC-SHA256,
requires HTTPS, and optionally pins the callback host. It never accepts a
callback URL from task notes or browser content. The SUUR server rejects stale
callbacks (more than five minutes old), unsigned decisions, duplicate decision
IDs, decisions for another profile, decisions without `update`, and attempts to
reuse an executed or failed proposal.

The outbound SUUR-to-Grace notification is configured by
`SUUR_HERMES_GRACE_URL`; it uses the same HMAC envelope. Point it only at the
verified Grace web-chat adapter ingress, which must verify the signature before
surfacing a proposal. An unbound generic webhook, browser-supplied callback URL,
or agent shell-out is not an accepted integration.

## Expected observable behavior

- Browser approval first: `202 {"ok":true,"status":"awaiting_grace"}`.
- Grace approval first: `202 {"ok":true,"status":"awaiting_browser"}`.
- Once both gates pass, SUUR uses its normal URL-scheme update path and stable
  Things-item readback. An unsuccessful or unverified readback becomes terminal
  `failed`; it does not silently retry or report success.
- A denial is terminal for that proposal. Create a fresh proposal to reconsider
  it.
