#!/usr/bin/env python3
"""Submit a human-reviewed Grace decision to a private SUUR dashboard.

This is deliberately a narrow adapter, not an agent runner: its caller must
already have a proposal ID and an explicit yes/no decision from Grace's Hermes
web-chat workflow. It can submit only the fixed ``grace`` profile and ``update``
scope, signs the exact JSON body, and refuses non-HTTPS callbacks.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


def _secret(path: Path) -> str:
    details = path.lstat()
    if not path.is_file() or stat.S_IMODE(details.st_mode) != 0o600:
        raise ValueError("Grace shared key must be a regular 0600 file")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError("Grace shared key is empty")
    return value


def _callback(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path != "/api/grace/decision":
        raise ValueError("callback must be an HTTPS SUUR /api/grace/decision URL")
    expected_host = os.environ.get("SUUR_GRACE_CALLBACK_HOST")
    if expected_host and parsed.hostname.casefold() != expected_host.casefold():
        raise ValueError("callback host does not match SUUR_GRACE_CALLBACK_HOST")
    return url


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal-id", required=True)
    parser.add_argument("--decision-id", required=True)
    outcome = parser.add_mutually_exclusive_group(required=True)
    outcome.add_argument("--approve", action="store_true")
    outcome.add_argument("--deny", action="store_true")
    parser.add_argument("--callback-url", required=True)
    parser.add_argument(
        "--shared-key-file",
        default=os.environ.get("SUUR_GRACE_SHARED_KEY_FILE", ""),
        help="0600 shared key file; never pass the key value as an argument",
    )
    args = parser.parse_args()
    if not args.shared_key_file:
        parser.error("--shared-key-file or SUUR_GRACE_SHARED_KEY_FILE is required")

    try:
        callback = _callback(args.callback_url)
        key = _secret(Path(args.shared_key_file))
    except (OSError, ValueError) as exc:
        print(f"refusing Grace decision: {exc}", file=sys.stderr)
        return 2

    body = json.dumps(
        {
            "proposal_id": args.proposal_id,
            "decision_id": args.decision_id,
            "approved": args.approve,
            "profile": "grace",
            "scopes": ["update"],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(key.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        callback,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Suur-Grace-Timestamp": timestamp,
            "X-Suur-Grace-Signature": signature,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"SUUR rejected the decision ({response.status})")
    except (OSError, RuntimeError) as exc:
        print(f"Grace decision delivery failed: {exc}", file=sys.stderr)
        return 1
    print("Grace decision delivered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
