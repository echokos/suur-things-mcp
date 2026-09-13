#!/usr/bin/env python3
"""Post one signed non-mutating smoke proposal to a private Grace ingress."""
import argparse
import hashlib
import hmac
import json
import stat
import time
import urllib.request
from pathlib import Path


def secret(path: Path) -> str:
    details = path.lstat()
    if not path.is_file() or stat.S_IMODE(details.st_mode) != 0o600:
        raise ValueError("shared key must be a regular 0600 file")
    return path.read_text(encoding="utf-8").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--shared-key-file", required=True)
    args = parser.parse_args()
    key = secret(Path(args.shared_key_file))
    payload = json.dumps({"profile": "grace", "proposal_id": f"smoke-{int(time.time())}", "task_data": {"id": "smoke", "title": "health-check only"}}, separators=(",", ":"), sort_keys=True).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(key.encode(), f"{timestamp}.".encode() + payload, hashlib.sha256).hexdigest()
    request = urllib.request.Request(args.url, data=payload, headers={"Content-Type": "application/json", "X-Suur-Grace-Timestamp": timestamp, "X-Suur-Grace-Signature": signature}, method="POST")
    with urllib.request.urlopen(request, timeout=35) as response:
        body = response.read()
        returned = response.headers.get("X-Grace-Signature", "")
        expected = hmac.new(key.encode(), f"{response.headers.get('X-Grace-Timestamp', '')}.".encode() + body, hashlib.sha256).hexdigest()
        if response.status != 202 or not hmac.compare_digest(returned, expected):
            raise RuntimeError("Grace ingress response was not authenticated")
    print("Grace ingress smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
