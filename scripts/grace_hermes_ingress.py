#!/usr/bin/env python3
"""Receive signed SUUR Grace proposals on a private loopback ingress.

Run this only behind an HTTPS private reverse proxy such as Tailscale Serve.
The endpoint accepts POST /api/suur/grace/proposals, validates the same
``timestamp.body`` HMAC envelope used by SUUR, and atomically spools a 0600 JSON
record for Grace's local Hermes workflow. It never executes proposal content.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_PATH = "/api/suur/grace/proposals"
_MAX_BODY_BYTES = 64 * 1024
_MAX_AGE_SECONDS = 300


def _secret(path: Path) -> str:
    """Read only a regular, owner-only key file without following its leaf symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o600:
            raise ValueError("Grace shared key must be a regular 0600 file")
        value = os.read(descriptor, 8192).decode("utf-8").strip()
    finally:
        os.close(descriptor)
    if not value:
        raise ValueError("Grace shared key is empty")
    return value


def _signature(key: str, timestamp: str, body: bytes) -> str:
    return hmac.new(key.encode("utf-8"), f"{timestamp}.".encode("ascii") + body, hashlib.sha256).hexdigest()


def _proposal_id(body: bytes) -> str:
    try:
        proposal = json.loads(body)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid JSON body") from exc
    if not isinstance(proposal, dict):
        raise ValueError("proposal must be a JSON object")
    proposal_id = proposal.get("proposal_id")
    if proposal.get("profile") != "grace" or not isinstance(proposal_id, str) or not proposal_id:
        raise ValueError("proposal must be a Grace proposal with an ID")
    if not isinstance(proposal.get("task_data"), dict):
        raise ValueError("proposal task_data must be an object")
    return proposal_id


def _spool(body: bytes, proposal_id: str, directory: Path) -> bool:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = directory.lstat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o700:
        raise ValueError("Grace proposal spool must be a regular 0700 directory")
    filename = hashlib.sha256(proposal_id.encode("utf-8")).hexdigest() + ".json"
    destination = directory / filename
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return False
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            destination.unlink(missing_ok=True)
        finally:
            raise
    return True


def _handler(key: str, spool_dir: Path) -> type[BaseHTTPRequestHandler]:
    class GraceIngressHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path != _PATH:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            try:
                size = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self.send_error(HTTPStatus.LENGTH_REQUIRED)
                return
            if not 0 <= size <= _MAX_BODY_BYTES:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            timestamp = self.headers.get("X-Suur-Grace-Timestamp", "")
            signature = self.headers.get("X-Suur-Grace-Signature", "")
            try:
                if abs(time.time() - int(timestamp)) > _MAX_AGE_SECONDS:
                    raise ValueError("stale signature")
            except ValueError:
                self.send_error(HTTPStatus.UNAUTHORIZED)
                return
            body = self.rfile.read(size)
            if not signature or not hmac.compare_digest(signature, _signature(key, timestamp, body)):
                self.send_error(HTTPStatus.UNAUTHORIZED)
                return
            try:
                proposal_id = _proposal_id(body)
                accepted = _spool(body, proposal_id, spool_dir)
            except ValueError:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            if not accepted:
                self.send_error(HTTPStatus.CONFLICT, "duplicate proposal")
                return
            response = b'{"ok":true,"status":"queued"}\n'
            self.send_response(HTTPStatus.ACCEPTED)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, format: str, *args: Any) -> None:
            # Task titles and notes are untrusted content; do not copy them to logs.
            return

    return GraceIngressHandler


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Binds 127.0.0.1 only; publish it only with an HTTPS private reverse proxy.",
    )
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1"], help="fixed loopback bind address")
    parser.add_argument("--port", type=int, default=8790, help="loopback port for the private proxy target")
    parser.add_argument("--shared-key-file", required=True, help="regular 0600 Grace shared-key file")
    parser.add_argument("--spool-dir", required=True, help="private 0700 proposal spool consumed by Grace Hermes")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be an integer from 1 through 65535")
    try:
        key = _secret(Path(args.shared_key_file))
        handler = _handler(key, Path(args.spool_dir))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
