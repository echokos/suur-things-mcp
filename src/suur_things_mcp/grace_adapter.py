"""Bounded Grace proposal adapter.

This module is deliberately not a general agent shell-out. It carries only a
small, normalized proposal envelope to the authenticated web confirmation
boundary. Things task text is data, never executable instructions, and no method
in this module can execute a Things mutation.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GraceProposal:
    id: str
    confirmation: str
    profile: str
    change: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "confirmation": self.confirmation,
            "profile": self.profile,
            "change": self.change,
            "mutation_performed": False,
        }


class GraceProposalAdapter:
    """Creates confirmation-bound, non-executing proposals for profile ``grace``."""

    profile = "grace"

    def __init__(self) -> None:
        self._pending: dict[str, tuple[str, dict[str, str]]] = {}

    def propose(self, item: dict[str, Any]) -> dict[str, Any]:
        # Whitelist the small UI schema; never interpolate task notes into commands.
        change = {key: str(item[key])[:500] for key in ("id", "title") if item.get(key) is not None}
        if "id" not in change:
            raise ValueError("proposal requires an item id")
        proposal_id = secrets.token_hex(16)
        confirmation = secrets.token_urlsafe(24)
        self._pending[proposal_id] = (hashlib.sha256(confirmation.encode()).hexdigest(), change)
        return GraceProposal(proposal_id, confirmation, self.profile, change).as_dict()

    def confirm(self, proposal_id: str, confirmation: str | None) -> bool:
        return self.confirmed_change(proposal_id, confirmation) is not None

    def confirmed_change(self, proposal_id: str, confirmation: str | None) -> dict[str, str] | None:
        """Consume a matching confirmation and return its bounded Things change."""
        pending = self._pending.pop(proposal_id, None)
        if not pending or not confirmation:
            return None
        expected, change = pending
        if not secrets.compare_digest(expected, hashlib.sha256(confirmation.encode()).hexdigest()):
            return None
        return dict(change)

    def discard(self, proposal_id: str) -> None:
        """Forget an undisclosed proposal when delivery to Grace was not possible."""
        self._pending.pop(proposal_id, None)

    @staticmethod
    def request_payload(item: dict[str, Any]) -> str:
        """Stable, data-only payload a Hermes Grace worker may receive later."""
        safe = {key: str(item[key])[:500] for key in ("id", "title", "notes") if item.get(key) is not None}
        return json.dumps({"profile": "grace", "task_data": safe}, sort_keys=True)
