"""Bounded Grace proposal adapter.

This module is deliberately not a general agent shell-out. It carries only a
small, normalized proposal envelope to the authenticated web confirmation
boundary. Things task text is data, never executable instructions, and no method
in this module can execute a Things mutation.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GraceProposal:
    id: str
    profile: str
    change: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "profile": self.profile,
            "change": self.change,
            "mutation_performed": False,
        }


class GraceProposalAdapter:
    """Creates bounded, non-executing proposals for profile ``grace``.

    Approval state belongs to the server-side security store.  In particular,
    this adapter never returns a confirmation capability to a browser.
    """

    profile = "grace"

    def propose(self, item: dict[str, Any]) -> dict[str, Any]:
        # Whitelist the small UI schema; never interpolate task notes into commands.
        change = {key: str(item[key])[:500] for key in ("id", "title") if item.get(key) is not None}
        if "id" not in change:
            raise ValueError("proposal requires an item id")
        proposal_id = secrets.token_hex(16)
        return GraceProposal(proposal_id, self.profile, change).as_dict()

    @staticmethod
    def request_payload(proposal_id: str, item: dict[str, Any]) -> str:
        """Stable, data-only payload a Hermes Grace worker may receive later."""
        safe = {key: str(item[key])[:500] for key in ("id", "title", "notes") if item.get(key) is not None}
        return json.dumps({"profile": "grace", "proposal_id": proposal_id, "task_data": safe}, sort_keys=True)
