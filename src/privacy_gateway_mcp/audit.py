"""Append-only audit log.

Every decision the gateway makes — allowed, blocked, awaiting approval, or actually
sent — is recorded here. The log is deliberately append-only: entries can be read but
never mutated or removed, so the history of what left (and what didn't) is
reconstructable. Entries never contain raw sensitive values, only counts and reasons.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class AuditEntry:
    action: str                       # "ask" | "confirm"
    decision: str                     # Decision value or "sent"
    entity_counts: dict[str, int]     # e.g. {"EMAIL": 1, "MONEY": 2}
    reasons: list[str]
    sent: bool
    timestamp: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLog:
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(
        self,
        action: str,
        decision: str,
        entity_counts: dict[str, int],
        reasons: list[str],
        sent: bool,
    ) -> AuditEntry:
        entry = AuditEntry(
            action=action,
            decision=decision,
            entity_counts=dict(entity_counts),
            reasons=list(reasons),
            sent=sent,
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        """A read-only snapshot (a copy, so callers can't mutate the log)."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
