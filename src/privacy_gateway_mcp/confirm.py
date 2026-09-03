"""Human-in-the-loop confirmation tokens.

When the policy returns NEEDS_APPROVAL the gateway does not send anything. Instead it
stashes the pending payload and hands back a single-use token with a short TTL. Only a
second, explicit call carrying that token releases the payload to the cloud.

This mirrors the "confirm before any mutation" pattern: the model can *propose* an
egress, but a human (or an approving system) must *confirm* it, and the approval
expires so a stale token can't be replayed later.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any


class ConfirmationError(Exception):
    """Raised when a token is unknown, already used, or expired."""


@dataclass
class _Pending:
    payload: dict[str, Any]
    expires_at: float


class ConfirmationStore:
    def __init__(self, ttl_seconds: float = 300.0, clock=time.monotonic) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._pending: dict[str, _Pending] = {}

    def issue(self, payload: dict[str, Any]) -> str:
        """Store a pending payload and return the token that will release it."""
        token = secrets.token_urlsafe(16)
        self._pending[token] = _Pending(payload=payload, expires_at=self._clock() + self._ttl)
        return token

    def confirm(self, token: str) -> dict[str, Any]:
        """Consume a token and return its payload, or raise ConfirmationError.

        Tokens are single-use: a confirmed or expired token is removed either way.
        """
        pending = self._pending.pop(token, None)
        if pending is None:
            raise ConfirmationError("unknown or already-used confirmation token")
        if self._clock() > pending.expires_at:
            raise ConfirmationError("confirmation token has expired")
        return pending.payload

    def pending_count(self) -> int:
        return len(self._pending)
