"""The privacy gateway — orchestration.

Ties the pieces together into the flow that matters:

    text ─▶ redact ─▶ policy ─┬─ BLOCKED         ─▶ nothing leaves
                              ├─ NEEDS_APPROVAL  ─▶ issue token, nothing leaves
                              └─ ALLOWED         ─▶ send redacted ─▶ rehydrate reply

    confirm(token) ─▶ send redacted ─▶ rehydrate reply

Only redacted text is ever handed to the provider. Every path is written to the audit
log. This class is pure/synchronous and has no MCP dependency, which keeps it fully
unit-testable; ``server.py`` is a thin async wrapper over it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .anonymizer import Anonymizer
from .audit import AuditLog
from .confirm import ConfirmationStore
from .policy import EgressPolicy
from .providers import CloudProvider, EchoProvider
from .types import Decision, PolicyConfig


@dataclass
class AskResult:
    """The outcome the caller sees. ``status`` is one of:
    "sent" | "blocked" | "needs_approval"."""

    status: str
    reasons: list[str] = field(default_factory=list)
    # populated when status == "sent"
    response: str | None = None
    redacted_sent: str | None = None
    # populated when status == "needs_approval"
    confirmation_token: str | None = None
    # always populated: how many of each entity type were found
    entity_counts: dict[str, int] = field(default_factory=dict)


class PrivacyGateway:
    def __init__(
        self,
        provider: CloudProvider | None = None,
        policy_config: PolicyConfig | None = None,
        *,
        confirm_ttl_seconds: float = 300.0,
    ) -> None:
        self._anonymizer = Anonymizer()
        self._policy = EgressPolicy(policy_config, self._anonymizer)
        self._provider = provider or EchoProvider()
        self._confirm = ConfirmationStore(ttl_seconds=confirm_ttl_seconds)
        self._audit = AuditLog()

    # -- public API ---------------------------------------------------------------

    def preview(self, text: str) -> AskResult:
        """Dry run: redact and evaluate, but never send and never issue a token."""
        red = self._anonymizer.redact(text)
        result = self._policy.evaluate(text, red.redacted, red.entities)
        return AskResult(
            status=result.decision.value,
            reasons=result.reasons,
            redacted_sent=red.redacted,
            entity_counts=self._counts(red.entities),
        )

    def ask(self, text: str) -> AskResult:
        """Redact, apply policy, and either send, block, or request approval."""
        red = self._anonymizer.redact(text)
        counts = self._counts(red.entities)
        result = self._policy.evaluate(text, red.redacted, red.entities)

        if result.decision is Decision.BLOCKED:
            self._audit.record("ask", Decision.BLOCKED.value, counts, result.reasons, sent=False)
            return AskResult(status="blocked", reasons=result.reasons, entity_counts=counts)

        if result.decision is Decision.NEEDS_APPROVAL:
            token = self._confirm.issue({"redacted": red.redacted, "mapping": red.mapping, "counts": counts})
            self._audit.record("ask", Decision.NEEDS_APPROVAL.value, counts, result.reasons, sent=False)
            return AskResult(
                status="needs_approval",
                reasons=result.reasons,
                confirmation_token=token,
                entity_counts=counts,
            )

        return self._dispatch(red.redacted, red.mapping, counts, action="ask")

    def confirm(self, token: str) -> AskResult:
        """Release a previously-approved payload. Raises ConfirmationError if the token
        is unknown, already used, or expired."""
        payload = self._confirm.confirm(token)  # may raise ConfirmationError
        return self._dispatch(
            payload["redacted"], payload["mapping"], payload["counts"], action="confirm"
        )

    def audit_entries(self) -> list[dict]:
        return [e.as_dict() for e in self._audit.entries()]

    # -- internals ----------------------------------------------------------------

    def _dispatch(self, redacted: str, mapping: dict[str, str], counts: dict[str, int], *, action: str) -> AskResult:
        raw_response = self._provider.complete(redacted)
        response = self._anonymizer.rehydrate(raw_response, mapping)
        self._audit.record(action, "sent", counts, ["dispatched to provider"], sent=True)
        return AskResult(
            status="sent",
            reasons=["dispatched to provider"],
            response=response,
            redacted_sent=redacted,
            entity_counts=counts,
        )

    @staticmethod
    def _counts(entities) -> dict[str, int]:
        return dict(Counter(e.type.value for e in entities))
