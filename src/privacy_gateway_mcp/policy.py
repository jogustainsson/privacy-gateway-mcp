"""Deterministic egress policy.

This is the "hard rules" layer the model never gets to override: given the original
text, the redacted text and the entities found, it decides whether a call may leave
for the cloud automatically, needs a human to approve it first, or is blocked.

The order of checks matters — the most restrictive outcome wins:
    BLOCKED  >  NEEDS_APPROVAL  >  ALLOWED
"""

from __future__ import annotations

from .anonymizer import Anonymizer
from .types import Decision, Entity, PolicyConfig, PolicyResult


class EgressPolicy:
    def __init__(self, config: PolicyConfig | None = None, anonymizer: Anonymizer | None = None) -> None:
        self.config = config or PolicyConfig()
        self._anonymizer = anonymizer or Anonymizer()

    def evaluate(self, original: str, redacted: str, entities: list[Entity]) -> PolicyResult:
        cfg = self.config
        present_types = {e.type for e in entities}

        # 1. Hard block — categories that must never reach a cloud LLM at all.
        blocking = present_types & cfg.hard_block_types
        if blocking:
            names = ", ".join(sorted(t.value for t in blocking))
            return PolicyResult(
                Decision.BLOCKED,
                [f"payload contains hard-blocked category: {names}"],
            )

        # 2. Fail-closed — if anything sensitive survived redaction, do not send.
        if self._anonymizer.has_residual_sensitive(redacted):
            return PolicyResult(
                Decision.BLOCKED,
                ["redacted text still contains a detectable sensitive entity (fail-closed)"],
            )

        # 3. Require human approval for softer risk signals (any one is enough).
        reasons: list[str] = []
        approval = present_types & cfg.require_approval_types
        if approval:
            names = ", ".join(sorted(t.value for t in approval))
            reasons.append(f"contains category requiring approval: {names}")
        if len(entities) > cfg.max_entities_auto:
            reasons.append(
                f"redacted {len(entities)} entities (> {cfg.max_entities_auto} auto limit)"
            )
        if len(original) > cfg.max_chars_auto:
            reasons.append(
                f"prompt length {len(original)} chars (> {cfg.max_chars_auto} auto limit)"
            )
        if reasons:
            return PolicyResult(Decision.NEEDS_APPROVAL, reasons)

        # 4. Nothing tripped — safe to send automatically.
        return PolicyResult(Decision.ALLOWED, ["no policy rule triggered"])
