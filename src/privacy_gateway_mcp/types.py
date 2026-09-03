"""Shared types for the privacy gateway.

These are deliberately plain dataclasses/enums so the core logic stays free of any
framework dependency and is trivial to unit-test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EntityType(str, Enum):
    """Categories of sensitive data the anonymizer knows how to detect."""

    EMAIL = "EMAIL"
    PHONE = "PHONE"
    RUT = "RUT"          # Chilean national ID (RUT/RUN)
    CARD = "CARD"        # credit/debit card number
    IPV4 = "IPV4"
    MONEY = "MONEY"      # monetary amounts
    SECRET = "SECRET"    # API keys / tokens


@dataclass(frozen=True)
class Entity:
    """A single detected entity and the placeholder that stands in for it."""

    type: EntityType
    value: str
    placeholder: str


class Decision(str, Enum):
    """Outcome of the deterministic egress policy."""

    ALLOWED = "allowed"
    NEEDS_APPROVAL = "needs_approval"
    BLOCKED = "blocked"


@dataclass
class PolicyConfig:
    """Tunable thresholds for the egress policy.

    Everything here is a hard, code-level rule — never something the model decides.
    """

    # Categories that must never be routed to a cloud LLM, even redacted.
    hard_block_types: frozenset[EntityType] = field(
        default_factory=lambda: frozenset({EntityType.SECRET, EntityType.CARD})
    )
    # Categories that are allowed but require explicit human approval first.
    require_approval_types: frozenset[EntityType] = field(
        default_factory=lambda: frozenset({EntityType.MONEY})
    )
    # Redacting more than this many entities is a signal of a bulk/risky payload.
    max_entities_auto: int = 5
    # Prompts longer than this need a human to look before they leave.
    max_chars_auto: int = 4000


@dataclass
class PolicyResult:
    """What the policy decided, and why (reasons are always human-readable)."""

    decision: Decision
    reasons: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCKED

    @property
    def needs_approval(self) -> bool:
        return self.decision is Decision.NEEDS_APPROVAL
