"""privacy-gateway-mcp.

An MCP server that sits between an assistant and a cloud LLM. Before any text is
sent out it is (1) redacted — sensitive entities are replaced by reversible
placeholders — and (2) evaluated by a deterministic egress policy that can allow,
require human approval, or block the call. Responses are re-hydrated so the caller
sees real values while the cloud provider never does.
"""

from .types import Decision, Entity, EntityType, PolicyConfig, PolicyResult
from .gateway import AskResult, PrivacyGateway

__all__ = [
    "Decision",
    "Entity",
    "EntityType",
    "PolicyConfig",
    "PolicyResult",
    "AskResult",
    "PrivacyGateway",
]

__version__ = "0.1.0"
