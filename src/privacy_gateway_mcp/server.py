"""MCP server exposing the privacy gateway as tools + a resource.

Tools
-----
* ``redact_preview(text)``   — dry run: what would be redacted and what the policy says.
* ``ask_cloud_llm(text)``    — the guarded egress call. Sends only when the policy
                               allows; otherwise blocks or returns an approval token.
* ``confirm_send(token)``    — releases a payload the policy flagged for approval.
* ``get_audit_log()``        — the append-only decision trail.

Resource
--------
* ``audit://log``            — same trail, exposed as a readable MCP resource.

Run it with:  ``python -m privacy_gateway_mcp.server``  (stdio transport).
"""

from __future__ import annotations

import json

from mcp.server.mcpserver import MCPServer

from .confirm import ConfirmationError
from .gateway import AskResult, PrivacyGateway

mcp = MCPServer("privacy-gateway")

# One gateway instance per process. Swap EchoProvider for a real provider here.
_gateway = PrivacyGateway()


def _as_dict(result: AskResult) -> dict:
    return {
        "status": result.status,
        "reasons": result.reasons,
        "response": result.response,
        "redacted_sent": result.redacted_sent,
        "confirmation_token": result.confirmation_token,
        "entity_counts": result.entity_counts,
    }


@mcp.tool()
def redact_preview(text: str) -> dict:
    """Show what would be redacted and how the egress policy would rule — without
    sending anything or issuing an approval token."""
    return _as_dict(_gateway.preview(text))


@mcp.tool()
def ask_cloud_llm(text: str) -> dict:
    """Send text to the cloud LLM through the privacy gateway.

    The text is redacted first; then the deterministic policy decides. Possible
    ``status`` values: ``sent`` (redacted text was dispatched and the reply
    re-hydrated), ``blocked`` (a hard rule refused it), or ``needs_approval``
    (call ``confirm_send`` with the returned ``confirmation_token``)."""
    return _as_dict(_gateway.ask(text))


@mcp.tool()
def confirm_send(token: str) -> dict:
    """Approve and release a payload the policy flagged for human approval. The token
    is single-use and time-limited."""
    try:
        return _as_dict(_gateway.confirm(token))
    except ConfirmationError as exc:
        return {"status": "error", "reasons": [str(exc)]}


@mcp.tool()
def get_audit_log() -> list[dict]:
    """Return the append-only log of every egress decision made this session."""
    return _gateway.audit_entries()


@mcp.resource("audit://log")
def audit_log_resource() -> str:
    """The audit trail as a readable JSON resource."""
    return json.dumps(_gateway.audit_entries(), indent=2, ensure_ascii=False)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
