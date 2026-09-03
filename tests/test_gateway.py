import pytest

from privacy_gateway_mcp.confirm import ConfirmationError
from privacy_gateway_mcp.gateway import PrivacyGateway
from privacy_gateway_mcp.providers import CloudProvider


class SpyProvider:
    """Records exactly what text was handed to the cloud."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    def complete(self, prompt: str) -> str:
        self.seen.append(prompt)
        return f"ack: {prompt}"


def test_clean_text_is_sent_and_only_redacted_leaves():
    spy = SpyProvider()
    gw = PrivacyGateway(provider=spy)
    result = gw.ask("Please write a friendly reminder to ana@acme.cl")
    assert result.status == "sent"
    # the real email must never have reached the provider
    assert spy.seen and "ana@acme.cl" not in spy.seen[0]
    # but the caller sees it re-hydrated in the response
    assert "ana@acme.cl" in result.response


def test_blocked_text_never_reaches_provider():
    spy = SpyProvider()
    gw = PrivacyGateway(provider=spy)
    result = gw.ask("the key is sk-ABCDEFGHIJKLMNOPQRST")
    assert result.status == "blocked"
    assert spy.seen == []  # nothing left the gateway


def test_needs_approval_then_confirm_sends():
    spy = SpyProvider()
    gw = PrivacyGateway(provider=spy)
    first = gw.ask("the contract is worth $600.000 CLP")
    assert first.status == "needs_approval"
    assert first.confirmation_token
    assert spy.seen == []  # nothing sent yet

    second = gw.confirm(first.confirmation_token)
    assert second.status == "sent"
    assert len(spy.seen) == 1
    assert "$600.000" in second.response  # re-hydrated


def test_confirm_with_bad_token_raises():
    gw = PrivacyGateway(provider=SpyProvider())
    with pytest.raises(ConfirmationError):
        gw.confirm("bogus")


def test_audit_log_records_every_path():
    gw = PrivacyGateway(provider=SpyProvider())
    gw.ask("hello, summarize this")                       # sent
    gw.ask("key sk-ABCDEFGHIJKLMNOPQRST")                 # blocked
    approval = gw.ask("worth $600.000 CLP")               # needs approval
    gw.confirm(approval.confirmation_token)               # sent
    log = gw.audit_entries()
    assert len(log) == 4
    decisions = [e["decision"] for e in log]
    assert "sent" in decisions and "blocked" in decisions and "needs_approval" in decisions


def test_preview_never_sends():
    spy = SpyProvider()
    gw = PrivacyGateway(provider=spy)
    result = gw.preview("worth $600.000 CLP to ana@acme.cl")
    assert result.status in {"allowed", "needs_approval", "blocked"}
    assert spy.seen == []
    assert gw.audit_entries() == []  # preview is side-effect free


def test_spy_conforms_to_protocol():
    assert isinstance(SpyProvider(), CloudProvider)
