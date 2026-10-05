from privacy_gateway_mcp.anonymizer import Anonymizer
from privacy_gateway_mcp.types import EntityType


def test_detects_common_entities():
    a = Anonymizer()
    text = "Contact ana@acme.cl or +56 9 1234 5678, RUT 12.345.678-5, pay $600.000 CLP"
    types = {e.type for e in a.redact(text).entities}
    assert EntityType.EMAIL in types
    assert EntityType.PHONE in types
    assert EntityType.RUT in types
    assert EntityType.MONEY in types


def test_roundtrip_is_identity():
    a = Anonymizer()
    text = "Write to ana@acme.cl and cc bob@acme.cl about the $1.200 invoice."
    red = a.redact(text)
    assert red.redacted != text
    assert "ana@acme.cl" not in red.redacted
    assert a.rehydrate(red.redacted, red.mapping) == text


def test_same_value_gets_same_placeholder():
    a = Anonymizer()
    red = a.redact("ana@acme.cl wrote; reply to ana@acme.cl please")
    # one distinct email -> one placeholder used twice
    assert red.redacted.count("[EMAIL_1]") == 2
    assert len([e for e in red.entities if e.type is EntityType.EMAIL]) == 1


def test_redacted_text_has_no_residual():
    a = Anonymizer()
    red = a.redact("email ana@acme.cl phone +56912345678")
    assert not a.has_residual_sensitive(red.redacted)


def test_card_placeholder_does_not_swallow_the_following_space():
    """The card span must end on a digit.

    A trailing separator inside the match glued the placeholder to the next
    word: "card [CARD_1]for the move".
    """
    a = Anonymizer()
    red = a.redact("Charge $1.250.000 to card 4532 7712 3456 7890 for the move.")
    assert "[CARD_1] for the move." in red.redacted
    assert a.rehydrate(red.redacted, red.mapping) == (
        "Charge $1.250.000 to card 4532 7712 3456 7890 for the move."
    )


def test_card_is_detected_with_each_separator_style():
    a = Anonymizer()
    for raw in ("4532771234567890", "4532 7712 3456 7890", "4532-7712-3456-7890"):
        red = a.redact(f"card {raw} ok")
        assert any(e.type is EntityType.CARD for e in red.entities), raw
        assert red.redacted.endswith(" ok"), raw


def test_secret_takes_priority_over_number_like_matches():
    a = Anonymizer()
    red = a.redact("key sk-ABCDEFGHIJKLMNOPQRST here")
    assert any(e.type is EntityType.SECRET for e in red.entities)


def test_detects_anthropic_api_key():
    """Anthropic keys 'sk-ant-...' were slipping through: the old regex stopped at
    the first hyphen. They must be detected as SECRET and never reach the cloud."""
    a = Anonymizer()
    text = "deploy with ANTHROPIC_API_KEY=sk-ant-api03-AbC1_dEf2-GhIj3kLmNoPqRsTuVwXyZ012345 now"
    red = a.redact(text)
    assert any(e.type is EntityType.SECRET for e in red.entities)
    assert "sk-ant-" not in red.redacted
    assert not a.has_residual_sensitive(red.redacted)


def test_response_placeholders_rehydrate():
    a = Anonymizer()
    red = a.redact("send it to ana@acme.cl")
    # a provider reply that reuses the placeholder
    reply = "I will email [EMAIL_1] shortly."
    assert a.rehydrate(reply, red.mapping) == "I will email ana@acme.cl shortly."
