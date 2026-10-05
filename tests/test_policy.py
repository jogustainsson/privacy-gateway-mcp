from privacy_gateway_mcp.anonymizer import Anonymizer
from privacy_gateway_mcp.policy import EgressPolicy
from privacy_gateway_mcp.types import Decision, PolicyConfig

anon = Anonymizer()


def _eval(text: str, policy: EgressPolicy) -> Decision:
    red = anon.redact(text)
    return policy.evaluate(text, red.redacted, red.entities).decision


def test_clean_text_is_allowed():
    assert _eval("Please summarize the quarterly plan.", EgressPolicy()) is Decision.ALLOWED


def test_secret_is_hard_blocked():
    assert _eval("the key is sk-ABCDEFGHIJKLMNOPQRST", EgressPolicy()) is Decision.BLOCKED


def test_anthropic_key_is_hard_blocked():
    key = "sk-ant-api03-AbC1_dEf2-GhIj3kLmNoPqRsTuVwXyZ012345"
    assert _eval(f"here is my key {key}", EgressPolicy()) is Decision.BLOCKED


def test_card_is_hard_blocked():
    assert _eval("card 4111 1111 1111 1111", EgressPolicy()) is Decision.BLOCKED


def test_money_requires_approval():
    assert _eval("the deal is worth $600.000 CLP", EgressPolicy()) is Decision.NEEDS_APPROVAL


def test_too_many_entities_requires_approval():
    text = "emails a@x.cl b@x.cl c@x.cl d@x.cl e@x.cl f@x.cl"
    assert _eval(text, EgressPolicy()) is Decision.NEEDS_APPROVAL


def test_long_prompt_requires_approval():
    policy = EgressPolicy(PolicyConfig(max_chars_auto=20))
    assert _eval("this prompt is definitely longer than twenty chars", policy) is Decision.NEEDS_APPROVAL


def test_block_beats_approval():
    # money (approval) + secret (block) -> block wins
    assert _eval("pay $500 with key sk-ABCDEFGHIJKLMNOPQRST", EgressPolicy()) is Decision.BLOCKED


def test_reasons_are_populated():
    red = anon.redact("worth $600.000 CLP")
    result = EgressPolicy().evaluate("worth $600.000 CLP", red.redacted, red.entities)
    assert result.reasons and isinstance(result.reasons[0], str)
