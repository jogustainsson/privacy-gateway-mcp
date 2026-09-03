import pytest

from privacy_gateway_mcp.confirm import ConfirmationError, ConfirmationStore


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_valid_token_returns_payload():
    store = ConfirmationStore(ttl_seconds=100, clock=FakeClock())
    token = store.issue({"redacted": "hello"})
    assert store.confirm(token) == {"redacted": "hello"}


def test_token_is_single_use():
    store = ConfirmationStore(ttl_seconds=100, clock=FakeClock())
    token = store.issue({"x": 1})
    store.confirm(token)
    with pytest.raises(ConfirmationError):
        store.confirm(token)


def test_unknown_token_raises():
    store = ConfirmationStore()
    with pytest.raises(ConfirmationError):
        store.confirm("not-a-real-token")


def test_expired_token_raises():
    clock = FakeClock()
    store = ConfirmationStore(ttl_seconds=60, clock=clock)
    token = store.issue({"x": 1})
    clock.now = 61  # past the TTL
    with pytest.raises(ConfirmationError):
        store.confirm(token)


def test_expired_token_is_not_replayable():
    clock = FakeClock()
    store = ConfirmationStore(ttl_seconds=60, clock=clock)
    token = store.issue({"x": 1})
    clock.now = 61
    with pytest.raises(ConfirmationError):
        store.confirm(token)
    # even if the clock is rewound, the token was consumed on the failed attempt
    clock.now = 0
    with pytest.raises(ConfirmationError):
        store.confirm(token)
