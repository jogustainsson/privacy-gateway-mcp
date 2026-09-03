"""Cloud LLM providers.

The gateway is provider-agnostic: it only needs something that takes a (already
redacted) prompt and returns a completion. The default ``EchoProvider`` performs no
network I/O so the whole server runs offline and deterministically in tests and demos.

To wire a real provider, implement ``complete`` with an SDK call. A sketch for the
Anthropic SDK is included below (commented) — note that by the time text reaches a
provider it is already redacted, so no real entity is ever sent to the cloud.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class CloudProvider(Protocol):
    """Anything that can turn a prompt into a completion."""

    def complete(self, prompt: str) -> str: ...


class EchoProvider:
    """Offline stub. Returns a deterministic reply that reuses the placeholders it was
    given, so re-hydration is observable end to end without any network call."""

    def complete(self, prompt: str) -> str:
        return (
            "[stub completion — a real provider would answer here]\n"
            f"Understood. I processed the following (redacted) input:\n{prompt}"
        )


# --- Real provider sketch (uncomment and add `anthropic` to dependencies) --------
#
# class AnthropicProvider:
#     def __init__(self, model: str = "claude-opus-4-8") -> None:
#         import anthropic
#         self._client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
#         self._model = model
#
#     def complete(self, prompt: str) -> str:
#         # `prompt` is already redacted; no real entity leaves the process.
#         msg = self._client.messages.create(
#             model=self._model,
#             max_tokens=1024,
#             messages=[{"role": "user", "content": prompt}],
#         )
#         return "".join(block.text for block in msg.content if block.type == "text")
