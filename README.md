# privacy-gateway-mcp

An [MCP](https://modelcontextprotocol.io) server that sits **between an assistant and a cloud LLM** and enforces a simple rule: *no raw sensitive data leaves the process.*

Before any text is sent out, the gateway:

1. **Redacts** sensitive entities (emails, phones, national IDs, cards, money, API keys) into reversible placeholders — `ana@acme.cl` → `[EMAIL_1]`.
2. Runs a **deterministic egress policy** that can `ALLOW`, require `HUMAN APPROVAL`, or `BLOCK` the call. The LLM never gets to overrule it.
3. **Re-hydrates** the provider's reply, so the caller sees real values while the cloud only ever saw placeholders.
4. Writes every decision to an **append-only audit log**.

> This is a small, generic illustration of a pattern I run in a private production system: a multi-agent setup where **business rules live in code, not in the prompt**, and any action that touches data or money needs explicit confirmation. No business logic or real data is included here.

## Why this exists

LLM assistants are great at drafting replies to an email or summarizing a contract — but doing so usually means shipping the raw text (names, phone numbers, amounts) to a third-party API. Two things must be true before that's acceptable:

- **The cloud must not see real entities.** Redaction is *bidirectional* so the answer is still useful.
- **The decision to send can't be the model's.** Whether a payload leaves — and whether a human signs off first — is a hard rule enforced in code. The model proposes; the gateway decides.

That "deterministic layer over the LLM" plus "confirm before it leaves" is the whole point.

## Architecture

```
                 ┌──────────────────────── privacy gateway ────────────────────────┐
   text ───▶ redact (reversible)  ─▶  egress policy ─┬─ BLOCKED        ─▶ ✋ nothing leaves
                                                     ├─ NEEDS_APPROVAL ─▶ 🎫 token, nothing leaves
                                                     └─ ALLOWED        ─▶ send redacted ─▶ cloud LLM
                                                                                            │
   caller ◀──────────────── rehydrate ◀──────────────────────────────── redacted reply ◀──┘
                 └── every path is written to an append-only audit log ──┘
```

| Module | Responsibility |
|---|---|
| `anonymizer.py` | Bidirectional entity redaction (span-based, consistent placeholders) |
| `policy.py` | Deterministic egress rules — `BLOCKED > NEEDS_APPROVAL > ALLOWED` |
| `confirm.py` | Single-use, TTL-bound human-approval tokens |
| `audit.py` | Append-only decision log (counts + reasons, never raw values) |
| `providers.py` | Pluggable cloud provider (`EchoProvider` stub by default, offline) |
| `gateway.py` | Orchestration — pure, synchronous, framework-free (fully unit-tested) |
| `server.py` | Thin MCP wrapper exposing the tools + resource |

The core (`gateway.py` and below) has **no MCP dependency**, so the guardrails are tested in isolation and the MCP layer stays thin.

## MCP tools

| Tool | What it does |
|---|---|
| `redact_preview(text)` | Dry run: shows what would be redacted and how the policy would rule. No send, no token. |
| `ask_cloud_llm(text)` | Guarded egress. Returns `sent` (with the re-hydrated reply), `blocked`, or `needs_approval` (with a `confirmation_token`). |
| `confirm_send(token)` | Releases a payload the policy flagged for approval. Token is single-use and time-limited. |
| `get_audit_log()` | The append-only decision trail. Also exposed as the resource `audit://log`. |

## The policy (defaults)

| Signal | Outcome |
|---|---|
| Text contains an API key/token or a card number | **BLOCKED** — never routed to the cloud, even redacted |
| A sensitive entity survives redaction | **BLOCKED** (fail-closed) |
| Text contains a monetary amount | **NEEDS_APPROVAL** |
| More than 5 entities redacted, or prompt > 4000 chars | **NEEDS_APPROVAL** |
| Otherwise | **ALLOWED** |

All thresholds live in `PolicyConfig` — they are code, not prompt.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
python -m privacy_gateway_mcp.server                # stdio transport
```

Register it with an MCP client (e.g. Claude Desktop's `mcp` config):

```json
{
  "mcpServers": {
    "privacy-gateway": {
      "command": "python",
      "args": ["-m", "privacy_gateway_mcp.server"]
    }
  }
}
```

## Test

```bash
pip install -e ".[dev]"
pytest -q
```

The suite covers the pieces that matter: redaction round-trips to identity, secrets/cards are blocked, money needs approval, `block` beats `approval`, approval tokens are single-use and expire, and — end to end — **the real entity never reaches the provider while the caller still gets it back re-hydrated**.

## Extending it

- **Real provider** — implement `CloudProvider.complete`; a commented Anthropic sketch is in `providers.py`. Text is already redacted before it reaches the provider.
- **Better detection** — the regex detectors are dependency-free on purpose (runs on bare metal, no model download). Swapping in an NER model (spaCy / Microsoft Presidio) is a single method on `Anonymizer.detect`.
- **Policy** — add categories or thresholds in `PolicyConfig`; the engine picks them up.

## License

MIT — see [LICENSE](LICENSE).
