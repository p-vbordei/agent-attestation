# agent-attestation

> Cryptographically verifiable receipts for actions taken by AI agents.

## Problem

When an AI agent acts on a user's behalf — sends a Slack message, files a JIRA ticket, executes a shell command, drafts an email, transfers money — there is no portable, cryptographically verifiable receipt that:

- *This* agent
- Took *this* action
- On behalf of *that* user
- At *that* time
- With *that* authorization

OpenTelemetry GenAI semantic conventions standardize **traces** (`gen_ai.*` attributes). Traces are not signed and don't survive transport. They're observability, not attestation.

A signed receipt is necessary for:

- Audit trails for regulated work (financial actions, healthcare summaries, legal drafts)
- Disputing or accepting an action ("the agent did X — here's the proof")
- Action-attestation policies ("this MCP server only accepts attested calls")
- User-visible "what did the assistant actually do" UIs

## Why doesn't this already exist

OpenTelemetry covers traces. Sigstore covers software supply chain. Neither covers **agent actions** as a first-class signed event.

## What this is

A **format** + **library** + **CLI** for signed action receipts:

```ts
interface ActionReceipt {
  spec: "agent-attestation/0.1";
  id: string;
  agent: { id: string; version: string; provider: string };   // e.g. "claude-opus-4-7"
  actor: string;                                              // user the agent acts for
  action: { verb: string; target: string; params?: object };  // "send_message", "slack:#team-eng", {...}
  authorization?: {
    tokenId?: string;       // e.g. approval-binding ID
    approvedBy?: string;    // human approver
    approvedAt?: string;
  };
  occurredAt: string;       // ISO 8601
  outcome: "succeeded" | "failed" | "partial";
  outcomeRef?: string;      // platform message ID, ticket ID, etc.
  prevReceiptId?: string;   // chain to previous action in same task
}
```

Receipts are **Ed25519-signed** by the agent runtime, in canonical JSON (RFC 8785 JCS). Verifiable offline. Chainable into a `Trail` for audit purposes.

## Quick start

```bash
pnpm install
pnpm build

# Generate an agent identity key
pnpm cli keygen --out ./agent.key

# Sign a receipt for an action
pnpm cli sign-action \
  --agent "claude-opus-4-7" \
  --actor "user:alice@example.com" \
  --verb "send_message" \
  --target "slack:#team-eng" \
  --outcome succeeded \
  --outcome-ref "1748100123.000045" \
  --key ./agent.key \
  > receipt.json

# Verify it
pnpm cli verify receipt.json --public-key ./agent.pub

# Build a trail
pnpm cli trail trail.jsonl receipt.json receipt2.json
```

## MVP scope

- [x] Receipt JSON schema + canonical JSON via RFC 8785 (reusing mcp-provenance's jcs.ts pattern)
- [x] Ed25519 sign / verify
- [x] CLI: `keygen`, `sign-action`, `verify`, `inspect`, `trail`
- [x] Trail validation (chain link integrity)
- [x] Unit tests
- [x] OpenTelemetry exporter: attach receipt as a span attribute
- [x] Verifiable Credentials (W3C VC v2) mapping
- [x] Sigstore-keyless variant for runtime-attested identities
- [x] Plugin examples for LangChain / OpenAI Agents SDK

## How agents adopt this

A runtime adds two hooks:

1. **On action commit** — produce + sign a receipt; persist to a trail.
2. **On display/audit** — show the trail; expose to verifiers.

Receipts can live alongside OpenTelemetry spans (`gen_ai.attestation.receipt_id`) without disrupting existing observability pipelines.

## Roadmap

| Milestone | What |
|---|---|
| v0.1 | Schema + Ed25519 sign/verify + CLI + tests |
| v0.2 | OpenTelemetry exporter |
| v0.3 | Trail compactor + Merkle-root summary |
| v0.4 | W3C Verifiable Credentials mapping |
| v0.5 | Reference runtime plugins (LangChain, custom) |

## References

- Research paper §7.5, §10.1 #14
- OpenTelemetry GenAI semantic conventions: <https://opentelemetry.io/blog/2025/ai-agent-observability/>
- W3C Verifiable Credentials Data Model 2.0
- RFC 8785 — JSON Canonicalization Scheme

## License

Apache-2.0 © Vlad Bordei
