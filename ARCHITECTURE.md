# Architecture — agent-attestation

## Receipt

```ts
export interface ActionReceipt {
  spec: "agent-attestation/0.1";
  id: string;                      // UUIDv7 — time-ordered
  agent: {
    id: string;                    // model or runtime ID, e.g. "claude-opus-4-7"
    version?: string;
    provider?: string;
    runtime?: string;              // "langchain" | "openai-agents-sdk" | "custom"
  };
  actor: string;                   // user the agent acts for
  action: {
    verb: string;                  // canonical, e.g. "send_message"
    target: string;                // canonical, e.g. "slack:#team-eng"
    params?: Record<string, unknown>;
  };
  authorization?: {
    tokenId?: string;
    approvedBy?: string;           // human approver if any
    approvedAt?: string;
    policy?: string;               // policy URI / id
  };
  occurredAt: string;
  outcome: "succeeded" | "failed" | "partial";
  outcomeRef?: string;             // platform message ID, ticket ID
  prevReceiptId?: string;          // chain link
  notes?: string;
  signature: {
    algorithm: "ed25519";
    keyId: string;                 // fingerprint of agent's public key
    value: string;                 // base64
  };
}
```

## Signing

The signed payload is the receipt with `signature.value` set to the empty string, canonicalised with RFC 8785 JCS. Verification reverses this.

## Trail

A `Trail` is an append-only JSONL file of receipts. Each receipt's `prevReceiptId` links to the previous in the same task chain. Verifying a trail walks the chain and validates each signature + each link.

`compactTrail(trail)` produces a summary record:

```ts
interface TrailSummary {
  firstReceiptId: string;
  lastReceiptId: string;
  count: number;
  merkleRoot: string;   // SHA-256 of canonicalized concatenated receipt hashes
}
```

This lets a long trail be archived to cheap storage while the summary remains in fast storage for auditors.

## Identity

The agent's signing key represents the **runtime instance**, not the model:

- A LangChain process on Alice's laptop has one key.
- A LangChain process on a server has a different key.
- An OpenAI Agents SDK run inside a CI job has its own ephemeral key (logged to Sigstore).

This mirrors the way TLS certificates work — the identity is the deployment, not the abstract software.

## Privacy

Receipts contain pointers (`outcomeRef`, `target`) but not message bodies by default. Frameworks can opt to include hashed content (`params: { contentSha256: "..." }`) for non-repudiation without leaking content.

## OpenTelemetry integration

Each receipt has an ID. A GenAI span can carry `gen_ai.attestation.receipt_id` so trace explorers can join span ↔ receipt. The receipt itself is **not** stored as a span attribute — it's a separate event stream that can outlive trace retention.

## Threat model

- **Defends:** repudiation ("the agent didn't do that"), tampering, forgery, replay (via `occurredAt` and `prevReceiptId`).
- **Does not defend:** an attacker who steals the agent's signing key. Mitigation: per-session ephemeral keys + Sigstore-keyless flow.
- **Does not defend:** lying signers. Mitigation: receipts are verifiable evidence in disputes, not policy enforcement.
