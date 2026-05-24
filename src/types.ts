export interface ActionReceipt {
  spec: "agent-attestation/0.1";
  id: string;
  agent: {
    id: string;
    version?: string;
    provider?: string;
    runtime?: string;
  };
  actor: string;
  action: {
    verb: string;
    target: string;
    params?: Record<string, unknown>;
  };
  authorization?: {
    tokenId?: string;
    approvedBy?: string;
    approvedAt?: string;
    policy?: string;
  };
  occurredAt: string;
  outcome: "succeeded" | "failed" | "partial";
  outcomeRef?: string;
  prevReceiptId?: string;
  notes?: string;
  signature: {
    algorithm: "ed25519";
    keyId: string;
    value: string;
  };
}

export interface TrailSummary {
  firstReceiptId: string;
  lastReceiptId: string;
  count: number;
  merkleRoot: string;
}
