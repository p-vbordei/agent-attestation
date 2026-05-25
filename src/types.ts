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
    algorithm: "ed25519" | "sigstore-keyless";
    keyId: string; // public key fingerprint for ed25519, OIDC subject for sigstore
    value: string; // signature value (base64) or serialized sigstore bundle
  };
}

export interface TrailSummary {
  firstReceiptId: string;
  lastReceiptId: string;
  count: number;
  merkleRoot: string;
}

export interface Proof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
  cryptosuite?: string;
  [key: string]: unknown;
}

export interface VerifiableCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string | { id: string; [key: string]: unknown };
  validFrom: string;
  validUntil?: string;
  credentialSubject: {
    id: string;
    agent: ActionReceipt["agent"];
    actor: ActionReceipt["actor"];
    action: ActionReceipt["action"];
    authorization?: ActionReceipt["authorization"];
    occurredAt: ActionReceipt["occurredAt"];
    outcome: ActionReceipt["outcome"];
    outcomeRef?: ActionReceipt["outcomeRef"];
    prevReceiptId?: ActionReceipt["prevReceiptId"];
    notes?: ActionReceipt["notes"];
    [key: string]: unknown;
  };
  proof: Proof;
}

