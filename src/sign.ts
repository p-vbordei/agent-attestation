import {
  createPrivateKey,
  createPublicKey,
  createHash,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { v7 as uuidv7 } from "uuid";
import type { ActionReceipt, TrailSummary } from "./types.ts";
import { canonicalize } from "./jcs.ts";

export function generateKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  return { publicKeyPem, privateKeyPem, keyId: fingerprint(publicKeyPem) };
}

export function fingerprint(publicKeyPem: string): string {
  return "sha256:" + createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 32);
}

export interface SignActionInput {
  id?: string;
  agent: ActionReceipt["agent"];
  actor: string;
  action: ActionReceipt["action"];
  authorization?: ActionReceipt["authorization"];
  outcome: ActionReceipt["outcome"];
  outcomeRef?: string;
  prevReceiptId?: string;
  notes?: string;
  occurredAt?: string;
}

export function signAction(
  input: SignActionInput,
  privateKeyPem: string,
  publicKeyPem: string,
): ActionReceipt {
  const keyId = fingerprint(publicKeyPem);
  const draft: ActionReceipt = {
    spec: "agent-attestation/0.1",
    id: input.id ?? uuidv7(),
    agent: input.agent,
    actor: input.actor,
    action: input.action,
    authorization: input.authorization,
    occurredAt: input.occurredAt ?? new Date().toISOString(),
    outcome: input.outcome,
    outcomeRef: input.outcomeRef,
    prevReceiptId: input.prevReceiptId,
    notes: input.notes,
    signature: { algorithm: "ed25519", keyId, value: "" },
  };
  const payload = canonicalize(draft);
  const privateKey = createPrivateKey(privateKeyPem);
  const sig = edSign(null, Buffer.from(payload, "utf8"), privateKey);
  draft.signature.value = sig.toString("base64");
  return draft;
}

export function verifyReceipt(receipt: ActionReceipt, publicKeyPem: string): boolean {
  if (receipt.signature.algorithm !== "ed25519") return false;
  const expectedKeyId = fingerprint(publicKeyPem);
  if (receipt.signature.keyId !== expectedKeyId) return false;
  const draft = { ...receipt, signature: { ...receipt.signature, value: "" } };
  const payload = canonicalize(draft);
  const pk = createPublicKey(publicKeyPem);
  return edVerify(
    null,
    Buffer.from(payload, "utf8"),
    pk,
    Buffer.from(receipt.signature.value, "base64"),
  );
}

export function verifyTrail(
  receipts: ActionReceipt[],
  publicKeyPem: string,
): { ok: boolean; reason?: string } {
  if (receipts.length === 0) return { ok: true };
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i]!;
    if (!verifyReceipt(r, publicKeyPem)) {
      return { ok: false, reason: `signature invalid on receipt #${i} (${r.id})` };
    }
    if (i > 0 && r.prevReceiptId !== receipts[i - 1]!.id) {
      return { ok: false, reason: `link broken between #${i - 1} and #${i}` };
    }
  }
  return { ok: true };
}

export function compactTrail(receipts: ActionReceipt[]): TrailSummary {
  if (receipts.length === 0) throw new Error("empty trail");
  const hashes = receipts.map((r) =>
    createHash("sha256").update(canonicalize(r)).digest("hex"),
  );
  const merkleRoot = createHash("sha256").update(hashes.join(",")).digest("hex");
  return {
    firstReceiptId: receipts[0]!.id,
    lastReceiptId: receipts[receipts.length - 1]!.id,
    count: receipts.length,
    merkleRoot,
  };
}
