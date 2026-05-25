import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import type { ActionReceipt, VerifiableCredential } from "./types.ts";
import { canonicalize } from "./jcs.ts";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function encodeBase58(buffer: Buffer): string {
  if (buffer.length === 0) return "";
  
  let numZeros = 0;
  while (numZeros < buffer.length && buffer[numZeros] === 0) {
    numZeros++;
  }
  
  const digits = [0];
  for (let i = numZeros; i < buffer.length; i++) {
    let carry = buffer[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  
  let string = "";
  for (let i = 0; i < numZeros; i++) {
    string += "1";
  }
  if (numZeros < buffer.length) {
    for (let i = digits.length - 1; i >= 0; i--) {
      string += BASE58_ALPHABET[digits[i]!]!;
    }
  }
  return string;
}

export function decodeBase58(string: string): Buffer {
  if (string.length === 0) return Buffer.alloc(0);
  
  let numZeros = 0;
  while (numZeros < string.length && string[numZeros] === "1") {
    numZeros++;
  }
  
  const bytes = [0];
  for (let i = numZeros; i < string.length; i++) {
    const char = string[i]!;
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) throw new Error("Invalid base58 character");
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  
  const leadingZeros = numZeros > 0 ? Buffer.alloc(numZeros) : Buffer.alloc(0);
  if (numZeros === string.length) {
    return leadingZeros;
  }
  return Buffer.concat([leadingZeros, Buffer.from(bytes.reverse())]);
}

export function extractRawPublicKey(publicKeyPem: string): Buffer {
  const pk = createPublicKey(publicKeyPem);
  const der = pk.export({ format: "der", type: "spki" });
  if (der.length !== 44) {
    throw new Error(`Unexpected Ed25519 public key DER length: ${der.length}`);
  }
  return der.subarray(12);
}

export function publicKeyToDidKey(publicKeyPem: string): string {
  const rawKey = extractRawPublicKey(publicKeyPem);
  const multicodec = Buffer.concat([Buffer.from([0xed, 0x01]), rawKey]);
  const base58 = encodeBase58(multicodec);
  return `did:key:z${base58}`;
}

export function didKeyToPublicKeyPem(didKey: string): string {
  if (!didKey.startsWith("did:key:z")) {
    throw new Error(`Invalid did:key format: ${didKey}`);
  }
  const base58Str = didKey.slice(9);
  const multicodec = decodeBase58(base58Str);
  if (multicodec[0] !== 0xed || multicodec[1] !== 0x01) {
    throw new Error("Only Ed25519 did:key is supported");
  }
  const rawKey = multicodec.subarray(2);
  if (rawKey.length !== 32) {
    throw new Error("Invalid raw Ed25519 public key length");
  }
  const header = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  const der = Buffer.concat([header, rawKey]);
  const pk = createPublicKey({ key: der, format: "der", type: "spki" });
  return pk.export({ format: "pem", type: "spki" }).toString();
}

export async function exportToVC(
  receipt: ActionReceipt,
  privateKeyPem: string,
  publicKeyPem: string,
): Promise<VerifiableCredential> {
  const didKey = publicKeyToDidKey(publicKeyPem);

  const vc: Omit<VerifiableCredential, "proof"> & { proof: Omit<VerifiableCredential["proof"], "proofValue"> } = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    id: `urn:uuid:${receipt.id}`,
    type: ["VerifiableCredential", "AgentActionCredential"],
    issuer: didKey,
    validFrom: receipt.occurredAt,
    credentialSubject: {
      id: `urn:uuid:${receipt.id}`,
      agent: receipt.agent,
      actor: receipt.actor,
      action: receipt.action,
      authorization: receipt.authorization,
      occurredAt: receipt.occurredAt,
      outcome: receipt.outcome,
      outcomeRef: receipt.outcomeRef,
      prevReceiptId: receipt.prevReceiptId,
      notes: receipt.notes,
    },
    proof: {
      type: "Ed25519Signature2020",
      created: new Date().toISOString(),
      verificationMethod: `${didKey}#${didKey.slice(8)}`,
      proofPurpose: "assertionMethod",
    }
  };

  const payload = canonicalize(vc);
  const privateKey = createPrivateKey(privateKeyPem);
  const sig = edSign(null, Buffer.from(payload, "utf8"), privateKey);
  const sigBase58 = "z" + encodeBase58(sig);
  
  return {
    ...vc,
    proof: {
      ...vc.proof,
      proofValue: sigBase58,
    }
  } as VerifiableCredential;
}

export async function verifyVC(vc: VerifiableCredential, publicKeyPem?: string): Promise<boolean> {
  if (vc.proof.type !== "Ed25519Signature2020") return false;
  if (vc.proof.proofPurpose !== "assertionMethod") return false;
  
  let pem = publicKeyPem;
  if (!pem) {
    const issuer = typeof vc.issuer === "string" ? vc.issuer : (vc.issuer as any).id;
    if (!issuer || !issuer.startsWith("did:key:z")) return false;
    try {
      pem = didKeyToPublicKeyPem(issuer);
    } catch {
      return false;
    }
  }

  const didKey = publicKeyToDidKey(pem);
  if (!vc.proof.verificationMethod.startsWith(didKey)) return false;

  const draft = {
    ...vc,
    proof: {
      ...vc.proof,
      proofValue: undefined,
    }
  };
  delete (draft.proof as any).proofValue;

  const payload = canonicalize(draft);
  const pk = createPublicKey(pem);

  const sigStr = vc.proof.proofValue;
  if (!sigStr.startsWith("z")) return false;
  
  try {
    const sig = decodeBase58(sigStr.slice(1));
    return edVerify(
      null,
      Buffer.from(payload, "utf8"),
      pk,
      sig
    );
  } catch {
    return false;
  }
}
