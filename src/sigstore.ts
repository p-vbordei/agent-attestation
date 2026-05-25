import { v7 as uuidv7 } from "uuid";
import type { ActionReceipt } from "./types.ts";
import { canonicalize } from "./jcs.ts";
import { generateKeyPair, fingerprint, signAction, verifyReceipt } from "./sign.ts";

export interface SignActionKeylessInput {
  agent: ActionReceipt["agent"];
  actor: string;
  action: ActionReceipt["action"];
  authorization?: ActionReceipt["authorization"];
  outcome: ActionReceipt["outcome"];
  outcomeRef?: string;
  prevReceiptId?: string;
  notes?: string;
  occurredAt?: string;
  identityToken?: string; // OIDC token
}

export async function signActionKeyless(input: SignActionKeylessInput): Promise<ActionReceipt> {
  const draft: ActionReceipt = {
    spec: "agent-attestation/0.1",
    id: uuidv7(),
    agent: input.agent,
    actor: input.actor,
    action: input.action,
    authorization: input.authorization,
    occurredAt: input.occurredAt ?? new Date().toISOString(),
    outcome: input.outcome,
    outcomeRef: input.outcomeRef,
    prevReceiptId: input.prevReceiptId,
    notes: input.notes,
    signature: {
      algorithm: "sigstore-keyless",
      keyId: "", // will be filled with OIDC identity
      value: "", // will be filled with base64 bundle
    },
  };

  const payload = canonicalize({ ...draft, signature: { ...draft.signature, value: "" } });

  if (process.env.SIGSTORE_MOCK === "true") {
    const kp = generateKeyPair();
    const sigActionDraft = signAction(
      {
        id: draft.id,
        agent: input.agent,
        actor: input.actor,
        action: input.action,
        authorization: input.authorization,
        outcome: input.outcome,
        outcomeRef: input.outcomeRef,
        prevReceiptId: input.prevReceiptId,
        notes: input.notes,
        occurredAt: draft.occurredAt,
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );

    const mockBundle = {
      mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
      mockPublicKeyPem: kp.publicKeyPem,
      mockSignature: sigActionDraft.signature.value,
      identity: input.actor,
    };

    draft.signature.keyId = input.actor;
    draft.signature.value = Buffer.from(JSON.stringify(mockBundle)).toString("base64");
    return draft;
  }

  const sigstore = await import("sigstore");
  const options: any = {};
  if (input.identityToken) {
    options.identityToken = input.identityToken;
  }
  
  const bundle = await sigstore.sign(Buffer.from(payload, "utf8"), options);
  
  let keyId = input.actor;
  try {
    const certBase64 = bundle.verificationMaterial?.x509CertificateChain?.certificates?.[0]?.rawBytes;
    if (certBase64) {
      // Note: Full key extraction or validation is done on verification.
      // We can use fallback or default value.
    }
  } catch {}

  draft.signature.keyId = keyId;
  draft.signature.value = Buffer.from(JSON.stringify(bundle)).toString("base64");
  return draft;
}

export async function verifyKeylessReceipt(receipt: ActionReceipt): Promise<boolean> {
  if (receipt.signature.algorithm !== "sigstore-keyless") return false;
  
  try {
    const bundleRaw = Buffer.from(receipt.signature.value, "base64").toString("utf8");
    const bundle = JSON.parse(bundleRaw);

    const draft = {
      ...receipt,
      signature: {
        ...receipt.signature,
        value: "",
      },
    };
    const payload = canonicalize(draft);

    if (process.env.SIGSTORE_MOCK === "true" || bundle.mockPublicKeyPem) {
      const mockedReceipt: ActionReceipt = {
        ...receipt,
        signature: {
          algorithm: "ed25519",
          keyId: fingerprint(bundle.mockPublicKeyPem),
          value: bundle.mockSignature,
        },
      };
      return verifyReceipt(mockedReceipt, bundle.mockPublicKeyPem);
    }

    const sigstore = await import("sigstore");
    await sigstore.verify(bundle, Buffer.from(payload, "utf8"));
    return true;
  } catch (err) {
    return false;
  }
}
