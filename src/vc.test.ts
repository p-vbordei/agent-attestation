import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, signAction } from "./sign.ts";
import {
  encodeBase58,
  decodeBase58,
  publicKeyToDidKey,
  didKeyToPublicKeyPem,
  exportToVC,
  verifyVC
} from "./vc.ts";

describe("W3C VC v2.0", () => {
  describe("base58", () => {
    it("round-trips arbitrary buffers", () => {
      const inputs = [
        Buffer.from([]),
        Buffer.from([0]),
        Buffer.from([0, 0, 1, 2, 3]),
        Buffer.from("hello world"),
        Buffer.from(new Uint8Array(32).fill(42))
      ];
      for (const input of inputs) {
        const encoded = encodeBase58(input);
        const decoded = decodeBase58(encoded);
        assert.deepEqual(decoded, input);
      }
    });

    it("throws on invalid characters", () => {
      assert.throws(() => decodeBase58("0")); // '0' is not in base58 alphabet
      assert.throws(() => decodeBase58("O")); // 'O' is not in base58 alphabet
      assert.throws(() => decodeBase58("l")); // 'l' is not in base58 alphabet
    });
  });

  describe("did:key conversion", () => {
    it("round-trips key pairs", () => {
      const kp = generateKeyPair();
      const didKey = publicKeyToDidKey(kp.publicKeyPem);
      assert.ok(didKey.startsWith("did:key:z6M"));
      
      const reconstructedPub = didKeyToPublicKeyPem(didKey);
      // Compare clean PEMs
      const cleanOriginal = kp.publicKeyPem.replace(/\r?\n/g, "").trim();
      const cleanReconstructed = reconstructedPub.replace(/\r?\n/g, "").trim();
      assert.equal(cleanReconstructed, cleanOriginal);
    });

    it("throws on invalid did:key formats", () => {
      assert.throws(() => didKeyToPublicKeyPem("did:key:y123"));
      assert.throws(() => didKeyToPublicKeyPem("did:example:123"));
    });
  });

  describe("exportToVC and verifyVC", () => {
    it("signs, exports, and verifies VC correctly", async () => {
      const kp = generateKeyPair();
      const receipt = signAction(
        {
          agent: { id: "test-agent" },
          actor: "user:bob",
          action: { verb: "send", target: "recipient" },
          outcome: "succeeded"
        },
        kp.privateKeyPem,
        kp.publicKeyPem
      );

      const vc = await exportToVC(receipt, kp.privateKeyPem, kp.publicKeyPem);

      // Verify W3C VC structural elements
      assert.deepEqual(vc["@context"], [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ]);
      assert.equal(vc.type[0], "VerifiableCredential");
      assert.equal(vc.type[1], "AgentActionCredential");
      assert.equal(vc.credentialSubject.actor, "user:bob");
      assert.equal(vc.credentialSubject.outcome, "succeeded");
      assert.ok(vc.proof.proofValue.startsWith("z"));

      // Verify with explicit public key PEM
      const okWithPem = await verifyVC(vc, kp.publicKeyPem);
      assert.equal(okWithPem, true);

      // Verify with key resolution (extracting key from issuer did:key)
      const okWithResolution = await verifyVC(vc);
      assert.equal(okWithResolution, true);
    });

    it("fails verification if VC payload is tampered", async () => {
      const kp = generateKeyPair();
      const receipt = signAction(
        {
          agent: { id: "test-agent" },
          actor: "user:bob",
          action: { verb: "send", target: "recipient" },
          outcome: "succeeded"
        },
        kp.privateKeyPem,
        kp.publicKeyPem
      );

      const vc = await exportToVC(receipt, kp.privateKeyPem, kp.publicKeyPem);

      // Tamper
      vc.credentialSubject.actor = "user:eve";

      const ok = await verifyVC(vc);
      assert.equal(ok, false);
    });

    it("fails verification if signature is tampered", async () => {
      const kp = generateKeyPair();
      const receipt = signAction(
        {
          agent: { id: "test-agent" },
          actor: "user:bob",
          action: { verb: "send", target: "recipient" },
          outcome: "succeeded"
        },
        kp.privateKeyPem,
        kp.publicKeyPem
      );

      const vc = await exportToVC(receipt, kp.privateKeyPem, kp.publicKeyPem);

      // Tamper signature
      vc.proof.proofValue = "z" + encodeBase58(Buffer.alloc(64, 9));

      const ok = await verifyVC(vc);
      assert.equal(ok, false);
    });
  });
});
