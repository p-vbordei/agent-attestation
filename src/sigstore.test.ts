import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { signActionKeyless, verifyKeylessReceipt } from "./sigstore.ts";

describe("Sigstore keyless", () => {
  before(() => {
    process.env.SIGSTORE_MOCK = "true";
  });

  it("signs and verifies keylessly", async () => {
    const receipt = await signActionKeyless({
      agent: { id: "ephemeral-runner" },
      actor: "runner-identity@example.com",
      action: { verb: "deploy", target: "prod-cluster" },
      outcome: "succeeded"
    });

    assert.equal(receipt.signature.algorithm, "sigstore-keyless");
    assert.equal(receipt.signature.keyId, "runner-identity@example.com");
    assert.ok(receipt.signature.value.length > 0);

    const verified = await verifyKeylessReceipt(receipt);
    assert.equal(verified, true);
  });

  it("fails verification if keyless receipt is tampered", async () => {
    const receipt = await signActionKeyless({
      agent: { id: "ephemeral-runner" },
      actor: "runner-identity@example.com",
      action: { verb: "deploy", target: "prod-cluster" },
      outcome: "succeeded"
    });

    receipt.actor = "malicious-runner@example.com";

    const verified = await verifyKeylessReceipt(receipt);
    assert.equal(verified, false);
  });
});
