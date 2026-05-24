import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compactTrail, generateKeyPair, signAction, verifyReceipt, verifyTrail } from "./sign.ts";

describe("attestation", () => {
  it("signs and verifies", () => {
    const kp = generateKeyPair();
    const r = signAction(
      {
        agent: { id: "claude-opus-4-7" },
        actor: "user:alice",
        action: { verb: "send_message", target: "slack:#team-eng" },
        outcome: "succeeded",
        outcomeRef: "1748100123.000045",
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
  });

  it("fails on tampered payload", () => {
    const kp = generateKeyPair();
    const r = signAction(
      {
        agent: { id: "claude-opus-4-7" },
        actor: "user:alice",
        action: { verb: "x", target: "y" },
        outcome: "succeeded",
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    r.action.target = "evil:target";
    assert.equal(verifyReceipt(r, kp.publicKeyPem), false);
  });

  it("fails with wrong key", () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const r = signAction(
      {
        agent: { id: "x" },
        actor: "user:a",
        action: { verb: "v", target: "t" },
        outcome: "succeeded",
      },
      kp1.privateKeyPem,
      kp1.publicKeyPem,
    );
    assert.equal(verifyReceipt(r, kp2.publicKeyPem), false);
  });

  it("verifies a trail with chain links", () => {
    const kp = generateKeyPair();
    const r1 = signAction(
      { agent: { id: "x" }, actor: "u", action: { verb: "v", target: "t1" }, outcome: "succeeded" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const r2 = signAction(
      { agent: { id: "x" }, actor: "u", action: { verb: "v", target: "t2" }, outcome: "succeeded", prevReceiptId: r1.id },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const v = verifyTrail([r1, r2], kp.publicKeyPem);
    assert.equal(v.ok, true);
    const s = compactTrail([r1, r2]);
    assert.equal(s.count, 2);
    assert.equal(s.firstReceiptId, r1.id);
    assert.equal(s.lastReceiptId, r2.id);
  });

  it("flags broken trail link", () => {
    const kp = generateKeyPair();
    const r1 = signAction(
      { agent: { id: "x" }, actor: "u", action: { verb: "v", target: "t1" }, outcome: "succeeded" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const r2 = signAction(
      { agent: { id: "x" }, actor: "u", action: { verb: "v", target: "t2" }, outcome: "succeeded", prevReceiptId: "wrong" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const v = verifyTrail([r1, r2], kp.publicKeyPem);
    assert.equal(v.ok, false);
    assert.ok(v.reason?.includes("link broken"));
  });
});
