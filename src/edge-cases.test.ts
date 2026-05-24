import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  compactTrail,
  fingerprint,
  generateKeyPair,
  signAction,
  verifyReceipt,
  verifyTrail,
} from "./sign.ts";
import { canonicalize } from "./jcs.ts";

describe("jcs canonicalization", () => {
  it("is independent of key insertion order", () => {
    const a = { b: 1, a: 2, c: 3 };
    const b = { c: 3, a: 2, b: 1 };
    assert.equal(canonicalize(a), canonicalize(b));
  });

  it("canonicalizes nested objects deterministically", () => {
    const a = { outer: { z: 1, a: { y: 2, x: 3 } }, arr: [{ b: 1, a: 2 }] };
    const b = { arr: [{ a: 2, b: 1 }], outer: { a: { x: 3, y: 2 }, z: 1 } };
    assert.equal(canonicalize(a), canonicalize(b));
  });

  it("drops undefined keys", () => {
    const a = { a: 1, b: undefined, c: 3 };
    const b = { a: 1, c: 3 };
    assert.equal(canonicalize(a), canonicalize(b));
    assert.ok(!canonicalize(a).includes("\"b\""));
  });

  it("throws on NaN", () => {
    assert.throws(() => canonicalize(NaN), /non-finite/);
  });

  it("throws on Infinity", () => {
    assert.throws(() => canonicalize(Infinity), /non-finite/);
    assert.throws(() => canonicalize(-Infinity), /non-finite/);
  });
});

describe("fingerprint", () => {
  it("is deterministic across calls", () => {
    const kp = generateKeyPair();
    assert.equal(fingerprint(kp.publicKeyPem), fingerprint(kp.publicKeyPem));
  });

  it("produces different fingerprints for different keys", () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    assert.notEqual(fingerprint(kp1.publicKeyPem), fingerprint(kp2.publicKeyPem));
  });

  it("starts with 'sha256:'", () => {
    const kp = generateKeyPair();
    assert.ok(fingerprint(kp.publicKeyPem).startsWith("sha256:"));
  });
});

describe("signAction", () => {
  it("defaults occurredAt to current time", () => {
    const kp = generateKeyPair();
    const before = Date.now();
    const r = signAction(
      { agent: { id: "a" }, actor: "u", action: { verb: "v", target: "t" }, outcome: "succeeded" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const after = Date.now();
    const ts = Date.parse(r.occurredAt);
    assert.ok(ts >= before && ts <= after, `expected ${ts} in [${before},${after}]`);
  });

  it("preserves custom occurredAt", () => {
    const kp = generateKeyPair();
    const custom = "2020-01-01T00:00:00.000Z";
    const r = signAction(
      {
        agent: { id: "a" },
        actor: "u",
        action: { verb: "v", target: "t" },
        outcome: "succeeded",
        occurredAt: custom,
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    assert.equal(r.occurredAt, custom);
    assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
  });

  it("round-trips arbitrary JSON params", () => {
    const kp = generateKeyPair();
    const params = {
      str: "hi",
      num: 42,
      neg: -7.5,
      bool: true,
      nil: null,
      arr: [1, "two", { nested: true }],
      obj: { deeply: { nested: { value: "ok" } } },
    };
    const r = signAction(
      {
        agent: { id: "a" },
        actor: "u",
        action: { verb: "v", target: "t", params },
        outcome: "succeeded",
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    assert.deepEqual(r.action.params, params);
    assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
  });

  it("round-trips authorization with all fields", () => {
    const kp = generateKeyPair();
    const auth = {
      tokenId: "tok_123",
      approvedBy: "user:alice",
      approvedAt: "2025-01-01T12:00:00.000Z",
      policy: "policy://default",
    };
    const r = signAction(
      {
        agent: { id: "a" },
        actor: "u",
        action: { verb: "v", target: "t" },
        outcome: "succeeded",
        authorization: auth,
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    assert.deepEqual(r.authorization, auth);
    assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
  });

  it("round-trips outcome 'partial'", () => {
    const kp = generateKeyPair();
    const r = signAction(
      { agent: { id: "a" }, actor: "u", action: { verb: "v", target: "t" }, outcome: "partial" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    assert.equal(r.outcome, "partial");
    assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
  });

  it("round-trips notes with multi-line and unicode content", () => {
    const kp = generateKeyPair();
    const notes = "line one\nline two\n  emoji: 🚀✨\n  cyrillic: Привет\n  cjk: 你好";
    const r = signAction(
      {
        agent: { id: "a" },
        actor: "u",
        action: { verb: "v", target: "t" },
        outcome: "succeeded",
        notes,
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    assert.equal(r.notes, notes);
    assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
  });
});

describe("verifyReceipt tampering", () => {
  function makeReceipt() {
    const kp = generateKeyPair();
    const r = signAction(
      {
        agent: { id: "a" },
        actor: "user:alice",
        action: { verb: "v", target: "t", params: { x: 1 } },
        outcome: "succeeded",
        notes: "original notes",
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    return { kp, r };
  }

  it("fails when actor is tampered", () => {
    const { kp, r } = makeReceipt();
    r.actor = "user:mallory";
    assert.equal(verifyReceipt(r, kp.publicKeyPem), false);
  });

  it("fails when outcome is tampered", () => {
    const { kp, r } = makeReceipt();
    r.outcome = "failed";
    assert.equal(verifyReceipt(r, kp.publicKeyPem), false);
  });

  it("fails when params are tampered", () => {
    const { kp, r } = makeReceipt();
    r.action.params = { x: 999 };
    assert.equal(verifyReceipt(r, kp.publicKeyPem), false);
  });

  it("fails when notes are tampered", () => {
    const { kp, r } = makeReceipt();
    r.notes = "tampered notes";
    assert.equal(verifyReceipt(r, kp.publicKeyPem), false);
  });

  it("fails when signature.value is replaced with random bytes", () => {
    const { kp, r } = makeReceipt();
    r.signature.value = randomBytes(64).toString("base64");
    assert.equal(verifyReceipt(r, kp.publicKeyPem), false);
  });

  it("fails (without throwing) when keyId is from a different key than the public key supplied", () => {
    const { r } = makeReceipt();
    const other = generateKeyPair();
    // r is signed under its own key; we now verify it with `other.publicKeyPem`,
    // whose fingerprint will not match r.signature.keyId.
    assert.equal(verifyReceipt(r, other.publicKeyPem), false);
  });
});

describe("verifyTrail", () => {
  it("returns ok on empty array", () => {
    const kp = generateKeyPair();
    assert.deepEqual(verifyTrail([], kp.publicKeyPem), { ok: true });
  });

  it("returns ok on single valid receipt", () => {
    const kp = generateKeyPair();
    const r = signAction(
      { agent: { id: "a" }, actor: "u", action: { verb: "v", target: "t" }, outcome: "succeeded" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    assert.deepEqual(verifyTrail([r], kp.publicKeyPem), { ok: true });
  });

  it("fails on the first bad signature in a mixed trail", () => {
    const kp = generateKeyPair();
    const r1 = signAction(
      { agent: { id: "a" }, actor: "u", action: { verb: "v", target: "t1" }, outcome: "succeeded" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const r2 = signAction(
      {
        agent: { id: "a" },
        actor: "u",
        action: { verb: "v", target: "t2" },
        outcome: "succeeded",
        prevReceiptId: r1.id,
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const r3 = signAction(
      {
        agent: { id: "a" },
        actor: "u",
        action: { verb: "v", target: "t3" },
        outcome: "succeeded",
        prevReceiptId: r2.id,
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    // Tamper r2 only.
    r2.actor = "user:mallory";
    const v = verifyTrail([r1, r2, r3], kp.publicKeyPem);
    assert.equal(v.ok, false);
    assert.match(v.reason!, /signature invalid on receipt #1/);
  });

  it("fails with link-broken message when chain is reordered", () => {
    const kp = generateKeyPair();
    const r1 = signAction(
      { agent: { id: "a" }, actor: "u", action: { verb: "v", target: "t1" }, outcome: "succeeded" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const r2 = signAction(
      {
        agent: { id: "a" },
        actor: "u",
        action: { verb: "v", target: "t2" },
        outcome: "succeeded",
        prevReceiptId: r1.id,
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    // Swap order — signatures are still individually valid, but the link is broken.
    const v = verifyTrail([r2, r1], kp.publicKeyPem);
    assert.equal(v.ok, false);
    assert.match(v.reason!, /link broken/);
  });
});

describe("compactTrail", () => {
  it("throws on empty array", () => {
    assert.throws(() => compactTrail([]), /empty trail/);
  });

  it("produces the same merkleRoot for the same input across calls", () => {
    const kp = generateKeyPair();
    const r1 = signAction(
      { agent: { id: "a" }, actor: "u", action: { verb: "v", target: "t1" }, outcome: "succeeded" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const r2 = signAction(
      {
        agent: { id: "a" },
        actor: "u",
        action: { verb: "v", target: "t2" },
        outcome: "succeeded",
        prevReceiptId: r1.id,
      },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const s1 = compactTrail([r1, r2]);
    const s2 = compactTrail([r1, r2]);
    assert.equal(s1.merkleRoot, s2.merkleRoot);
  });

  it("produces a different merkleRoot when receipts are reordered", () => {
    const kp = generateKeyPair();
    const r1 = signAction(
      { agent: { id: "a" }, actor: "u", action: { verb: "v", target: "t1" }, outcome: "succeeded" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const r2 = signAction(
      { agent: { id: "a" }, actor: "u", action: { verb: "v", target: "t2" }, outcome: "succeeded" },
      kp.privateKeyPem,
      kp.publicKeyPem,
    );
    const s1 = compactTrail([r1, r2]);
    const s2 = compactTrail([r2, r1]);
    assert.notEqual(s1.merkleRoot, s2.merkleRoot);
  });
});
