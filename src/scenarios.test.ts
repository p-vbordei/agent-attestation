import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  compactTrail,
  generateKeyPair,
  signAction,
  verifyReceipt,
  verifyTrail,
  type ActionReceipt,
} from "./index.ts";

describe("scenario: agent produces a 5-step task chain", () => {
  it("signs, persists to JSONL, reads back, and verifies", async () => {
    const kp = generateKeyPair();
    const agent = { id: "claude-opus-4-7", version: "0.1", provider: "anthropic", runtime: "cli" };

    const steps: Array<{
      verb: string;
      target: string;
      outcome: ActionReceipt["outcome"];
      notes?: string;
    }> = [
      { verb: "plan", target: "task:cleanup-inbox", outcome: "succeeded", notes: "drafted plan" },
      { verb: "list", target: "gmail:inbox", outcome: "succeeded" },
      { verb: "label", target: "gmail:message/abc", outcome: "succeeded", notes: "labeled triage" },
      { verb: "label", target: "gmail:message/xyz", outcome: "partial", notes: "rate-limited" },
      { verb: "summarize", target: "task:cleanup-inbox", outcome: "succeeded" },
    ];

    const chain: ActionReceipt[] = [];
    let prev: string | undefined;
    for (const s of steps) {
      const r = signAction(
        {
          agent,
          actor: "user:alice",
          action: { verb: s.verb, target: s.target },
          outcome: s.outcome,
          notes: s.notes,
          prevReceiptId: prev,
        },
        kp.privateKeyPem,
        kp.publicKeyPem,
      );
      chain.push(r);
      prev = r.id;
    }

    assert.equal(chain.length, 5);

    // Serialize trail to disk as JSONL.
    const dir = mkdtempSync(path.join(tmpdir(), "attest-scenario-"));
    try {
      const trailPath = path.join(dir, "trail.jsonl");
      await fs.writeFile(trailPath, chain.map((r) => JSON.stringify(r)).join("\n") + "\n");

      // Read back.
      const raw = await fs.readFile(trailPath, "utf8");
      const restored = raw
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l) as ActionReceipt);

      assert.equal(restored.length, 5);

      // Each receipt verifies individually.
      for (const r of restored) {
        assert.equal(verifyReceipt(r, kp.publicKeyPem), true, `receipt ${r.id} failed to verify`);
      }

      // Whole-chain verification passes.
      const v = verifyTrail(restored, kp.publicKeyPem);
      assert.equal(v.ok, true, v.reason);

      // Summary matches the in-memory chain.
      const summary = compactTrail(restored);
      assert.equal(summary.count, 5);
      assert.equal(summary.firstReceiptId, chain[0]!.id);
      assert.equal(summary.lastReceiptId, chain[4]!.id);
      assert.equal(summary.merkleRoot, compactTrail(chain).merkleRoot);

      // Chain links are intact.
      for (let i = 1; i < restored.length; i++) {
        assert.equal(restored[i]!.prevReceiptId, restored[i - 1]!.id);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
