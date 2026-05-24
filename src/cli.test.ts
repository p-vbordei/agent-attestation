import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(__dirname, "cli.ts");

function runCli(args: string[], opts: { cwd?: string } = {}) {
  // Use tsx (devDependency, already used by `npm run cli`) to execute the .ts CLI directly.
  return spawnSync("npx", ["--no-install", "tsx", CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd,
  });
}

describe("CLI smoke test", () => {
  let dir: string;

  before(() => {
    dir = mkdtempSync(path.join(tmpdir(), "attest-cli-"));
  });

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("keygen writes private and public key files", () => {
    const out = path.join(dir, "agent.key");
    const r = runCli(["keygen", "--out", out]);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /keyId=sha256:/);
  });

  it("sign-action emits a receipt JSON", async () => {
    const keyPath = path.join(dir, "agent.key");
    const r = runCli([
      "sign-action",
      "--agent", "claude-opus-4-7",
      "--actor", "user:alice",
      "--verb", "send_message",
      "--target", "slack:#team",
      "--outcome", "succeeded",
      "--outcome-ref", "ref-1",
      "--key", keyPath,
    ]);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const receipt = JSON.parse(r.stdout);
    assert.equal(receipt.spec, "agent-attestation/0.1");
    assert.equal(receipt.actor, "user:alice");
    assert.equal(receipt.outcome, "succeeded");
    await fs.writeFile(path.join(dir, "r1.json"), r.stdout);
  });

  it("verify reports OK on an untampered receipt", () => {
    const r = runCli([
      "verify",
      path.join(dir, "r1.json"),
      "--public-key",
      path.join(dir, "agent.pub"),
    ]);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /OK/);
  });

  it("verify reports FAILED and exits non-zero on a tampered receipt", async () => {
    const raw = await fs.readFile(path.join(dir, "r1.json"), "utf8");
    const r = JSON.parse(raw);
    r.actor = "user:mallory";
    const tamperedPath = path.join(dir, "r1-tampered.json");
    await fs.writeFile(tamperedPath, JSON.stringify(r));
    const out = runCli(["verify", tamperedPath, "--public-key", path.join(dir, "agent.pub")]);
    assert.notEqual(out.status, 0);
    assert.match(out.stdout, /FAILED/);
  });

  it("inspect prints receipt summary", () => {
    const out = runCli(["inspect", path.join(dir, "r1.json")]);
    assert.equal(out.status, 0, `stderr: ${out.stderr}`);
    assert.match(out.stdout, /id: /);
    assert.match(out.stdout, /agent: claude-opus-4-7/);
    assert.match(out.stdout, /actor: user:alice/);
    assert.match(out.stdout, /action: send_message/);
    assert.match(out.stdout, /outcome: succeeded/);
  });

  it("trail builds a JSONL trail and prints a TrailSummary", async () => {
    // Sign r2 chained to r1.
    const r1 = JSON.parse(await fs.readFile(path.join(dir, "r1.json"), "utf8"));
    const r2cmd = runCli([
      "sign-action",
      "--agent", "claude-opus-4-7",
      "--actor", "user:alice",
      "--verb", "send_message",
      "--target", "slack:#team",
      "--outcome", "succeeded",
      "--prev", r1.id,
      "--key", path.join(dir, "agent.key"),
    ]);
    assert.equal(r2cmd.status, 0, `stderr: ${r2cmd.stderr}`);
    await fs.writeFile(path.join(dir, "r2.json"), r2cmd.stdout);
    const r2 = JSON.parse(r2cmd.stdout);

    const r3cmd = runCli([
      "sign-action",
      "--agent", "claude-opus-4-7",
      "--actor", "user:alice",
      "--verb", "send_message",
      "--target", "slack:#team",
      "--outcome", "succeeded",
      "--prev", r2.id,
      "--key", path.join(dir, "agent.key"),
    ]);
    assert.equal(r3cmd.status, 0, `stderr: ${r3cmd.stderr}`);
    await fs.writeFile(path.join(dir, "r3.json"), r3cmd.stdout);

    const trailOut = path.join(dir, "trail.jsonl");
    const tcmd = runCli([
      "trail",
      trailOut,
      path.join(dir, "r1.json"),
      path.join(dir, "r2.json"),
      path.join(dir, "r3.json"),
    ]);
    assert.equal(tcmd.status, 0, `stderr: ${tcmd.stderr}`);
    const summary = JSON.parse(tcmd.stdout);
    assert.equal(summary.count, 3);
    assert.equal(summary.firstReceiptId, r1.id);
    assert.equal(summary.lastReceiptId, JSON.parse(r3cmd.stdout).id);
    assert.match(summary.merkleRoot, /^[0-9a-f]{64}$/);

    const onDisk = await fs.readFile(trailOut, "utf8");
    assert.equal(onDisk.trim().split("\n").length, 3);
  });

  it("verify-trail reports OK for a correctly chained trail", () => {
    const out = runCli([
      "verify-trail",
      path.join(dir, "trail.jsonl"),
      "--public-key",
      path.join(dir, "agent.pub"),
    ]);
    assert.equal(out.status, 0, `stderr: ${out.stderr}`);
    assert.match(out.stdout, /OK/);
  });

  it("verify-trail reports FAILED with link-broken when chain is reordered", async () => {
    const lines = (await fs.readFile(path.join(dir, "trail.jsonl"), "utf8"))
      .split("\n")
      .filter(Boolean);
    // Swap first two — signatures still valid individually, but the link is broken.
    const swapped = [lines[1], lines[0], lines[2]].join("\n") + "\n";
    const brokenPath = path.join(dir, "trail-broken.jsonl");
    await fs.writeFile(brokenPath, swapped);
    const out = runCli([
      "verify-trail",
      brokenPath,
      "--public-key",
      path.join(dir, "agent.pub"),
    ]);
    assert.notEqual(out.status, 0);
    assert.match(out.stdout, /FAILED/);
    assert.match(out.stdout, /link broken/);
  });
});
