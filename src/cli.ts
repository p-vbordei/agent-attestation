#!/usr/bin/env node
import process from "node:process";
import { promises as fs } from "node:fs";
import {
  compactTrail,
  generateKeyPair,
  signAction,
  verifyReceipt,
  verifyTrail,
  type ActionReceipt,
} from "./index.ts";

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main() {
  const [, , cmd, ...rest] = process.argv;
  if (!cmd || cmd === "help" || cmd === "-h" || cmd === "--help") {
    console.log(`attest — agent-attestation CLI

Usage:
  attest keygen --out <prefix>
  attest sign-action --agent <id> --actor <key> --verb <v> --target <t>
                     --outcome succeeded|failed|partial [--outcome-ref <r>]
                     [--prev <id>] --key <agent.key>
  attest verify <receipt.json> --public-key <agent.pub>
  attest inspect <receipt.json>
  attest trail <out.jsonl> <receipt1.json> <receipt2.json> ...
  attest verify-trail <trail.jsonl> --public-key <agent.pub>
`);
    return;
  }

  switch (cmd) {
    case "keygen": {
      const out = flag(rest, "out") ?? "./agent.key";
      const kp = generateKeyPair();
      await fs.writeFile(out, kp.privateKeyPem, { mode: 0o600 });
      const pubPath = out.replace(/\.key$/, "") + ".pub";
      await fs.writeFile(pubPath, kp.publicKeyPem, { mode: 0o644 });
      console.log(`Wrote ${out} (private) and ${pubPath} (public). keyId=${kp.keyId}`);
      return;
    }
    case "sign-action": {
      const agentId = flag(rest, "agent");
      const actor = flag(rest, "actor");
      const verb = flag(rest, "verb");
      const target = flag(rest, "target");
      const outcome = flag(rest, "outcome") as ActionReceipt["outcome"] | undefined;
      const outcomeRef = flag(rest, "outcome-ref");
      const prev = flag(rest, "prev");
      const keyPath = flag(rest, "key");
      if (!agentId || !actor || !verb || !target || !outcome || !keyPath) {
        throw new Error("missing required flags; see --help");
      }
      const privateKeyPem = await fs.readFile(keyPath, "utf8");
      const pubPath = keyPath.replace(/\.key$/, "") + ".pub";
      const publicKeyPem = await fs.readFile(pubPath, "utf8");
      const r = signAction(
        {
          agent: { id: agentId },
          actor,
          action: { verb, target },
          outcome,
          outcomeRef,
          prevReceiptId: prev,
        },
        privateKeyPem,
        publicKeyPem,
      );
      process.stdout.write(JSON.stringify(r, null, 2) + "\n");
      return;
    }
    case "verify": {
      const file = rest[0];
      const pk = flag(rest, "public-key");
      if (!file || !pk) throw new Error("usage: verify <receipt.json> --public-key <pub>");
      const r = JSON.parse(await fs.readFile(file, "utf8")) as ActionReceipt;
      const pubPem = await fs.readFile(pk, "utf8");
      const ok = verifyReceipt(r, pubPem);
      console.log(ok ? "OK" : "FAILED");
      if (!ok) process.exit(1);
      return;
    }
    case "inspect": {
      const file = rest[0];
      if (!file) throw new Error("receipt path required");
      const r = JSON.parse(await fs.readFile(file, "utf8")) as ActionReceipt;
      console.log(`id: ${r.id}`);
      console.log(`agent: ${r.agent.id}`);
      console.log(`actor: ${r.actor}`);
      console.log(`action: ${r.action.verb} → ${r.action.target}`);
      console.log(`outcome: ${r.outcome} (${r.outcomeRef ?? "no ref"})`);
      console.log(`signed at: ${r.occurredAt}`);
      console.log(`prev: ${r.prevReceiptId ?? "(none)"}`);
      console.log(`keyId: ${r.signature.keyId}`);
      return;
    }
    case "trail": {
      const out = rest[0];
      const files = rest.slice(1);
      if (!out || files.length === 0) throw new Error("usage: trail <out.jsonl> <receipts...>");
      const lines: string[] = [];
      for (const f of files) {
        const r = JSON.parse(await fs.readFile(f, "utf8")) as ActionReceipt;
        lines.push(JSON.stringify(r));
      }
      await fs.writeFile(out, lines.join("\n") + "\n");
      const receipts = lines.map((l) => JSON.parse(l) as ActionReceipt);
      console.log(JSON.stringify(compactTrail(receipts), null, 2));
      return;
    }
    case "verify-trail": {
      const file = rest[0];
      const pk = flag(rest, "public-key");
      if (!file || !pk) throw new Error("usage: verify-trail <trail.jsonl> --public-key <pub>");
      const raw = await fs.readFile(file, "utf8");
      const receipts = raw.split(/\n/).filter(Boolean).map((l) => JSON.parse(l) as ActionReceipt);
      const pubPem = await fs.readFile(pk, "utf8");
      const r = verifyTrail(receipts, pubPem);
      console.log(r.ok ? "OK" : `FAILED: ${r.reason}`);
      if (!r.ok) process.exit(1);
      return;
    }
    default:
      console.error(`Unknown command: ${cmd}`);
      process.exit(2);
  }
}

main().catch((e) => { console.error(e.message ?? String(e)); process.exit(1); });
