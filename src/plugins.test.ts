import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, verifyReceipt } from "./sign.ts";
import { AttestationCallbackHandler } from "./plugins/langchain.ts";
import { wrapVercelAITool } from "./plugins/vercel-ai.ts";
import { wrapOpenAITools } from "./plugins/openai.ts";
import type { ActionReceipt } from "./types.ts";

describe("Framework Plugins", () => {
  const kp = generateKeyPair();
  const agent = { id: "plugin-test-agent", version: "1.0" };
  const actor = "user:plugin-user";

  describe("LangChain Callback Handler", () => {
    it("signs tool calls successfully", async () => {
      const receipts: ActionReceipt[] = [];
      const handler = new AttestationCallbackHandler({
        agent,
        actor,
        privateKeyPem: kp.privateKeyPem,
        publicKeyPem: kp.publicKeyPem,
        onReceipt: (r) => {
          receipts.push(r);
        },
      });

      const tool = { name: "test_tool", description: "a test tool" };
      const runId = "run-123";

      await handler.handleToolStart(tool, JSON.stringify({ query: "hello" }), runId);
      await handler.handleToolEnd("tool response", runId);

      assert.equal(receipts.length, 1);
      const r = receipts[0]!;
      assert.equal(r.action.verb, "call_tool");
      assert.equal(r.action.target, "test_tool");
      assert.deepEqual(r.action.params, { query: "hello" });
      assert.equal(r.outcome, "succeeded");
      assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
    });

    it("signs tool errors", async () => {
      const receipts: ActionReceipt[] = [];
      const handler = new AttestationCallbackHandler({
        agent,
        actor,
        privateKeyPem: kp.privateKeyPem,
        publicKeyPem: kp.publicKeyPem,
        onReceipt: (r) => {
          receipts.push(r);
        },
      });

      const tool = { name: "error_tool" };
      const runId = "run-456";

      await handler.handleToolStart(tool, "plain_input", runId);
      await handler.handleToolError(new Error("tool failed"), runId);

      assert.equal(receipts.length, 1);
      const r = receipts[0]!;
      assert.equal(r.outcome, "failed");
      assert.equal(r.notes, "tool failed");
      assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
    });
  });

  describe("Vercel AI SDK wrapper", () => {
    it("intercepts execute method on tools", async () => {
      const receipts: ActionReceipt[] = [];
      
      const mockTool = {
        description: "my tool",
        execute: async (args: { input: string }) => {
          return `result: ${args.input}`;
        }
      };

      const wrapped = wrapVercelAITool("my_vercel_tool", mockTool, {
        agent,
        actor,
        privateKeyPem: kp.privateKeyPem,
        publicKeyPem: kp.publicKeyPem,
        onReceipt: (r) => { receipts.push(r); }
      });

      const res = await wrapped.execute!({ input: "value" });
      assert.equal(res, "result: value");
      assert.equal(receipts.length, 1);
      const r = receipts[0]!;
      assert.equal(r.action.verb, "execute_tool");
      assert.equal(r.action.target, "my_vercel_tool");
      assert.deepEqual(r.action.params, { input: "value" });
      assert.equal(r.outcome, "succeeded");
      assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
    });
  });

  describe("OpenAI wrapper", () => {
    it("wraps tools and intercepts invocations", async () => {
      const receipts: ActionReceipt[] = [];
      
      const rawTools = {
        calculate: async (args: { a: number; b: number }) => {
          return args.a + args.b;
        }
      };

      const wrapped = wrapOpenAITools(rawTools, {
        agent,
        actor,
        privateKeyPem: kp.privateKeyPem,
        publicKeyPem: kp.publicKeyPem,
        onReceipt: (r) => { receipts.push(r); }
      });

      const res = await wrapped.calculate({ a: 10, b: 20 });
      assert.equal(res, 30);
      assert.equal(receipts.length, 1);
      const r = receipts[0]!;
      assert.equal(r.action.verb, "call_function");
      assert.equal(r.action.target, "calculate");
      assert.deepEqual(r.action.params, { a: 10, b: 20 });
      assert.equal(r.outcome, "succeeded");
      assert.equal(verifyReceipt(r, kp.publicKeyPem), true);
    });
  });
});
