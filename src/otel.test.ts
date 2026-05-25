import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { context } from "@opentelemetry/api";
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { generateKeyPair, signAction } from "./sign.ts";
import { withReceipt, AttestationSpanProcessor, AttestationSpanExporter } from "./otel.ts";

describe("OpenTelemetry integration", () => {
  it("automatically attaches attestation receipt to span attributes", () => {
    const memoryExporter = new InMemorySpanExporter();
    const provider = new BasicTracerProvider({
      spanProcessors: [
        new AttestationSpanProcessor(),
        new SimpleSpanProcessor(new AttestationSpanExporter(memoryExporter))
      ]
    });
    const tracer = provider.getTracer("test-tracer");

    const kp = generateKeyPair();
    const receipt = signAction(
      {
        agent: { id: "test-otel-agent" },
        actor: "user:otel",
        action: { verb: "test_action", target: "otel_target" },
        outcome: "succeeded"
      },
      kp.privateKeyPem,
      kp.publicKeyPem
    );

    const ctx = withReceipt(context.active(), receipt);
    context.with(ctx, () => {
      const span = tracer.startSpan("agent-action", undefined, ctx);
      span.end();
    });

    const spans = memoryExporter.getFinishedSpans();
    assert.equal(spans.length, 1);
    const span = spans[0]!;
    
    assert.equal(span.attributes["gen_ai.attestation.receipt_id"], receipt.id);
    assert.equal(span.attributes["gen_ai.attestation.receipt"], JSON.stringify(receipt));
  });
});
