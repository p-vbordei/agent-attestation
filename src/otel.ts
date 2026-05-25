import { createContextKey, context } from "@opentelemetry/api";
import type { Context, Span } from "@opentelemetry/api";
import type { ReadableSpan, SpanExporter, SpanProcessor } from "@opentelemetry/sdk-trace-base";
import type { ActionReceipt } from "./types.ts";

export const ATTESTATION_RECEIPT_KEY = createContextKey("agent-attestation-receipt");

export function withReceipt(ctx: Context, receipt: ActionReceipt): Context {
  return ctx.setValue(ATTESTATION_RECEIPT_KEY, receipt);
}

export function getReceipt(ctx: Context): ActionReceipt | undefined {
  return ctx.getValue(ATTESTATION_RECEIPT_KEY) as ActionReceipt | undefined;
}

export function attachReceiptToSpan(span: Span, receipt: ActionReceipt): void {
  span.setAttribute("gen_ai.attestation.receipt_id", receipt.id);
  span.setAttribute("gen_ai.attestation.receipt", JSON.stringify(receipt));
}

export class AttestationSpanProcessor implements SpanProcessor {
  onStart(span: Span, ctx: Context): void {
    const receipt = getReceipt(ctx);
    if (receipt) {
      attachReceiptToSpan(span, receipt);
    }
  }

  onEnd(span: ReadableSpan): void {
    // No-op
  }

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }
}

export class AttestationSpanExporter implements SpanExporter {
  constructor(private delegate: SpanExporter) {}

  export(spans: ReadableSpan[], resultCallback: (result: any) => void): void {
    this.delegate.export(spans, resultCallback);
  }

  shutdown(): Promise<void> {
    return this.delegate.shutdown();
  }
}
