import type { ActionReceipt } from "../types.ts";
import { signAction } from "../sign.ts";
import type { SignActionInput } from "../sign.ts";

export interface LangChainCallbackHandlerOptions {
  agent: ActionReceipt["agent"];
  actor: string;
  privateKeyPem?: string;
  publicKeyPem?: string;
  signFn?: (input: SignActionInput) => Promise<ActionReceipt> | ActionReceipt;
  onReceipt?: (receipt: ActionReceipt) => void | Promise<void>;
}

export class AttestationCallbackHandler {
  private activeRuns = new Map<string, { verb: string; target: string; params: any }>();
  private prevReceiptId?: string;

  constructor(private options: LangChainCallbackHandlerOptions) {
    if (!options.signFn && (!options.privateKeyPem || !options.publicKeyPem)) {
      throw new Error("Either signFn or privateKeyPem + publicKeyPem must be provided");
    }
  }

  getPrevReceiptId(): string | undefined {
    return this.prevReceiptId;
  }

  setPrevReceiptId(id: string | undefined): void {
    this.prevReceiptId = id;
  }

  async handleToolStart(
    tool: { name: string; description?: string },
    input: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, any>
  ): Promise<void> {
    let params: any = input;
    try {
      params = JSON.parse(input);
    } catch {}

    this.activeRuns.set(runId, {
      verb: "call_tool",
      target: tool.name,
      params: typeof params === "object" ? params : { input: params },
    });
  }

  async handleToolEnd(output: string, runId: string): Promise<void> {
    const active = this.activeRuns.get(runId);
    if (!active) return;
    this.activeRuns.delete(runId);

    const inputReceipt: SignActionInput = {
      agent: this.options.agent,
      actor: this.options.actor,
      action: {
        verb: active.verb,
        target: active.target,
        params: active.params,
      },
      outcome: "succeeded",
      outcomeRef: runId,
      prevReceiptId: this.prevReceiptId,
      notes: typeof output === "string" && output.length < 500 ? output : undefined,
    };

    let receipt: ActionReceipt;
    if (this.options.signFn) {
      receipt = await this.options.signFn(inputReceipt);
    } else {
      receipt = signAction(
        inputReceipt,
        this.options.privateKeyPem!,
        this.options.publicKeyPem!
      );
    }

    this.prevReceiptId = receipt.id;
    if (this.options.onReceipt) {
      await this.options.onReceipt(receipt);
    }
  }

  async handleToolError(err: any, runId: string): Promise<void> {
    const active = this.activeRuns.get(runId);
    if (!active) return;
    this.activeRuns.delete(runId);

    const inputReceipt: SignActionInput = {
      agent: this.options.agent,
      actor: this.options.actor,
      action: {
        verb: active.verb,
        target: active.target,
        params: active.params,
      },
      outcome: "failed",
      notes: err.message ?? String(err),
      outcomeRef: runId,
      prevReceiptId: this.prevReceiptId,
    };

    let receipt: ActionReceipt;
    if (this.options.signFn) {
      receipt = await this.options.signFn(inputReceipt);
    } else {
      receipt = signAction(
        inputReceipt,
        this.options.privateKeyPem!,
        this.options.publicKeyPem!
      );
    }

    this.prevReceiptId = receipt.id;
    if (this.options.onReceipt) {
      await this.options.onReceipt(receipt);
    }
  }
}
