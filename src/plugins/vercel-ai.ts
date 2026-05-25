import type { ActionReceipt } from "../types.ts";
import { signAction } from "../sign.ts";
import type { SignActionInput } from "../sign.ts";

export interface VercelAIToolWrapperOptions {
  agent: ActionReceipt["agent"];
  actor: string;
  privateKeyPem?: string;
  publicKeyPem?: string;
  signFn?: (input: SignActionInput) => Promise<ActionReceipt> | ActionReceipt;
  onReceipt?: (receipt: ActionReceipt) => void | Promise<void>;
  getPrevReceiptId?: () => string | undefined;
  setPrevReceiptId?: (id: string) => void;
}

export function wrapVercelAITool<T extends { execute?: (...args: any[]) => any }>(
  toolName: string,
  tool: T,
  options: VercelAIToolWrapperOptions
): T {
  if (!tool.execute) return tool;

  const originalExecute = tool.execute;
  let localPrevReceiptId: string | undefined;

  const wrappedExecute = async (...args: any[]) => {
    const prevId = options.getPrevReceiptId ? options.getPrevReceiptId() : localPrevReceiptId;
    const actionInput = args[0];

    try {
      const result = await originalExecute(...args);

      const inputReceipt: SignActionInput = {
        agent: options.agent,
        actor: options.actor,
        action: {
          verb: "execute_tool",
          target: toolName,
          params: typeof actionInput === "object" ? actionInput : { input: actionInput },
        },
        outcome: "succeeded",
        prevReceiptId: prevId,
      };

      let receipt: ActionReceipt;
      if (options.signFn) {
        receipt = await options.signFn(inputReceipt);
      } else {
        receipt = signAction(
          inputReceipt,
          options.privateKeyPem!,
          options.publicKeyPem!
        );
      }

      if (options.setPrevReceiptId) {
        options.setPrevReceiptId(receipt.id);
      } else {
        localPrevReceiptId = receipt.id;
      }

      if (options.onReceipt) {
        await options.onReceipt(receipt);
      }

      return result;
    } catch (err: any) {
      const inputReceipt: SignActionInput = {
        agent: options.agent,
        actor: options.actor,
        action: {
          verb: "execute_tool",
          target: toolName,
          params: typeof actionInput === "object" ? actionInput : { input: actionInput },
        },
        outcome: "failed",
        notes: err.message ?? String(err),
        prevReceiptId: prevId,
      };

      let receipt: ActionReceipt;
      if (options.signFn) {
        receipt = await options.signFn(inputReceipt);
      } else {
        receipt = signAction(
          inputReceipt,
          options.privateKeyPem!,
          options.publicKeyPem!
        );
      }

      if (options.setPrevReceiptId) {
        options.setPrevReceiptId(receipt.id);
      } else {
        localPrevReceiptId = receipt.id;
      }

      if (options.onReceipt) {
        await options.onReceipt(receipt);
      }

      throw err;
    }
  };

  return {
    ...tool,
    execute: wrappedExecute,
  };
}
