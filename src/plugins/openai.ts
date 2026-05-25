import type { ActionReceipt } from "../types.ts";
import { signAction } from "../sign.ts";
import type { SignActionInput } from "../sign.ts";

export interface OpenAIToolWrapperOptions {
  agent: ActionReceipt["agent"];
  actor: string;
  privateKeyPem?: string;
  publicKeyPem?: string;
  signFn?: (input: SignActionInput) => Promise<ActionReceipt> | ActionReceipt;
  onReceipt?: (receipt: ActionReceipt) => void | Promise<void>;
  getPrevReceiptId?: () => string | undefined;
  setPrevReceiptId?: (id: string) => void;
}

export function wrapOpenAITools<T extends Record<string, (...args: any[]) => any>>(
  tools: T,
  options: OpenAIToolWrapperOptions
): T {
  const wrappedTools: any = {};
  let localPrevReceiptId: string | undefined;

  for (const [name, fn] of Object.entries(tools)) {
    wrappedTools[name] = async (...args: any[]) => {
      const prevId = options.getPrevReceiptId ? options.getPrevReceiptId() : localPrevReceiptId;
      const actionInput = args[0];

      try {
        const result = await fn(...args);

        const inputReceipt: SignActionInput = {
          agent: options.agent,
          actor: options.actor,
          action: {
            verb: "call_function",
            target: name,
            params: typeof actionInput === "object" ? actionInput : { arguments: actionInput },
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
            verb: "call_function",
            target: name,
            params: typeof actionInput === "object" ? actionInput : { arguments: actionInput },
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
  }

  return wrappedTools as T;
}
