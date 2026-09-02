import type { BridgeAction, BridgeRequest, BridgeResponse } from "@soc-watch/protocol";

const extensionId = import.meta.env.VITE_SOC_WATCH_EXTENSION_ID as string | undefined;

export async function sendBridgeMessage<TParams, TData>(action: BridgeAction, params: TParams): Promise<BridgeResponse<TData>> {
  const request: BridgeRequest<TParams> = {
    version: 1,
    requestId: crypto.randomUUID(),
    action,
    params
  };

  if (!extensionId || !globalThis.chrome?.runtime?.sendMessage) {
    return {
      version: 1,
      requestId: request.requestId,
      success: false,
      error: {
        code: "BRIDGE_NOT_INSTALLED",
        message: "SOC Watch Bridge is not configured or Chrome extension messaging is unavailable."
      }
    };
  }

  return new Promise((resolve) => {
    chrome.runtime.sendMessage(extensionId, request, (response: BridgeResponse<TData> | undefined) => {
      const lastError = chrome.runtime.lastError;
      if (lastError || !response) {
        resolve({
          version: 1,
          requestId: request.requestId,
          success: false,
          error: {
            code: "BRIDGE_NOT_INSTALLED",
            message: lastError?.message ?? "SOC Watch Bridge did not respond."
          }
        });
        return;
      }
      resolve(response);
    });
  });
}
