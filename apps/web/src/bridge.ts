import type { BridgeAction, BridgeRequest, BridgeResponse } from "@soc-watch/protocol";

const configuredExtensionId = import.meta.env.VITE_SOC_WATCH_EXTENSION_ID as string | undefined;
const knownDevExtensionId = "ofljokhnjhmjbffolgbjplbohglemajc";

export interface BridgeStream {
  send<TParams>(action: BridgeAction, params: TParams): void;
  disconnect(): void;
}

export function getExtensionId(): string | undefined {
  return configuredExtensionId || localStorage.getItem("socWatchExtensionId") || knownDevExtensionId;
}

export function saveExtensionId(value: string): void {
  localStorage.setItem("socWatchExtensionId", value.trim());
}

export async function sendBridgeMessage<TParams, TData>(action: BridgeAction, params: TParams): Promise<BridgeResponse<TData>> {
  const request: BridgeRequest<TParams> = {
    version: 1,
    requestId: crypto.randomUUID(),
    action,
    params
  };

  const extensionId = getExtensionId();
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

export function connectBridgeStream(options: {
  onSnapshot: (snapshot: unknown) => void;
  onResponse?: (response: BridgeResponse) => void;
  onStatus: (status: "connecting" | "connected" | "disconnected" | "unavailable", message?: string) => void;
}): BridgeStream | null {
  const extensionId = getExtensionId();
  if (!extensionId || !globalThis.chrome?.runtime?.connect) {
    options.onStatus("unavailable", "SOC Watch Bridge is not configured or Chrome extension messaging is unavailable.");
    return null;
  }

  options.onStatus("connecting");
  let port: chrome.runtime.Port;
  try {
    port = chrome.runtime.connect(extensionId, { name: "soc-watch-live" });
  } catch (error) {
    options.onStatus("unavailable", error instanceof Error ? error.message : "Unable to connect to SOC Watch Bridge.");
    return null;
  }

  port.onMessage.addListener((message: unknown) => {
    const record = typeof message === "object" && message !== null ? (message as Record<string, unknown>) : {};
    if (record.type === "soc-watch.snapshot") {
      options.onStatus("connected");
      options.onSnapshot(record.snapshot);
      return;
    }
    if (record.type === "soc-watch.response" && options.onResponse) {
      options.onResponse(record.response as BridgeResponse);
    }
  });

  port.onDisconnect.addListener(() => {
    const lastError = chrome.runtime.lastError;
    options.onStatus("disconnected", lastError?.message ?? "SOC Watch Bridge disconnected.");
  });

  return {
    send<TParams>(action: BridgeAction, params: TParams) {
      const request: BridgeRequest<TParams> = {
        version: 1,
        requestId: crypto.randomUUID(),
        action,
        params
      };
      port.postMessage(request);
    },
    disconnect() {
      port.disconnect();
    }
  };
}
