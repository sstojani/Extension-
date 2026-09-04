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
    return sendViaWindowRelay<TParams, TData>(request);
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
    return connectWindowRelay(options);
  }

  options.onStatus("connecting");
  let port: chrome.runtime.Port;
  try {
    port = chrome.runtime.connect(extensionId, { name: "soc-watch-live" });
  } catch (error) {
    return connectWindowRelay(options);
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

function connectWindowRelay(options: {
  onSnapshot: (snapshot: unknown) => void;
  onResponse?: (response: BridgeResponse) => void;
  onStatus: (status: "connecting" | "connected" | "disconnected" | "unavailable", message?: string) => void;
}): BridgeStream {
  options.onStatus("connecting", "Waiting for SOC Watch Bridge page relay.");
  let disconnected = false;
  let ready = false;

  const listener = (event: MessageEvent) => {
    if (event.source !== window || event.origin !== window.location.origin) return;
    const data = typeof event.data === "object" && event.data !== null ? (event.data as Record<string, unknown>) : {};
    if (data.source !== "soc-watch-content") return;
    const envelope = typeof data.message === "object" && data.message !== null ? (data.message as Record<string, unknown>) : {};
    if (envelope.type === "soc-watch.relay-ready") {
      ready = true;
      options.onStatus("connecting", "SOC Watch page relay is ready. Waiting for live data.");
      return;
    }
    if (envelope.type === "soc-watch.disconnected") {
      options.onStatus("disconnected", typeof envelope.reason === "string" ? envelope.reason : "SOC Watch Bridge disconnected.");
      return;
    }
    if (envelope.type === "soc-watch.snapshot") {
      ready = true;
      options.onStatus("connected");
      options.onSnapshot(envelope.snapshot);
      return;
    }
    if (envelope.type === "soc-watch.response" && options.onResponse) {
      options.onResponse(envelope.response as BridgeResponse);
    }
  };

  window.addEventListener("message", listener);
  window.postMessage({ source: "soc-watch-web", message: { type: "soc-watch.hello" } }, window.location.origin);

  window.setTimeout(() => {
    if (!ready && !disconnected) {
      options.onStatus(
        "unavailable",
        "SOC Watch Bridge page relay was not found. Reload the extension in chrome://extensions, then reload this SOC Watch tab."
      );
    }
  }, 15000);

  return {
    send<TParams>(action: BridgeAction, params: TParams) {
      const request: BridgeRequest<TParams> = {
        version: 1,
        requestId: crypto.randomUUID(),
        action,
        params
      };
      window.postMessage({ source: "soc-watch-web", message: request }, window.location.origin);
    },
    disconnect() {
      disconnected = true;
      window.removeEventListener("message", listener);
    }
  };
}

function sendViaWindowRelay<TParams, TData>(request: BridgeRequest<TParams>): Promise<BridgeResponse<TData>> {
  return new Promise((resolve) => {
    const timeout = window.setTimeout(() => {
      window.removeEventListener("message", listener);
      resolve({
        version: 1,
        requestId: request.requestId,
        success: false,
        error: {
          code: "BRIDGE_NOT_INSTALLED",
          message: "SOC Watch Bridge page relay did not respond."
        }
      });
    }, 15000);

    const listener = (event: MessageEvent) => {
      if (event.source !== window || event.origin !== window.location.origin) return;
      const data = typeof event.data === "object" && event.data !== null ? (event.data as Record<string, unknown>) : {};
      if (data.source !== "soc-watch-content") return;
      const envelope = typeof data.message === "object" && data.message !== null ? (data.message as Record<string, unknown>) : {};
      if (envelope.type !== "soc-watch.response") return;
      const response = envelope.response as BridgeResponse<TData> | undefined;
      if (!response || response.requestId !== request.requestId) return;
      window.clearTimeout(timeout);
      window.removeEventListener("message", listener);
      resolve(response);
    };

    window.addEventListener("message", listener);
    window.postMessage({ source: "soc-watch-web", message: request }, window.location.origin);
  });
}

function isSocWatchWebOrigin(): boolean {
  if (window.location.origin === "https://socwatch.internal") return true;
  if (window.location.protocol !== "http:") return false;
  return window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1";
}
