import { ZodError } from "zod";
import {
  fail,
  isAllowedOrigin,
  ok,
  parseBridgeRequest,
  type BridgeRequest,
  type BridgeResponse
} from "@soc-watch/protocol";
import { DEFAULT_ALLOWED_ORIGINS } from "./config";
import {
  BridgeOperationError,
  getDataView,
  getFleetAgent,
  getFleetIncomingData,
  getFleetSummary,
  getKibanaStatus,
  listDataViews,
  listFleetAgents,
  searchIOC
} from "./kibana";

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  void handleExternalMessage(message, sender).then(sendResponse);
  return true;
});

chrome.runtime.onConnectExternal.addListener((port) => {
  void handleExternalPort(port);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  void handleInternalMessage(message).then(sendResponse);
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  void chrome.action.setBadgeText({ text: "OFF" });
  void chrome.action.setBadgeBackgroundColor({ color: "#64748b" });
});

async function handleExternalMessage(message: unknown, sender: chrome.runtime.MessageSender): Promise<BridgeResponse> {
  const started = performance.now();
  let requestId = "unknown";
  try {
    if (!isAllowedOrigin(sender.url, DEFAULT_ALLOWED_ORIGINS)) {
      return fail(requestId, "INVALID_ORIGIN", "This origin is not allowed to use SOC Watch Bridge.", elapsed(started));
    }

    const request = parseBridgeRequest(message);
    requestId = request.requestId;
    const data = await dispatch(request);
    return ok(requestId, data, elapsed(started));
  } catch (error) {
    if (error instanceof BridgeOperationError) {
      return fail(requestId, error.code, error.message, elapsed(started), error.details);
    }
    if (error instanceof ZodError) {
      return fail(requestId, "INVALID_REQUEST", "The bridge request did not match the protocol schema.", elapsed(started), error.issues);
    }
    return fail(requestId, "INTERNAL_ERROR", "SOC Watch Bridge encountered an unexpected error.", elapsed(started));
  }
}

async function handleExternalPort(port: chrome.runtime.Port): Promise<void> {
  if (!isAllowedOrigin(port.sender?.url, DEFAULT_ALLOWED_ORIGINS)) {
    port.postMessage(fail("stream", "INVALID_ORIGIN", "This origin is not allowed to use SOC Watch Bridge."));
    port.disconnect();
    return;
  }

  let closed = false;
  port.onDisconnect.addListener(() => {
    closed = true;
  });

  port.onMessage.addListener((message) => {
    void handleExternalMessage(message, port.sender ?? {}).then((response) => {
      if (!closed) port.postMessage({ type: "soc-watch.response", response });
    });
  });

  const pushSnapshot = async () => {
    if (closed) return;
    const snapshot = await collectLiveSnapshot();
    await chrome.storage.local.set({ lastConnection: snapshot });
    port.postMessage({ type: "soc-watch.snapshot", snapshot });
  };

  await pushSnapshot();
  const interval = setInterval(() => {
    if (closed) {
      clearInterval(interval);
      return;
    }
    void pushSnapshot();
  }, 15000);
}

async function handleInternalMessage(message: unknown): Promise<BridgeResponse> {
  const started = performance.now();
  let requestId = "unknown";
  try {
    if (isInternalConfigMessage(message)) {
      await chrome.storage.local.set({ kibanaBaseUrl: message.kibanaBaseUrl });
      return ok(message.requestId, { saved: true }, elapsed(started));
    }

    const request = parseBridgeRequest(message);
    requestId = request.requestId;
    const data = await dispatch(request);
    await setConnectedBadge(request.action);
    if (request.action === "fleet.summary") {
      await chrome.storage.local.set({ lastConnection: { state: "connected", updatedAt: new Date().toISOString(), fleet: data } });
    }
    return ok(requestId, data, elapsed(started));
  } catch (error) {
    await setErrorBadge();
    if (error instanceof BridgeOperationError) {
      return fail(requestId, error.code, error.message, elapsed(started), error.details);
    }
    if (error instanceof ZodError) {
      return fail(requestId, "INVALID_REQUEST", "The bridge request did not match the protocol schema.", elapsed(started), error.issues);
    }
    return fail(requestId, "INTERNAL_ERROR", "SOC Watch Bridge encountered an unexpected error.", elapsed(started));
  }
}

async function collectLiveSnapshot(): Promise<Record<string, unknown>> {
  const updatedAt = new Date().toISOString();
  try {
    const [kibana, fleet] = await Promise.all([getKibanaStatus(), getFleetSummary({})]);
    await chrome.action.setBadgeText({ text: "ON" });
    await chrome.action.setBadgeBackgroundColor({ color: "#16a34a" });
    return {
      state: "connected",
      updatedAt,
      kibana,
      fleet
    };
  } catch (error) {
    await setErrorBadge();
    if (error instanceof BridgeOperationError) {
      return {
        state: "error",
        updatedAt,
        error: {
          code: error.code,
          message: error.message,
          details: error.details
        }
      };
    }
    return {
      state: "error",
      updatedAt,
      error: {
        code: "INTERNAL_ERROR",
        message: error instanceof Error ? error.message : "Unexpected bridge error"
      }
    };
  }
}

function isInternalConfigMessage(message: unknown): message is { type: "soc-watch.saveConfig"; requestId: string; kibanaBaseUrl: string } {
  if (typeof message !== "object" || message === null) return false;
  const record = message as Record<string, unknown>;
  if (record.type !== "soc-watch.saveConfig") return false;
  if (typeof record.requestId !== "string") return false;
  if (typeof record.kibanaBaseUrl !== "string") return false;
  try {
    const url = new URL(record.kibanaBaseUrl);
    return (url.protocol === "https:" || url.protocol === "http:") && url.hostname === "10.10.254.202";
  } catch {
    return false;
  }
}

async function dispatch(request: BridgeRequest): Promise<unknown> {
  switch (request.action) {
    case "bridge.ping":
      return { extension: "SOC Watch Bridge", version: chrome.runtime.getManifest().version, status: "ok" };
    case "kibana.status":
      return getKibanaStatus();
    case "fleet.summary":
      return getFleetSummary(request.params);
    case "fleet.list":
      return listFleetAgents(request.params);
    case "fleet.get":
      return getFleetAgent(request.params);
    case "fleet.incomingData":
      return getFleetIncomingData(request.params);
    case "dataViews.list":
      return listDataViews();
    case "dataViews.get":
      return getDataView(request.params);
    case "ioc.search":
      return searchIOC(request.params);
    default:
      throw new BridgeOperationError("INVALID_REQUEST", "This action is not implemented in the bridge yet.");
  }
}

function elapsed(started: number): number {
  return Math.round(performance.now() - started);
}

async function setConnectedBadge(action: string): Promise<void> {
  if (action !== "fleet.summary" && action !== "kibana.status") return;
  await chrome.action.setBadgeText({ text: "ON" });
  await chrome.action.setBadgeBackgroundColor({ color: "#16a34a" });
}

async function setErrorBadge(): Promise<void> {
  await chrome.action.setBadgeText({ text: "ERR" });
  await chrome.action.setBadgeBackgroundColor({ color: "#dc2626" });
}
