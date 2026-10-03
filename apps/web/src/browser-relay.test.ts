import { it, expect, vi } from "vitest";
import { runBrowserRelay } from "./browser-relay";
import type { BridgeAction, BridgeResponse } from "@soc-watch/protocol";

const policy = { indexPattern: "logs-*", timestampField: "@timestamp", infrastructureField: "observer.name" };
const source = { kibanaBaseUrl: "https://kibana.internal", spaceId: "default", policy };
const success = (data: unknown): BridgeResponse<unknown> => ({ version: 1, requestId: crypto.randomUUID(), success: true, data });

it("pumps one authenticated job at a time and disconnects both transports on cancellation", async () => {
  const controller = new AbortController(), posts: { path: string; body: unknown; signal?: AbortSignal | undefined }[] = [];
  const api = async <T,>(path: string, options: { body: unknown; signal?: AbortSignal }) => {
    posts.push({ path, body: options.body, signal: options.signal });
    if (path === "/relay/poll") return { job: { id: crypto.randomUUID(), operation: { kind: "openPit", indexPattern: "logs-*" } } } as T;
    if (path === "/relay/result") controller.abort();
    return {} as T;
  };
  const bridge = vi.fn(async (action: BridgeAction) => success(action === "agent.relay.connect" ? { relayId: crypto.randomUUID(), source } : { id: "pit" }));
  const progress = vi.fn();
  await runBrowserRelay({ api, bridge, policy, signal: controller.signal, onProgress: progress, pollMs: 0, retryMs: 0 });
  expect(posts.map(p => p.path)).toEqual(["/relay/connect", "/relay/poll", "/relay/result", "/relay/disconnect"]);
  expect(posts[2]?.body).toMatchObject({ success: true, data: { id: "pit" } });
  expect(posts.at(-1)?.signal).toBeUndefined();
  expect(bridge.mock.calls.map(call => call[0])).toEqual(["agent.relay.connect", "agent.relay.execute", "agent.relay.disconnect"]);
  expect(progress).toHaveBeenCalledWith(expect.objectContaining({ state: "connected" }));
});

it.each([
  { code: "KIBANA_AUTH_REQUIRED", message: "Sign in to Kibana" },
  { code: "KIBANA_UNREACHABLE", message: "Browser relay authorization expired" }
] as const)("reports extension $code failure to the server and reconnects without claiming failed reads succeeded", async error => {
  const controller = new AbortController(); let connected = 0;
  const posts: { path: string; body: unknown }[] = [], progress = vi.fn();
  const api = async <T,>(path: string, options: { body: unknown }) => {
    posts.push({ path, body: options.body });
    if (path === "/relay/connect" && ++connected === 2) controller.abort();
    if (path === "/relay/poll") return { job: { id: crypto.randomUUID(), operation: { kind: "openPit", indexPattern: "logs-*" } } } as T;
    return {} as T;
  };
  const bridge = async (action: BridgeAction): Promise<BridgeResponse<unknown>> => action === "agent.relay.execute"
    ? { version: 1, requestId: crypto.randomUUID(), success: false, error }
    : success({ relayId: crypto.randomUUID(), source });
  await runBrowserRelay({ api, bridge, policy, signal: controller.signal, onProgress: progress, retryMs: 0 });
  expect(posts.find(p => p.path === "/relay/result")?.body).toMatchObject({ success: false, error: error.message });
  expect(progress).toHaveBeenCalledWith({ state: "disconnected", message: error.message, retrying: true });
  expect(connected).toBe(2);
});

it("does not register a provider when the extension is absent or the source is invalid", async () => {
  const controller = new AbortController(), routes: string[] = [];
  const api = async <T,>(path: string) => { routes.push(path); controller.abort(); return {} as T; };
  const bridge = async (): Promise<BridgeResponse<unknown>> => ({ version: 1, requestId: crypto.randomUUID(), success: false, error: { code: "BRIDGE_NOT_INSTALLED", message: "Install Bridge" } });
  const progress = vi.fn();
  await runBrowserRelay({ api, bridge, policy, signal: controller.signal, onProgress: progress });
  expect(routes).toEqual(["/relay/disconnect"]);
  expect(progress).toHaveBeenCalledWith({ state: "disconnected", message: "Install Bridge", retrying: true });
});

it.each(["INVALID_REQUEST", "KIBANA_FORBIDDEN", "INVALID_ORIGIN"] as const)("stops retrying %s failures and cleans up instead of showing a connected button", async code => {
  const controller = new AbortController(), progress = vi.fn(), routes: string[] = [];
  const api = async <T,>(path: string) => { routes.push(path); return {} as T; };
  const bridge = vi.fn(async (): Promise<BridgeResponse<unknown>> => ({ version: 1, requestId: crypto.randomUUID(), success: false, error: { code, message: "Review log settings" } }));
  await runBrowserRelay({ api, bridge, policy, signal: controller.signal, onProgress: progress, retryMs: 0 });
  expect(bridge).toHaveBeenCalledTimes(1);
  expect(routes).toEqual(["/relay/disconnect"]);
  expect(progress).toHaveBeenLastCalledWith({ state: "disconnected", message: "Review log settings", retrying: false });
});
