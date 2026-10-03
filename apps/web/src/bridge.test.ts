import { afterEach, describe, expect, it, vi } from "vitest";
import { detectBridgeExtension, getExtensionId, sendBridgeMessage } from "./bridge";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });

function mockServerPage(versions: string[]) {
  const origin = "https://laptop-1.tail029be8.ts.net";
  const listeners = new Set<(event: MessageEvent) => void>();
  const page = {
    location: { hostname: "laptop-1.tail029be8.ts.net", origin },
    addEventListener(_type: string, listener: (event: MessageEvent) => void) { listeners.add(listener); },
    removeEventListener(_type: string, listener: (event: MessageEvent) => void) { listeners.delete(listener); },
    postMessage() {
      for (const version of versions) queueMicrotask(() => {
        for (const listener of listeners) {
          listener({
            source: page,
            origin,
            data: {
              source: "soc-watch-content",
              message: {
                type: "soc-watch.relay-ready",
                extensionId: "abcdefghijklmnopabcdefghijklmnop",
                extensionName: "SOC Watch Bridge",
                extensionVersion: version
              }
            }
          } as unknown as MessageEvent);
        }
      });
    },
    setTimeout,
    clearTimeout
  };
  vi.stubGlobal("window", page);
  vi.stubGlobal("localStorage", { getItem: () => null });
}

describe("server-hosted bridge discovery", () => {
  it.each(["page", "native"])("reports a stalled agent job as a transport failure, not a missing extension (%s)", async transport => {
    vi.useFakeTimers(); mockServerPage([]);
    vi.stubGlobal("chrome", transport === "native" ? { runtime: { sendMessage: vi.fn() } } : undefined);
    if (transport === "native") vi.stubGlobal("localStorage", { getItem: () => "abcdefghijklmnopabcdefghijklmnop" });
    const response = sendBridgeMessage("agent.relay.execute", {});
    await vi.advanceTimersByTimeAsync(50000);
    expect(await response).toMatchObject({ success: false, error: { code: "KIBANA_UNREACHABLE" } });
  });
  it("uses the relay-reported extension ID instead of a local development ID", async () => {
    mockServerPage(["0.12.5", "0.13.0"]);
    expect(getExtensionId()).toBeUndefined();
    expect(await detectBridgeExtension(100, "0.13.0")).toMatchObject({
      installed: true,
      extensionId: "abcdefghijklmnopabcdefghijklmnop",
      extensionVersion: "0.13.0",
      transport: "page-relay"
    });
  });

  it("keeps the installation gate locked when no extension responds", async () => {
    mockServerPage([]);
    expect(await detectBridgeExtension(10, "0.13.0")).toMatchObject({ installed: false });
  });

  it("identifies an outdated bridge instead of accepting it", async () => {
    mockServerPage(["0.12.5"]);
    expect(await detectBridgeExtension(10, "0.13.0")).toMatchObject({
      installed: false,
      reason: expect.stringContaining("Bridge v0.12.5 is installed")
    });
  });
});
