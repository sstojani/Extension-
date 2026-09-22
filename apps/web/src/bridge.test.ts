import { afterEach, describe, expect, it, vi } from "vitest";
import { detectBridgeExtension, getExtensionId } from "./bridge";

afterEach(() => vi.unstubAllGlobals());

function mockServerPage(replyToHello: boolean) {
  const origin = "https://laptop-1.tail029be8.ts.net";
  const listeners = new Set<(event: MessageEvent) => void>();
  const page = {
    location: { hostname: "laptop-1.tail029be8.ts.net", origin },
    addEventListener(_type: string, listener: (event: MessageEvent) => void) { listeners.add(listener); },
    removeEventListener(_type: string, listener: (event: MessageEvent) => void) { listeners.delete(listener); },
    postMessage() {
      if (!replyToHello) return;
      queueMicrotask(() => {
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
                extensionVersion: "0.12.4"
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
  it("uses the relay-reported extension ID instead of a local development ID", async () => {
    mockServerPage(true);
    expect(getExtensionId()).toBeUndefined();
    expect(await detectBridgeExtension(100)).toMatchObject({
      installed: true,
      extensionId: "abcdefghijklmnopabcdefghijklmnop",
      extensionVersion: "0.12.4",
      transport: "page-relay"
    });
  });

  it("keeps the installation gate locked when no extension responds", async () => {
    mockServerPage(false);
    expect(await detectBridgeExtension(10)).toMatchObject({ installed: false });
  });
});
