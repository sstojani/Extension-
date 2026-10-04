import { test, expect, vi } from "vitest";
import { saveIntegrationKeys, hasBrowserGtiKey } from "../src/integration-keys";

test("keys survive a new worker session and blank fields never clear earlier keys", async () => {
  const data: Record<string, string> = {};
  const storage = { get: vi.fn(async (keys: string | string[]) => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, data[key]]))),
    set: vi.fn(async (values: Record<string, string>) => { Object.assign(data, values); }) };
  await saveIntegrationKeys({ googleThreatIntelApiKey: " persistent-test-key ", threatFoxAuthKey: "fox", malwareBazaarAuthKey: "bazaar" }, storage as never);
  await saveIntegrationKeys({ googleThreatIntelApiKey: "", threatFoxAuthKey: "  " }, storage as never);
  expect(data).toMatchObject({ googleThreatIntelApiKey: "persistent-test-key", threatFoxAuthKey: "fox", malwareBazaarAuthKey: "bazaar" });
  expect(data.googleThreatIntelApiKeyRevision).toMatch(/^[a-f0-9-]{36}$/i);
  vi.stubGlobal("chrome", { storage: { local: storage } });
  try { expect(await hasBrowserGtiKey()).toBe(true); } finally { vi.unstubAllGlobals(); }
});

test("a storage failure or failed readback cannot report a successful save", async () => {
  await expect(saveIntegrationKeys({ googleThreatIntelApiKey: "test" }, { set: async () => {}, get: async () => ({}) } as never)).rejects.toThrow("did not persist");
  await expect(saveIntegrationKeys({ googleThreatIntelApiKey: "bad\nkey" }, {} as never)).rejects.toThrow("Invalid integration");
  await expect(saveIntegrationKeys({ googleThreatIntelApiKey: "test" }, { set: async () => { throw new Error("Storage failed"); } } as never)).rejects.toThrow("Storage failed");
});
