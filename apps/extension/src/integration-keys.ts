const fields = ["threatFoxAuthKey", "malwareBazaarAuthKey", "googleThreatIntelApiKey"] as const;
type Storage = Pick<chrome.storage.StorageArea, "get" | "set">;

export async function saveIntegrationKeys(params: Record<string, unknown>, storage: Storage = chrome.storage.local) {
  const updates: Record<string, string> = {};
  for (const field of fields) {
    if (params[field] === undefined) continue;
    if (typeof params[field] !== "string" || params[field].length > 4096 || /[\r\n\0]/.test(params[field])) throw new Error("Invalid integration key.");
    const key = params[field].trim();
    if (key) updates[field] = key;
  }
  if (updates.googleThreatIntelApiKey) updates.googleThreatIntelApiKeyRevision = crypto.randomUUID();
  if (Object.keys(updates).length) {
    await storage.set(updates);
    const saved = await storage.get(Object.keys(updates));
    if (Object.entries(updates).some(([field, key]) => saved[field] !== key)) throw new Error("Chrome did not persist the integration keys. Retry saving in this browser profile.");
  }
  return { gtiChanged: Boolean(updates.googleThreatIntelApiKey) };
}

export async function hasBrowserGtiKey() {
  const saved = await chrome.storage.local.get("googleThreatIntelApiKey");
  return typeof saved.googleThreatIntelApiKey === "string" && Boolean(saved.googleThreatIntelApiKey.trim());
}

export async function browserGtiRevision() {
  const saved = await chrome.storage.local.get("googleThreatIntelApiKeyRevision");
  const revision = saved.googleThreatIntelApiKeyRevision;
  return typeof revision === "string" && /^[a-f0-9-]{36}$/i.test(revision) ? revision : undefined;
}
