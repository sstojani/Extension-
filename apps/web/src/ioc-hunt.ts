import type { BridgeResponse, IocHuntCoverage, IocHuntGroup } from "@soc-watch/protocol";

const CURSOR_KEY = "socWatchIocHuntCursors";
export type HuntScope = { indexPattern: string; timestampField: string; from: string; to: string };
export type HuntFailure = { message: string; recovery: "fresh_scan" | "retry" | "alert_delivery"; nextBatchOffset?: number };

export function huntScopeKey(scope: HuntScope): string {
  return JSON.stringify([scope.indexPattern, scope.timestampField, scope.from, scope.to]);
}

export function loadIocHuntOffset(scope: HuntScope, group: IocHuntGroup = "all"): number {
  try {
    const stored = JSON.parse(localStorage.getItem(CURSOR_KEY) ?? "null");
    const offset = stored?.offsets?.[group] ?? (group === "all" ? stored?.offset : 0);
    return stored?.scope === huntScopeKey(scope) && Number.isSafeInteger(offset) && offset >= 0 && offset <= 1_000_000
      ? offset : 0;
  } catch { return 0; }
}

export function saveIocHuntOffset(scope: HuntScope, offset: number, group: IocHuntGroup = "all"): void {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1_000_000) return;
  try {
    const stored = readCampaign(scope);
    localStorage.setItem(CURSOR_KEY, JSON.stringify({ ...stored, scope: huntScopeKey(scope), offsets: { ...stored?.offsets, [group]: offset } }));
  } catch { /* The extension still validates its authoritative saved progress. */ }
}

function readCampaign(scope: HuntScope): { campaignId?: string; offsets?: Partial<Record<IocHuntGroup, number>> } | null {
  try {
    const stored = JSON.parse(localStorage.getItem(CURSOR_KEY) ?? "null");
    return stored?.scope === huntScopeKey(scope) ? stored : null;
  } catch { return null; }
}

export function loadIocHuntCampaignId(scope: HuntScope): string | undefined {
  const id = readCampaign(scope)?.campaignId;
  return typeof id === "string" && /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(id) ? id : undefined;
}

export function saveIocHuntCampaign(scope: HuntScope, campaignId: string, coverage: IocHuntCoverage): void {
  try {
    localStorage.setItem(CURSOR_KEY, JSON.stringify({ scope: huntScopeKey(scope), campaignId,
      offsets: Object.fromEntries(Object.entries(coverage).map(([group, value]) => [group, value.nextBatchOffset])) }));
  } catch { /* The extension remains authoritative. */ }
}

export function resetIocHuntCampaign(scope: HuntScope): void {
  try { localStorage.setItem(CURSOR_KEY, JSON.stringify({ scope: huntScopeKey(scope), offsets: {} })); } catch { /* Best effort. */ }
}

export function huntFailure(error: Extract<BridgeResponse, { success: false }>["error"]): HuntFailure {
  const details = error.details && typeof error.details === "object" ? error.details as Record<string, unknown> : {};
  return {
    message: error.message,
    recovery: details.huntRecovery === "fresh_scan" ? "fresh_scan" : "retry",
    ...(Number.isSafeInteger(details.nextBatchOffset) && Number(details.nextBatchOffset) >= 0 && Number(details.nextBatchOffset) <= 1_000_000
      ? { nextBatchOffset: Number(details.nextBatchOffset) } : {})
  };
}
