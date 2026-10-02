import { classifyIOC, type ClassifiedIOC } from "@soc-watch/ioc";

export interface ThreatIntelProviderStatus {
  name: string;
  status: "healthy" | "skipped" | "error";
  collected: number;
  byType: Record<string, number>;
  message?: string;
}

export interface ThreatIntelIOC extends ClassifiedIOC {
  sources: string[];
  sourceCount: number;
  riskScore: number;
  riskLevel: "critical" | "high" | "medium" | "low";
  riskReasons: string[];
  malware?: string | undefined;
  threatType?: string | undefined;
  confidence?: number | undefined;
  firstSeen?: string | undefined;
  reference?: string | undefined;
}

export interface RawIntelIOC {
  value: string;
  source: string;
  malware?: string | undefined;
  threatType?: string | undefined;
  confidence?: number | undefined;
  firstSeen?: string | undefined;
  reference?: string | undefined;
}

type Collector = () => Promise<RawIntelIOC[]>;

const THREAT_FEED_TIMEOUT_MS = 15_000;
const THREAT_FEED_ATTEMPTS = 2;

export interface ThreatIntelSnapshot {
  iocs: ThreatIntelIOC[];
  providers: ThreatIntelProviderStatus[];
  totalAvailable: number;
  excluded: number;
}

export async function collectDailyThreatIntel(
  maxIocs: number,
  batchOffset = 0,
  include: (ioc: ThreatIntelIOC) => boolean = () => true
): Promise<{
  iocs: ThreatIntelIOC[];
  providers: ThreatIntelProviderStatus[];
  totalAvailable: number;
  batchOffset: number;
  batchSize: number;
  hasMore: boolean;
}> {
  const snapshot = await collectThreatIntelSnapshot(include);
  const iocs = snapshot.iocs.slice(batchOffset, batchOffset + maxIocs);
  return {
    iocs,
    providers: snapshot.providers,
    totalAvailable: snapshot.totalAvailable,
    batchOffset,
    batchSize: iocs.length,
    hasMore: batchOffset + iocs.length < snapshot.totalAvailable
  };
}

export async function collectThreatIntelSnapshot(
  include: (ioc: ThreatIntelIOC) => boolean = () => true
): Promise<ThreatIntelSnapshot> {
  const keys = await readProviderKeys();
  const collectors: Array<{ name: string; collect: Collector }> = [
    { name: "ThreatFox", collect: () => collectThreatFox(keys.threatFoxAuthKey) },
    { name: "MalwareBazaar", collect: () => collectMalwareBazaar(keys.malwareBazaarAuthKey) },
    { name: "URLhaus", collect: collectUrlhausRecent },
    { name: "Feodo Tracker", collect: collectFeodoTracker },
    { name: "OpenPhish", collect: collectOpenPhish },
    { name: "ThreatView IP", collect: () => collectLineFeed("ThreatView IP", "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt") },
    { name: "ThreatView Domain", collect: () => collectLineFeed("ThreatView Domain", "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt") },
    { name: "ThreatView Hash", collect: () => collectLineFeed("ThreatView Hash", "https://threatview.io/Downloads/SHA-HASH-FEED.txt") }
  ];

  const outcomes = await Promise.all(collectors.map(async (collector) => {
    try {
      const collected = await collector.collect();
      return {
        collected,
        provider: { name: collector.name, status: "healthy", collected: collected.length, byType: countByType(collected) } satisfies ThreatIntelProviderStatus
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Provider failed.";
      return {
        collected: [] as RawIntelIOC[],
        provider: {
          name: collector.name,
          status: message.includes("API key") ? "skipped" : "error",
          collected: 0,
          byType: {},
          message
        } satisfies ThreatIntelProviderStatus
      };
    }
  }));

  const records = outcomes.flatMap((outcome) => outcome.collected);
  const providers = outcomes.map((outcome) => outcome.provider);

  const deduped = dedupeIntel(records);
  const iocs = deduped.filter(include);
  return {
    iocs,
    providers,
    totalAvailable: iocs.length,
    excluded: deduped.length - iocs.length
  };
}

function countByType(records: RawIntelIOC[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const record of records) {
    const type = classifyIOC(record.value).type;
    if (type === "unknown") continue;
    counts[type] = (counts[type] ?? 0) + 1;
  }
  return counts;
}

async function collectThreatFox(authKey: string | undefined): Promise<RawIntelIOC[]> {
  if (!authKey) throw new Error("ThreatFox API key is not configured.");
  const response = await fetchThreatFeed("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "Auth-Key": authKey
    },
    body: JSON.stringify({ query: "get_iocs", days: 1 })
  });
  if (!response.ok) throw new Error(`ThreatFox returned HTTP ${response.status}.`);
  const body = await response.json();
  const data = Array.isArray(body?.data) ? body.data : [];
  return data.flatMap((item: unknown) => {
    const record = asRecord(item);
    return normalizeIpPort(String(record.ioc ?? "")).map((value) => ({
      value,
      source: "ThreatFox",
      malware: readString(record.malware_printable) ?? readString(record.malware),
      threatType: readString(record.threat_type),
      confidence: readNumber(record.confidence_level),
      firstSeen: readString(record.first_seen),
      reference: readString(record.reference)
    }));
  });
}

async function collectMalwareBazaar(authKey: string | undefined): Promise<RawIntelIOC[]> {
  if (!authKey) throw new Error("MalwareBazaar API key is not configured.");
  const response = await fetchThreatFeed("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "Auth-Key": authKey
    },
    body: new URLSearchParams({ query: "get_recent", selector: "100" }).toString()
  });
  if (!response.ok) throw new Error(`MalwareBazaar returned HTTP ${response.status}.`);
  const body = await response.json();
  const data = Array.isArray(body?.data) ? body.data : [];
  return data.flatMap((item: unknown) => {
    const record = asRecord(item);
    const hashes = [record.sha256_hash, record.sha1_hash, record.md5_hash].filter((value): value is string => typeof value === "string");
    return hashes.map((value) => ({
      value,
      source: "MalwareBazaar",
      malware: readString(record.signature),
      threatType: "malware_hash",
      firstSeen: readString(record.first_seen),
      reference: readString(record.file_name)
    }));
  });
}

async function collectUrlhausRecent(): Promise<RawIntelIOC[]> {
  const text = await fetchText("https://urlhaus.abuse.ch/downloads/csv_recent/");
  const rows = parseCsvRows(text);
  return rows.flatMap((columns) => {
    const dateAdded = columns[1];
    const url = columns[2];
    if (!url) return [];
    const records: RawIntelIOC[] = [
      { value: url, source: "URLhaus", threatType: columns[4], firstSeen: dateAdded, reference: columns[6] }
    ];
    try {
      records.push({ value: new URL(url).hostname, source: "URLhaus", threatType: columns[4], firstSeen: dateAdded, reference: columns[6] });
    } catch {
      // Keep the URL IOC even if the host extraction fails.
    }
    return records;
  });
}

async function collectFeodoTracker(): Promise<RawIntelIOC[]> {
  const text = await fetchText("https://feodotracker.abuse.ch/downloads/ipblocklist.csv");
  return parseCsvRows(text).flatMap((columns) => normalizeIpPort(columns[1] ?? "").map((value) => ({
    value,
    source: "Feodo Tracker",
    malware: columns[4],
    threatType: "botnet_c2",
    firstSeen: columns[0]
  })));
}

async function collectOpenPhish(): Promise<RawIntelIOC[]> {
  const text = await fetchText("https://openphish.com/feed.txt");
  return text.split(/\r?\n/).flatMap((line) => {
    const value = line.trim();
    if (!value || value.startsWith("#")) return [];
    const records: RawIntelIOC[] = [{ value, source: "OpenPhish", threatType: "phishing_url" }];
    try {
      records.push({ value: new URL(value).hostname, source: "OpenPhish", threatType: "phishing_domain" });
    } catch {
      // Keep the URL as provided.
    }
    return records;
  });
}

async function collectLineFeed(source: string, url: string): Promise<RawIntelIOC[]> {
  const text = await fetchText(url);
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .flatMap((value) => normalizeIpPort(value).map((normalizedValue) => ({ value: normalizedValue, source, threatType: "threat_feed" })));
}

async function fetchText(url: string): Promise<string> {
  const response = await fetchThreatFeed(url);
  if (!response.ok) throw new Error(`${new URL(url).hostname} returned HTTP ${response.status}.`);
  return response.text();
}

async function fetchThreatFeed(url: string, init: RequestInit = {}): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= THREAT_FEED_ATTEMPTS; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), THREAT_FEED_TIMEOUT_MS);
    try {
      const response = await fetch(url, { ...init, signal: controller.signal });
      const transient = response.status === 429 || response.status >= 500;
      if (!transient || attempt === THREAT_FEED_ATTEMPTS) return response;
      lastError = new Error(`${new URL(url).hostname} returned HTTP ${response.status}.`);
    } catch (error) {
      lastError = controller.signal.aborted
        ? new Error(`${new URL(url).hostname} timed out after ${THREAT_FEED_TIMEOUT_MS / 1000} seconds.`)
        : error;
      if (attempt === THREAT_FEED_ATTEMPTS) throw lastError;
    } finally {
      clearTimeout(timer);
    }
    await waitForRetry(attempt * 500);
  }
  throw lastError instanceof Error ? lastError : new Error(`${new URL(url).hostname} request failed.`);
}

function waitForRetry(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function prioritizeThreatIntel(records: RawIntelIOC[], now = Date.now()): ThreatIntelIOC[] {
  const byKey = new Map<string, Omit<ThreatIntelIOC, "riskScore" | "riskLevel" | "riskReasons">>();
  for (const record of records) {
    const classified = classifyIOC(record.value);
    if (classified.type === "unknown") continue;
    const key = `${classified.type}:${classified.normalized}`;
    const existing = byKey.get(key);
    if (existing) {
      if (!existing.sources.includes(record.source)) existing.sources.push(record.source);
      existing.sourceCount = existing.sources.length;
      existing.confidence = Math.max(existing.confidence ?? 0, record.confidence ?? 0) || existing.confidence;
      if (threatContextWeight(record.threatType, record.malware) > threatContextWeight(existing.threatType, existing.malware)) {
        existing.malware = record.malware ?? existing.malware;
        existing.threatType = record.threatType ?? existing.threatType;
        existing.reference = record.reference ?? existing.reference;
      } else {
        existing.malware = existing.malware ?? record.malware;
        existing.threatType = existing.threatType ?? record.threatType;
        existing.reference = existing.reference ?? record.reference;
      }
      existing.firstSeen = earliest(existing.firstSeen, record.firstSeen);
      continue;
    }
    byKey.set(key, {
      ...classified,
      sources: [record.source],
      sourceCount: 1,
      malware: record.malware,
      threatType: record.threatType,
      confidence: record.confidence,
      firstSeen: record.firstSeen,
      reference: record.reference
    });
  }
  return [...byKey.values()]
    .map((ioc) => scoreThreatIntel(ioc, now))
    .sort((left, right) => right.riskScore - left.riskScore
      || right.sourceCount - left.sourceCount
      || compareSeenAt(right.firstSeen, left.firstSeen)
      || left.normalized.localeCompare(right.normalized));
}

function dedupeIntel(records: RawIntelIOC[]): ThreatIntelIOC[] {
  return prioritizeThreatIntel(records);
}

function scoreThreatIntel(
  ioc: Omit<ThreatIntelIOC, "riskScore" | "riskLevel" | "riskReasons">,
  now: number
): ThreatIntelIOC {
  const reasons: string[] = [];
  let score = 10;
  const sourceStrength = Math.max(...ioc.sources.map(providerRiskWeight), 0);
  score += sourceStrength;
  if (sourceStrength > 0) reasons.push(`High-confidence source: ${ioc.sources.find((source) => providerRiskWeight(source) === sourceStrength)}`);

  if (ioc.sourceCount >= 3) {
    score += 25;
    reasons.push(`Corroborated by ${ioc.sourceCount} feeds`);
  } else if (ioc.sourceCount === 2) {
    score += 15;
    reasons.push("Corroborated by two feeds");
  }

  if (typeof ioc.confidence === "number") {
    const confidenceBoost = Math.round(Math.max(0, Math.min(100, ioc.confidence)) * 0.25);
    score += confidenceBoost;
    if (ioc.confidence >= 70) reasons.push(`Vendor confidence ${ioc.confidence}%`);
  }

  const context = `${ioc.threatType ?? ""} ${ioc.malware ?? ""}`.toLowerCase();
  if (/command.?and.?control|\bc2\b|botnet/.test(context)) {
    score += 22;
    reasons.push("Command-and-control or botnet context");
  } else if (/ransom|trojan|backdoor|malware|exploit/.test(context)) {
    score += 18;
    reasons.push("Malware or exploit context");
  } else if (/phish|credential/.test(context)) {
    score += 14;
    reasons.push("Phishing or credential-theft context");
  }

  const ageMs = parsedTimestamp(ioc.firstSeen);
  if (ageMs !== undefined) {
    const ageDays = Math.max(0, (now - ageMs) / 86_400_000);
    if (ageDays <= 2) {
      score += 15;
      reasons.push("First reported within 48 hours");
    } else if (ageDays <= 7) {
      score += 8;
      reasons.push("First reported within seven days");
    } else if (ageDays > 180) {
      score -= 8;
      reasons.push("Older indicator; verify that it is still active");
    }
  }

  if (["md5", "sha1", "sha256"].includes(ioc.type)) score += 6;
  else if (ioc.type === "ip") score += 5;
  else if (ioc.type === "domain") score += 4;

  const riskScore = Math.max(0, Math.min(100, Math.round(score)));
  return {
    ...ioc,
    riskScore,
    riskLevel: riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 35 ? "medium" : "low",
    riskReasons: reasons.slice(0, 5)
  };
}

function providerRiskWeight(source: string): number {
  if (source === "Feodo Tracker") return 28;
  if (source === "ThreatFox" || source === "MalwareBazaar") return 25;
  if (source.startsWith("ThreatView")) return 22;
  if (source === "URLhaus") return 20;
  if (source === "OpenPhish") return 18;
  return 8;
}

function threatContextWeight(threatType: string | undefined, malware: string | undefined): number {
  const context = `${threatType ?? ""} ${malware ?? ""}`.toLowerCase();
  if (/command.?and.?control|\bc2\b|botnet/.test(context)) return 4;
  if (/ransom|trojan|backdoor|malware|exploit/.test(context)) return 3;
  if (/phish|credential/.test(context)) return 2;
  return context.trim() ? 1 : 0;
}

function parsedTimestamp(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value.replace(/ UTC$/i, "Z"));
  return Number.isFinite(parsed) ? parsed : undefined;
}

function compareSeenAt(left: string | undefined, right: string | undefined): number {
  return (parsedTimestamp(left) ?? 0) - (parsedTimestamp(right) ?? 0);
}

function normalizeIpPort(value: string): string[] {
  const trimmed = value.trim();
  const ipPort = trimmed.match(/^((?:\d{1,3}\.){3}\d{1,3}):\d{1,5}$/);
  return ipPort ? [ipPort[1] ?? trimmed] : [trimmed];
}

function parseCsvRows(text: string): string[][] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map(parseCsvLine);
}

function parseCsvLine(line: string): string[] {
  const columns: string[] = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"' && line[index + 1] === '"') {
      current += '"';
      index += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      columns.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  columns.push(current);
  return columns;
}

function earliest(left: string | undefined, right: string | undefined): string | undefined {
  if (!left) return right;
  if (!right) return left;
  return left < right ? left : right;
}

async function readProviderKeys(): Promise<{ threatFoxAuthKey?: string; malwareBazaarAuthKey?: string }> {
  const stored = await chrome.storage.local.get(["threatFoxAuthKey", "malwareBazaarAuthKey"]);
  const threatFoxAuthKey = readStoredKey(stored.threatFoxAuthKey);
  const malwareBazaarAuthKey = readStoredKey(stored.malwareBazaarAuthKey);
  return {
    ...(threatFoxAuthKey ? { threatFoxAuthKey } : {}),
    ...(malwareBazaarAuthKey ? { malwareBazaarAuthKey } : {})
  };
}

function readStoredKey(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function readNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}
