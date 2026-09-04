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
  malware?: string;
  threatType?: string;
  confidence?: number;
  firstSeen?: string;
  reference?: string;
}

interface RawIntelIOC {
  value: string;
  source: string;
  malware?: string;
  threatType?: string;
  confidence?: number;
  firstSeen?: string;
  reference?: string;
}

type Collector = () => Promise<RawIntelIOC[]>;

export async function collectDailyThreatIntel(maxIocs: number): Promise<{
  iocs: ThreatIntelIOC[];
  providers: ThreatIntelProviderStatus[];
}> {
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

  const records: RawIntelIOC[] = [];
  const providers: ThreatIntelProviderStatus[] = [];

  for (const collector of collectors) {
    try {
      const collected = await collector.collect();
      records.push(...collected);
      providers.push({ name: collector.name, status: "healthy", collected: collected.length, byType: countByType(collected) });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Provider failed.";
      providers.push({
        name: collector.name,
        status: message.includes("API key") ? "skipped" : "error",
        collected: 0,
        byType: {},
        message
      });
    }
  }

  return {
    iocs: dedupeIntel(records).slice(0, maxIocs),
    providers
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
  const response = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
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
  const response = await fetch("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(authKey ? { "Auth-Key": authKey } : {})
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
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${new URL(url).hostname} returned HTTP ${response.status}.`);
  return response.text();
}

function dedupeIntel(records: RawIntelIOC[]): ThreatIntelIOC[] {
  const byKey = new Map<string, ThreatIntelIOC>();
  for (const record of records) {
    const classified = classifyIOC(record.value);
    if (classified.type === "unknown") continue;
    const key = `${classified.type}:${classified.normalized}`;
    const existing = byKey.get(key);
    if (existing) {
      if (!existing.sources.includes(record.source)) existing.sources.push(record.source);
      existing.sourceCount = existing.sources.length;
      existing.confidence = Math.max(existing.confidence ?? 0, record.confidence ?? 0) || existing.confidence;
      existing.malware = existing.malware ?? record.malware;
      existing.threatType = existing.threatType ?? record.threatType;
      existing.firstSeen = earliest(existing.firstSeen, record.firstSeen);
      existing.reference = existing.reference ?? record.reference;
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
  return [...byKey.values()].sort((left, right) => right.sourceCount - left.sourceCount || left.normalized.localeCompare(right.normalized));
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
  return {
    threatFoxAuthKey: readStoredKey(stored.threatFoxAuthKey),
    malwareBazaarAuthKey: readStoredKey(stored.malwareBazaarAuthKey)
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
