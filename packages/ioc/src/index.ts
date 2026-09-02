export type IOCType = "ip" | "domain" | "url" | "md5" | "sha1" | "sha256" | "unknown";

export interface ClassifiedIOC {
  original: string;
  normalized: string;
  type: IOCType;
}

const ipv4Pattern =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const domainPattern = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;
const md5Pattern = /^[a-f0-9]{32}$/i;
const sha1Pattern = /^[a-f0-9]{40}$/i;
const sha256Pattern = /^[a-f0-9]{64}$/i;

export function refangIOC(value: string): string {
  return value
    .trim()
    .replace(/\[\.\]|\(\.\)|\{\.}/gi, ".")
    .replace(/\bhxxps:\/\//i, "https://")
    .replace(/\bhxxp:\/\//i, "http://")
    .replace(/\[:\]/g, ":")
    .replace(/\s+/g, "");
}

export function classifyIOC(value: string): ClassifiedIOC {
  const normalized = normalizeIOC(value);
  if (ipv4Pattern.test(normalized)) return { original: value, normalized, type: "ip" };
  if (md5Pattern.test(normalized)) return { original: value, normalized: normalized.toLowerCase(), type: "md5" };
  if (sha1Pattern.test(normalized)) return { original: value, normalized: normalized.toLowerCase(), type: "sha1" };
  if (sha256Pattern.test(normalized)) return { original: value, normalized: normalized.toLowerCase(), type: "sha256" };
  if (isUrl(normalized)) return { original: value, normalized, type: "url" };
  if (domainPattern.test(normalized)) return { original: value, normalized: normalized.toLowerCase(), type: "domain" };
  return { original: value, normalized, type: "unknown" };
}

export function normalizeIOC(value: string): string {
  const refanged = refangIOC(value);
  if (isUrl(refanged)) {
    const url = new URL(refanged);
    url.hostname = url.hostname.toLowerCase();
    return url.toString();
  }
  return refanged.replace(/\.$/, "").toLowerCase();
}

export function parseBulkIOCs(input: string, limit = 500): ClassifiedIOC[] {
  const seen = new Set<string>();
  const values = input
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);

  if (values.length > limit) {
    throw new Error(`Bulk IOC list exceeds limit of ${limit}`);
  }

  return values
    .map(classifyIOC)
    .filter((ioc) => {
      const key = `${ioc.type}:${ioc.normalized}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function isUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}
