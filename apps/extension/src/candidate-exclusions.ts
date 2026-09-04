type ExclusionCandidate = {
  type?: string;
  normalized?: string;
  ip?: string;
  sourceIp?: string;
  destinationIp?: string;
  values?: string[];
  text?: string;
};

type ExclusionRule = { scope: "ip" | "domain" | "hash" | "keyword" | "value"; value: string };

export function isExcludedCandidate(candidate: ExclusionCandidate, entries: string[]): boolean {
  const rules = entries.map(parseRule).filter((rule): rule is ExclusionRule => rule !== undefined);
  const values = [candidate.normalized, candidate.ip, candidate.sourceIp, candidate.destinationIp, ...(candidate.values ?? [])]
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
    .map((value) => value.trim().toLowerCase());
  const text = `${candidate.text ?? ""} ${values.join(" ")}`.toLowerCase();

  return rules.some((rule) => {
    if (rule.scope === "keyword") return text.includes(rule.value);
    if (rule.scope === "ip") return values.some((value) => matchesIpRule(value, rule.value));
    if (rule.scope === "domain") return candidate.type === "domain" || candidate.type === "url"
      ? values.some((value) => matchesDomainRule(value, rule.value))
      : false;
    if (rule.scope === "hash") return ["md5", "sha1", "sha256"].includes(candidate.type ?? "") && values.includes(rule.value);
    return values.includes(rule.value);
  });
}

function parseRule(entry: string): ExclusionRule | undefined {
  const trimmed = entry.trim().toLowerCase();
  if (!trimmed || trimmed.startsWith("#")) return undefined;
  const separator = trimmed.indexOf(":");
  if (separator > 0) {
    const scope = trimmed.slice(0, separator);
    const value = trimmed.slice(separator + 1).trim();
    if (!value) return undefined;
    if (scope === "ip" || scope === "domain" || scope === "hash" || scope === "keyword") return { scope, value };
  }
  return ipv4OrCidrPattern.test(trimmed) ? { scope: "ip", value: trimmed } : { scope: "value", value: trimmed };
}

const ipv4OrCidrPattern = /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/;

function matchesIpRule(value: string, rule: string): boolean {
  if (!ipv4OrCidrPattern.test(value) || !ipv4OrCidrPattern.test(rule)) return value === rule;
  if (!rule.includes("/")) return value === rule;
  const [network, prefixValue] = rule.split("/");
  const prefix = Number(prefixValue);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const candidate = ipv4ToNumber(value);
  const base = ipv4ToNumber(network);
  if (candidate === undefined || base === undefined) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (candidate & mask) === (base & mask);
}

function matchesDomainRule(value: string, rule: string): boolean {
  let hostname = value;
  try {
    hostname = new URL(value).hostname;
  } catch {
    // A domain indicator is already a hostname, so no URL parsing is required.
  }
  return hostname === rule || hostname.endsWith(`.${rule}`);
}

function ipv4ToNumber(value: string): number | undefined {
  const parts = value.split("/")[0].split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return undefined;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}
