import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

const DEFAULTS = {
  timezone: "Europe/Tirane",
  baselineDays: 7,
  retentionDays: 30,
  scanMinAttempts: 30,
  scanMinTargets: 5,
  scanMinPorts: 10,
  authFailures: 10,
  beaconMinConnections: 8,
  beaconMaxCv: 0.15,
  exfilMinBytes: 52_428_800,
  exfilRatio: 5,
  riskyPorts: [22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017]
};
const WINDOW_MS = 15 * 60_000;
const CORRELATION_MS = 60 * 60_000;
const CORRELATION_LIMIT = 100_000;
const BASELINE_EVENT_LIMIT = 100_000;
const BASELINE_ENTITY_LIMIT = 5_000;
const scopeCache = new Map();
const dispositionCache = new WeakMap();
const dnsCache = new WeakMap();
const HASH_LENGTHS = { md5: 32, sha1: 40, sha256: 64, sha384: 96, sha512: 128 };
const VERDICTS = new Set(["malicious", "suspicious", "undetected", "benign", "unknown"]);
const BLOCKED_ACTIONS = new Set([
  "deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected",
  "connection_denied", "connection_blocked", "firewall_denied", "prevented", "quarantined"
]);
const ALLOWED_ACTIONS = new Set([
  "allow", "allowed", "accept", "accepted", "connection_allowed", "connection_accepted", "connected"
]);
const EXECUTION_ACTIONS = new Set(["start", "process_start", "process_started", "exec", "execution", "executed"]);
const DNS_RESOLVERS = new Set([
  "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
  "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
  "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
  "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9"
]);

/** Exact ECS paths, including flattened keys and arrays of nested objects. */
function fieldValues(record, path) {
  const parts = path.split(".");
  function visit(value, offset) {
    if (Array.isArray(value)) return value.flatMap((item) => visit(item, offset));
    if (offset === parts.length) return value === null || value === undefined ? [] : [value];
    if (!isRecord(value)) return [];
    for (let end = parts.length; end > offset; end -= 1) {
      const key = parts.slice(offset, end).join(".");
      if (Object.hasOwn(value, key)) return visit(value[key], end);
    }
    return [];
  }
  return visit(record, 0);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function strings(record, path) {
  return fieldValues(record, path).filter((value) => typeof value === "string" && value.trim()).map((value) => value.trim());
}

function firstString(record, ...paths) {
  for (const path of paths) {
    const value = strings(record, path)[0];
    if (value) return value;
  }
  return null;
}

function firstNumber(record, path, maximum = Number.MAX_SAFE_INTEGER) {
  for (const value of fieldValues(record, path)) {
    if (typeof value !== "number" && !(typeof value === "string" && /^\d+(\.\d+)?$/.test(value))) continue;
    const number = Number(value);
    if (Number.isFinite(number) && number >= 0 && number <= maximum) return number;
  }
  return null;
}

function timestamp(value) {
  if (typeof value === "string") {
    if (/^-?\d{10,16}$/.test(value)) value = Number(value);
    else {
      if (!/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2}))?$/.test(value)) return null;
      const day = value.slice(0, 10);
      const midnight = new Date(`${day}T00:00:00.000Z`);
      if (!Number.isFinite(midnight.getTime()) || midnight.toISOString().slice(0, 10) !== day) return null;
    }
  } else if (typeof value !== "number" && !(value instanceof Date)) {
    return null;
  }
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function ip(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  const family = isIP(trimmed);
  if (!family) return null;
  return family === 6 ? new URL(`http://[${trimmed}]/`).hostname.slice(1, -1) : trimmed;
}

function domain(value) {
  if (typeof value !== "string") return null;
  const ascii = domainToASCII(value.trim().replace(/\.$/, "").toLowerCase());
  if (!ascii || ascii.length > 253 || isIP(ascii)) return null;
  return ascii.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ? ascii : null;
}

function unique(values) {
  return [...new Set(values.filter((value) => value !== null && value !== undefined))];
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
}

function digest(value) {
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

function hashes(record, prefix) {
  return unique(Object.entries(HASH_LENGTHS).flatMap(([algorithm, length]) =>
    strings(record, `${prefix}.hash.${algorithm}`).map((value) => value.toLowerCase())
      .filter((value) => new RegExp(`^[a-f0-9]{${length}}$`).test(value))));
}

/** Returns null for an event without a valid timestamp. No message/name guessing. */
export const INDICATOR_FIELDS = {
  ip: ["source.ip", "destination.ip", "client.ip", "server.ip"],
  domain: ["source.domain", "destination.domain", "dns.question.name", "url.domain"],
  hash: ["file.hash.md5", "file.hash.sha1", "file.hash.sha256", "process.hash.md5", "process.hash.sha1", "process.hash.sha256"],
  identity: ["user.name", "user.email", "user.id"]
};

export function normalizeEvent(hit, { timestampField = "@timestamp", infrastructureField = "observer.name" } = {}) {
  if (!isRecord(hit)) return null;
  const source = isRecord(hit._source) ? hit._source : hit;
  const time = fieldValues(source, timestampField).map(timestamp).find(Boolean);
  if (!time) return null;
  const user = firstString(source, "user.name", "user.email", "user.id");
  const userDomain = firstString(source, "user.domain");
  const identity = user && userDomain && !/[\\@]/.test(user) ? `${userDomain}\\${user}` : user;
  const sourceDomain = strings(source, "source.domain").map(domain).find(Boolean) ?? null;
  const destinationDomain = strings(source, "destination.domain").map(domain).find(Boolean) ?? null;
  const port = firstNumber(source, "destination.port", 65535);
  return {
    id: (typeof hit._id === "string" && hit._id) || firstString(source, "event.id") || `synthetic:${digest(source)}`,
    index: typeof hit._index === "string" ? hit._index : null,
    timestamp: time,
    sourceIp: strings(source, "source.ip").map(ip).find(Boolean) ?? null,
    sourceCountry: firstString(source, "source.geo.country_name", "source.geo.country_iso_code"),
    destinationIp: strings(source, "destination.ip").map(ip).find(Boolean) ?? null,
    ips: unique(INDICATOR_FIELDS.ip.flatMap(path => strings(source, path).map(ip))),
    sourceDomain,
    destinationDomain,
    domains: unique([sourceDomain, destinationDomain, ...["source.domain", "destination.domain", "dns.question.name", "url.domain"]
      .flatMap((path) => strings(source, path).map(domain))]),
    hashes: unique([...hashes(source, "file"), ...hashes(source, "process")]),
    identity,
    host: firstString(source, "host.name", "host.id"),
    infrastructure: firstString(source, infrastructureField),
    port: port !== null && Number.isInteger(port) && port > 0 ? port : null,
    action: firstString(source, "event.action"),
    outcome: firstString(source, "event.outcome")?.toLowerCase() ?? null,
    category: unique(strings(source, "event.category").map((value) => value.toLowerCase())),
    bytesOut: firstNumber(source, "source.bytes"),
    bytesIn: firstNumber(source, "destination.bytes"),
    process: firstString(source, "process.name", "process.executable"),
    processEntityId: firstString(source, "process.entity_id"),
    message: firstString(source, "message"),
    rawFields: source
  };
}

export function eventIndicators(event) {
  return [["ip", unique([event.sourceIp, event.destinationIp, ...(event.ips || [])])], ["domain", event.domains || []], ["hash", event.hashes || []]];
}

function ipNumber(value) {
  const normalized = ip(value);
  if (!normalized) return null;
  if (isIP(normalized) === 4) return { bits: 32, value: normalized.split(".").reduce((number, part) => (number << 8n) + BigInt(part), 0n) };
  const halves = normalized.split("::").map((half) => half ? half.split(":") : []);
  const groups = halves.length === 1 ? halves[0] : [...halves[0], ...Array(8 - halves[0].length - halves[1].length).fill("0"), ...halves[1]];
  return { bits: 128, value: groups.reduce((number, group) => (number << 16n) + BigInt(`0x${group}`), 0n) };
}

function inCidr(value, cidr) {
  if (typeof cidr !== "string") return false;
  const [base, prefix, extra] = cidr.split("/");
  const address = ipNumber(value);
  const network = ipNumber(base);
  if (extra !== undefined || !address || !network || address.bits !== network.bits || !/^\d+$/.test(prefix ?? "")) return false;
  const length = Number(prefix);
  if (length < 0 || length > address.bits) return false;
  const shift = BigInt(address.bits - length);
  return address.value >> shift === network.value >> shift;
}

function computeScope(value) {
  const address = ipNumber(value);
  if (!address) return "unknown";
  if (address.bits === 128) {
    if (address.value >> 32n === 0xffffn) {
      const number = address.value & 0xffffffffn;
      return addressScope([24n, 16n, 8n, 0n].map((shift) => Number(number >> shift & 255n)).join("."));
    }
    if (inCidr(value, "fc00::/7")) return "private";
    if (!inCidr(value, "2000::/3") || inCidr(value, "2001:db8::/32")) return "reserved";
    return "public";
  }
  if (["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].some((cidr) => inCidr(value, cidr))) return "private";
  if (["0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24",
    "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"]
    .some((cidr) => inCidr(value, cidr))) return "reserved";
  return "public";
}

function addressScope(value) {
  if (scopeCache.has(value)) return scopeCache.get(value);
  const result = computeScope(value);
  if (scopeCache.size >= CORRELATION_LIMIT) scopeCache.clear();
  scopeCache.set(value, result);
  return result;
}

function disposition(event) {
  if (dispositionCache.has(event)) return dispositionCache.get(event);
  const types = strings(event.rawFields, "event.type").map((value) => value.toLowerCase());
  const action = event.action?.toLowerCase().replace(/[ -]/g, "_");
  const result = types.includes("denied") || BLOCKED_ACTIONS.has(action) ? "blocked"
    : event.outcome === "failure" ? "failed"
      : types.includes("allowed") || ALLOWED_ACTIONS.has(action) || event.outcome === "success" ? "allowed" : "unknown";
  dispositionCache.set(event, result);
  return result;
}

function isDns(event) {
  if (dnsCache.has(event)) return dnsCache.get(event);
  const result = strings(event.rawFields, "network.protocol").some((value) => value.toLowerCase() === "dns")
    || fieldValues(event.rawFields, "dns.question.name").length > 0;
  dnsCache.set(event, result);
  return result;
}

function routineDns(event) {
  return DNS_RESOLVERS.has(event.destinationIp) && (isDns(event) || [53, 853, 443].includes(event.port));
}

function outbound(event) {
  return event.category.includes("network") && disposition(event) === "allowed"
    && addressScope(event.sourceIp) === "private" && addressScope(event.destinationIp) === "public";
}

function settings(config) {
  const result = { ...DEFAULTS };
  for (const key of ["baselineDays", "retentionDays", "scanMinAttempts", "scanMinTargets", "scanMinPorts", "authFailures",
    "beaconMinConnections", "exfilMinBytes", "exfilRatio"]) {
    if (typeof config[key] === "number" && Number.isFinite(config[key]) && config[key] > 0) {
      result[key] = key === "exfilRatio" ? config[key] : Math.ceil(config[key]);
    }
  }
  result.beaconMinConnections = Math.max(8, result.beaconMinConnections);
  if (typeof config.beaconMaxCv === "number" && Number.isFinite(config.beaconMaxCv) && config.beaconMaxCv >= 0) result.beaconMaxCv = config.beaconMaxCv;
  if (typeof config.timezone === "string") {
    try {
      new Intl.DateTimeFormat("en-GB", { timeZone: config.timezone }).format();
      result.timezone = config.timezone;
    } catch { /* Keep the documented default for invalid timezones. */ }
  }
  if (Array.isArray(config.riskyPorts)) result.riskyPorts = unique(config.riskyPorts.filter((port) => Number.isInteger(port) && port > 0 && port <= 65535));
  return result;
}

function calendar(timezone) {
  const formatter = new Intl.DateTimeFormat("en-GB", {
    timeZone: timezone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23"
  });
  const cache = new Map();
  return (value) => {
    if (cache.has(value)) return cache.get(value);
    const parts = Object.fromEntries(formatter.formatToParts(new Date(value)).map(({ type, value: part }) => [type, part]));
    const day = `${parts.year}-${parts.month}-${parts.day}`;
    const result = { day, hour: Number(parts.hour), minute: Number(parts.minute), weekday: new Date(`${day}T00:00:00Z`).getUTCDay() };
    cache.set(value, result);
    return result;
  };
}

function hostKey(event) {
  return event.host || (addressScope(event.sourceIp) === "private" ? event.sourceIp : null);
}

function peerKey(event) {
  return event.destinationDomain || event.destinationIp || null;
}

function increment(record, key, amount = 1) {
  if (key === null || key === undefined) return;
  Object.defineProperty(record, key, { value: (Object.hasOwn(record, key) ? record[key] : 0) + amount, enumerable: true, writable: true, configurable: true });
}

function setEntry(record, key, value) {
  Object.defineProperty(record, key, { value, enumerable: true, writable: true, configurable: true });
  return value;
}

function eventKey(event) {
  return JSON.stringify([event.index, event.id]);
}

function loadBaselines(baselines, timezone) {
  // Calendar buckets cannot be reused after a timezone change.
  const empty = { version: 1, layout: "bounded-ledger-v1", timezone, hosts: {}, users: {}, observedEvents: {}, incompleteDays: {}, correlation: { events: [] } };
  if (baselines.version !== 1 || baselineResetReason(baselines, timezone)) return empty;
  for (const key of ["hosts", "users", "observedEvents", "incompleteDays", "correlation"]) {
    if (isRecord(baselines[key])) empty[key] = structuredClone(baselines[key]);
  }
  return empty;
}

function baselineResetReason(baselines, timezone) {
  if (baselines.version !== 1) return null;
  if (baselines.timezone !== timezone) return "Baseline calendar buckets reset because the configured timezone changed.";
  if (baselines.layout !== "bounded-ledger-v1") return "Unbounded or incompatible baseline layout reset; historical evidence must be collected again.";
  for (const [kind, limit] of [["hosts", BASELINE_ENTITY_LIMIT], ["users", BASELINE_ENTITY_LIMIT], ["observedEvents", BASELINE_EVENT_LIMIT]]) {
    let count = 0;
    for (const key in baselines[kind] ?? {}) {
      if (Object.hasOwn(baselines[kind], key) && ++count > limit) return "Oversized baseline reset; dependent alerts require new reliable history.";
    }
  }
  if (baselines.correlation?.events?.length > CORRELATION_LIMIT) return "Oversized correlation baseline reset; dependent alerts require new reliable history.";
  return null;
}

function pruneBaselines(baselines, today, retentionDays) {
  const cutoff = new Date(Date.parse(`${today}T00:00:00Z`) - retentionDays * 86_400_000).toISOString().slice(0, 10);
  for (const kind of ["hosts", "users"]) {
    for (const [key, entity] of Object.entries(baselines[kind])) {
      for (const day of Object.keys(entity.days)) if (day < cutoff) delete entity.days[day];
      if (!Object.keys(entity.days).length) delete baselines[kind][key];
    }
  }
  for (const [key, record] of Object.entries(baselines.observedEvents)) if (record.day < cutoff) delete baselines.observedEvents[key];
  for (const day of Object.keys(baselines.incompleteDays)) if (day < cutoff) delete baselines.incompleteDays[day];
  return cutoff;
}

function incomplete(baselines, day, reason) {
  setEntry(baselines.incompleteDays, day, unique([...(baselines.incompleteDays[day] ?? []), reason]));
}

function observe(baselines, event, local, budget) {
  const keyForEvent = eventKey(event);
  if (local.day < budget.cutoff || Object.hasOwn(baselines.observedEvents, keyForEvent)) return;
  if (Object.hasOwn(baselines.incompleteDays, local.day)) { budget.dropped += 1; return; }
  if (budget.events >= BASELINE_EVENT_LIMIT) {
    incomplete(baselines, local.day, "event tracking limit"); budget.dropped += 1; return;
  }
  for (const [kind, key] of [["hosts", hostKey(event)], ["users", event.identity]]) {
    if (key && !Object.hasOwn(baselines[kind], key) && budget[kind] >= BASELINE_ENTITY_LIMIT) {
      incomplete(baselines, local.day, `${kind} entity limit`); budget.dropped += 1; return;
    }
  }
  const peer = peerKey(event);
  for (const [kind, key] of [["hosts", hostKey(event)], ["users", event.identity]]) {
    if (!key) continue;
    let entity = Object.hasOwn(baselines[kind], key) ? baselines[kind][key] : null;
    if (!entity) {
      entity = setEntry(baselines[kind], key, { firstSeen: event.timestamp, lastSeen: event.timestamp, days: {} });
      budget[kind] += 1;
    }
    const day = Object.hasOwn(entity.days, local.day) ? entity.days[local.day] : setEntry(entity.days, local.day, {
      observations: 0, weekday: local.weekday, peers: {}, hours: {}, hosts: {}, outboundBytesByHour: {}
    });
    day.observations += 1;
    increment(day.peers, peer);
    increment(day.hours, local.hour);
    increment(day.hosts, hostKey(event));
    if (outbound(event) && event.bytesOut !== null && !routineDns(event) && !isDns(event)) increment(day.outboundBytesByHour, local.hour, event.bytesOut);
    entity.firstSeen = entity.firstSeen < event.timestamp ? entity.firstSeen : event.timestamp;
    entity.lastSeen = entity.lastSeen > event.timestamp ? entity.lastSeen : event.timestamp;
  }
  setEntry(baselines.observedEvents, keyForEvent, { day: local.day, timestamp: event.timestamp, hour: local.hour, peer,
    host: hostKey(event), identity: event.identity,
    bytes: outbound(event) && event.bytesOut !== null && !routineDns(event) && !isDns(event) ? event.bytesOut : null });
  budget.events += 1;
}

function subtract(record, key, amount = 1) {
  if (key === null || key === undefined || !Object.hasOwn(record, key)) return;
  if (record[key] <= amount) delete record[key];
  else record[key] -= amount;
}

function rejectObservation(baselines, event, local, budget) {
  const key = eventKey(event);
  if (local.day < budget.cutoff) return;
  const observed = Object.hasOwn(baselines.observedEvents, key) ? baselines.observedEvents[key] : null;
  if (observed?.excluded) return;
  if (!observed && budget.events >= BASELINE_EVENT_LIMIT) {
    incomplete(baselines, local.day, "event tracking limit"); return;
  }
  if (!observed) budget.events += 1;
  setEntry(baselines.observedEvents, key, { day: observed?.day ?? local.day, excluded: true });
  if (!observed) return;
  for (const [kind, entityKey] of [["hosts", observed.host], ["users", observed.identity]]) {
    const entity = entityKey && Object.hasOwn(baselines[kind], entityKey) ? baselines[kind][entityKey] : null;
    const day = entity?.days[observed.day];
    if (!day) continue;
    subtract(day.peers, observed.peer);
    subtract(day.hours, observed.hour);
    subtract(day.hosts, observed.host);
    if (observed.bytes !== null) subtract(day.outboundBytesByHour, observed.hour, observed.bytes);
    day.observations -= 1;
    entity._dirty = true;
    if (day.observations === 0) delete entity.days[observed.day];
  }
}

function rebuildRejectedDays(baselines) {
  let changed = false;
  for (const kind of ["hosts", "users"]) {
    for (const [key, entity] of Object.entries(baselines[kind])) {
      if (!entity._dirty) continue;
      changed = true;
      if (!Object.keys(entity.days).length) { delete baselines[kind][key]; continue; }
      entity.firstSeen = null; entity.lastSeen = null;
    }
  }
  if (!changed) return;
  for (const record of Object.values(baselines.observedEvents)) {
    if (record.excluded) continue;
    for (const [kind, key] of [["hosts", record.host], ["users", record.identity]]) {
      const entity = key && Object.hasOwn(baselines[kind], key) ? baselines[kind][key] : null;
      if (!entity?._dirty) continue;
      if (!entity.firstSeen || record.timestamp < entity.firstSeen) entity.firstSeen = record.timestamp;
      if (!entity.lastSeen || record.timestamp > entity.lastSeen) entity.lastSeen = record.timestamp;
    }
  }
  for (const kind of ["hosts", "users"]) for (const entity of Object.values(baselines[kind])) delete entity._dirty;
}

function normalObservation(event) {
  if (disposition(event) !== "allowed" || (!hostKey(event) && !event.identity)) return false;
  return event.category.includes("network") || event.category.includes("authentication") || event.category.includes("process");
}

function history(baselines, kind, key, beforeDay, minDays) {
  const entity = key && Object.hasOwn(baselines[kind], key) ? baselines[kind][key] : null;
  const days = Object.entries(entity?.days ?? {}).filter(([date, day]) => date < beforeDay && day.observations > 0);
  const partial = Object.keys(baselines.incompleteDays).some((date) => date <= beforeDay);
  return { days: days.map(([, day]) => day), mature: !partial && days.length >= minDays, incomplete: partial };
}

function reputationFor(reputations, type, indicator) {
  let record;
  for (const key of [`${type}|${indicator}`, `${type}:${indicator}`, indicator]) {
    if (Object.hasOwn(reputations, key)) { record = reputations[key]; break; }
  }
  if (record === undefined && isRecord(reputations[type]) && Object.hasOwn(reputations[type], indicator)) record = reputations[type][indicator];
  if (typeof record === "string") record = { verdict: record };
  if (!isRecord(record)) return { verdict: "unknown" };
  return { ...record, verdict: VERDICTS.has(record.verdict) ? record.verdict : "unknown" };
}

function excepted(event, type, indicator, options) {
  return (options.exceptions.get(`${type}|${indicator}`) ?? []).some((exception) =>
    (!exception.host || exception.host === event.host)
    && (!exception.infrastructure || exception.infrastructure === event.infrastructure));
}

function exclusions(config, now) {
  const exceptions = (Array.isArray(config.exceptions) ? config.exceptions : []).filter((exception) => isRecord(exception)
    && exception.enabled !== false && typeof exception.reason === "string" && exception.reason.trim()
    && (!exception.expiresAt || (timestamp(exception.expiresAt) && timestamp(exception.expiresAt) > now)))
    .map((exception) => ({ ...exception, indicatorValue: exception.indicatorType === "ip" ? ip(exception.indicatorValue)
      : exception.indicatorType === "domain" ? domain(exception.indicatorValue)
        : exception.indicatorType === "hash" && typeof exception.indicatorValue === "string" ? exception.indicatorValue.toLowerCase() : exception.indicatorValue }));
  const result = new Map();
  for (const exception of exceptions) {
    const key = `${exception.indicatorType}|${exception.indicatorValue}`;
    if (!result.has(key)) result.set(key, []);
    result.get(key).push(exception);
  }
  return result;
}

function adverseEvent(event, reputations) {
  return [...eventIndicators(event)[0][1].map((value) => ["ip", value]),
    ...event.domains.map((value) => ["domain", value]), ...event.hashes.map((value) => ["hash", value]),
    ...(event.identity ? [["identity", event.identity]] : [])].some(([type, value]) => {
    const reputation = reputationFor(reputations, type, value);
    return adverse(reputation) && !resolverNoise(event, type, value, reputation);
  });
}

function resolverNoise(event, type, indicator, reputation) {
  if (type !== "ip" || indicator !== event.destinationIp || !routineDns(event) || reputation.verdict !== "suspicious") return false;
  const votes = Number(reputation.malicious);
  const score = Number(reputation.score);
  const primary = typeof reputation.gtiVerdict === "string" ? reputation.gtiVerdict.toLowerCase() : "";
  return Number.isFinite(votes) && votes >= 0 && votes < 3 && Number.isFinite(score) && score >= 0 && score < 20
    && !/\b(?:malicious|suspicious)\b/.test(primary);
}

function adverse(reputation) {
  return reputation.verdict === "malicious" || reputation.verdict === "suspicious";
}

function bounded(value) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function assetFor(event, config) {
  return (Array.isArray(config.assets) ? config.assets : []).find((asset) => isRecord(asset) &&
    ([asset.id, asset.name].filter(Boolean).includes(event.host)
      || (Array.isArray(asset.ips) && asset.ips.some((value) => [event.sourceIp, event.destinationIp].includes(ip(value))))
      || (Array.isArray(asset.cidrs) && asset.cidrs.some((cidr) => inCidr(event.sourceIp, cidr) || inCidr(event.destinationIp, cidr))))) ?? null;
}

function assetBoost(event, config) {
  const criticality = assetFor(event, config)?.criticality;
  if (criticality === "critical") return 10;
  if (criticality === "high") return 5;
  return typeof criticality === "number" && criticality >= 4 ? 5 : 0;
}

function proofReason(event) {
  const state = disposition(event);
  return `${state === "allowed" ? "Allowed" : state === "blocked" ? "Blocked" : state === "failed" ? "Failed" : "Outcome unknown"} event`
    + (event.action ? ` (${event.action})` : "");
}

function addFinding(findings, details, events, config, reasonForEvent = proofReason) {
  if (!events.length) return;
  const ordered = [...new Map(events.map((event) => [eventKey(event), event])).values()]
    .sort((left, right) => left.timestamp.localeCompare(right.timestamp) || eventKey(left).localeCompare(eventKey(right)));
  const representative = ordered.at(-1);
  const fingerprint = digest([details.category, details.indicatorType, details.indicator, details.scope]);
  const prior = findings.get(fingerprint);
  const behaviorScore = bounded(details.behaviorScore);
  const confidence = bounded(details.confidence);
  const reputation = details.reputation ?? { verdict: "unknown" };
  const reputationBoost = reputation.verdict === "malicious" ? 15 : reputation.verdict === "suspicious" ? 7 : 0;
  const priority = bounded(behaviorScore * 0.65 + confidence * 0.35 + reputationBoost + assetBoost(representative, config));
  const proofs = ordered.map((event) => ({ eventId: event.id, index: event.index, timestamp: event.timestamp, reason: reasonForEvent(event) }));
  if (prior) {
    for (const event of ordered) prior._eventKeys.add(eventKey(event));
    prior.firstSeen = prior.firstSeen < ordered[0].timestamp ? prior.firstSeen : ordered[0].timestamp;
    if (representative.timestamp >= prior.lastSeen) {
      prior.lastSeen = representative.timestamp;
      for (const field of ["host", "identity", "sourceIp", "destinationIp", "infrastructure"]) prior[field] = representative[field];
    }
    prior.priority = Math.max(prior.priority, priority);
    prior.confidence = Math.max(prior.confidence, confidence);
    prior.behaviorScore = Math.max(prior.behaviorScore, behaviorScore);
    prior.events = prior.count = prior._eventKeys.size;
    prior.evidence = sampleProofs([...prior.evidence, ...proofs]);
    prior.reasons = unique([...prior.reasons, ...details.reasons]);
    return;
  }
  const { scope, ...rest } = details;
  findings.set(fingerprint, {
    ...rest, fingerprint,
    sourceIp: representative.sourceIp, destinationIp: representative.destinationIp,
    host: representative.host, identity: representative.identity, infrastructure: representative.infrastructure,
    severity: details.severity ?? (priority >= 90 ? "critical" : priority >= 70 ? "high" : priority >= 40 ? "medium" : "low"),
    behaviorScore, confidence, priority,
    reputation,
    firstSeen: ordered[0].timestamp, lastSeen: representative.timestamp,
    events: ordered.length, count: ordered.length, evidence: sampleProofs(proofs),
    reasons: unique(details.reasons ?? []), limitations: unique(details.limitations ?? []), status: "open",
    _eventKeys: new Set(ordered.map(eventKey))
  });
}

function sampleProofs(proofs) {
  const sorted = [...new Map(proofs.map((proof) => [JSON.stringify([proof.index, proof.eventId]), proof])).values()]
    .sort((left, right) => left.timestamp.localeCompare(right.timestamp) || left.eventId.localeCompare(right.eventId));
  if (sorted.length <= 30) return sorted;
  // Preserve both ends, including the success that completes an auth sequence.
  return Array.from({ length: 30 }, (_, index) => sorted[Math.round(index * (sorted.length - 1) / 29)]);
}

function authentication(events, findings, options) {
  const pending = new Map();
  for (const event of events) {
    if (!event.category.includes("authentication") || !event.identity || !event.sourceIp || excepted(event, "identity", event.identity, options)) continue;
    const key = JSON.stringify([event.identity, event.sourceIp]);
    const time = Date.parse(event.timestamp);
    const stateForKey = pending.get(key) ?? { failures: [], start: 0 };
    while (stateForKey.start < stateForKey.failures.length && time - Date.parse(stateForKey.failures[stateForKey.start].timestamp) > WINDOW_MS) stateForKey.start += 1;
    if (stateForKey.start > 1000 && stateForKey.start * 2 > stateForKey.failures.length) {
      stateForKey.failures = stateForKey.failures.slice(stateForKey.start);
      stateForKey.start = 0;
    }
    const state = disposition(event);
    if (event.outcome === "failure" || state === "blocked") {
      stateForKey.failures.push(event);
      pending.set(key, stateForKey);
    } else if (event.outcome === "success" && state === "allowed") {
      const preceding = stateForKey.failures.slice(stateForKey.start).filter((failure) => failure.timestamp < event.timestamp);
      if (preceding.length >= options.settings.authFailures) {
        addFinding(findings, {
          category: "authentication", title: "Repeated authentication failures followed by success",
          indicatorType: "identity", indicator: event.identity, scope: event.sourceIp,
          behaviorScore: 85, confidence: 95, severity: "high",
          reputation: reputationFor(options.reputations, "identity", event.identity),
          reasons: [`${preceding.length} failures preceded a success for the same identity and source within 15 minutes.`],
          limitations: ["A successful login after failures warrants investigation; it does not establish account compromise."]
        }, [...preceding, event], options.config, (item) =>
          item === event ? "Allowed authentication success after the preceding failures" : "Failed/blocked authentication before the success");
      }
      pending.delete(key);
    }
  }
}

function scans(events, findings, options) {
  const groups = new Map();
  for (const event of events) {
    if (addressScope(event.sourceIp) !== "public" || disposition(event) !== "blocked" || !event.category.includes("network") || excepted(event, "ip", event.sourceIp, options)) continue;
    if (!event.destinationIp && !event.port) continue;
    if (!groups.has(event.sourceIp)) groups.set(event.sourceIp, []);
    groups.get(event.sourceIp).push(event);
  }
  for (const [source, attempts] of groups) {
    let start = 0;
    const counts = { infrastructures: new Map(), targets: new Map(), ports: new Map() };
    const ranges = [];
    const change = (event, amount) => {
      for (const [key, value] of [["infrastructures", event.infrastructure], ["targets", event.destinationIp], ["ports", event.port]]) {
        if (value === null || value === undefined) continue;
        const total = (counts[key].get(value) ?? 0) + amount;
        if (total > 0) counts[key].set(value, total);
        else counts[key].delete(value);
      }
    };
    for (let end = 0; end < attempts.length; end += 1) {
      change(attempts[end], 1);
      while (Date.parse(attempts[end].timestamp) - Date.parse(attempts[start].timestamp) > WINDOW_MS) change(attempts[start++], -1);
      if (end - start + 1 < options.settings.scanMinAttempts) continue;
      if (counts.infrastructures.size < 2 || (counts.targets.size < options.settings.scanMinTargets && counts.ports.size < options.settings.scanMinPorts)) continue;
      const previous = ranges.at(-1);
      if (previous && start <= previous.end + 1) previous.end = end;
      else ranges.push({ start, end });
    }
    if (ranges.length) {
      const window = ranges.flatMap((range) => attempts.slice(range.start, range.end + 1));
      const infrastructures = unique(window.map((event) => event.infrastructure));
      const targets = unique(window.map((event) => event.destinationIp));
      const ports = unique(window.map((event) => event.port));
      const reputation = reputationFor(options.reputations, "ip", source);
      const risky = ports.filter((port) => options.settings.riskyPorts.includes(port));
      addFinding(findings, {
        category: "scan", title: "Denied scan attempts across infrastructure", indicatorType: "ip", indicator: source, scope: source,
        behaviorScore: 70 + Math.min(10, risky.length), confidence: 90,
        severity: adverse(reputation) ? "high" : "medium", reputation,
        reasons: [`${window.length} blocked attempts in qualifying 15-minute windows across ${infrastructures.length} infrastructure sources, ${targets.length} targets and ${ports.length} ports.`,
          ...(risky.length ? [`Configured risky ports observed: ${risky.join(", ")}.`] : [])],
        limitations: ["Denied attempts show probing, not successful access.",
          ...(!adverse(reputation) ? ["Reputation is not adverse; investigate the observed scan behavior."] : [])]
      }, window, options.config, (event) => `Blocked attempt to ${event.destinationIp ?? "unknown target"}:${event.port ?? "unknown port"} via ${event.infrastructure ?? "unknown infrastructure"}`);
    }
  }
}

function intelligenceMode(event, type, indicator) {
  if (disposition(event) === "blocked") return "blocked";
  if (type === "hash" && hashes(event.rawFields, "process").includes(indicator) && event.category.includes("process")
    && disposition(event) !== "failed" && (strings(event.rawFields, "event.type").includes("start")
      || EXECUTION_ACTIONS.has(event.action?.toLowerCase().replace(/[ -]/g, "_")))) return "execution";
  if ((type === "domain" && strings(event.rawFields, "dns.question.name").map(domain).includes(indicator)) || (type === "ip" && isDns(event))) return "dns-query";
  if (type !== "hash" && event.category.includes("network") && disposition(event) === "allowed"
    && (type === "ip" || event.destinationDomain === indicator || strings(event.rawFields, "url.domain").map(domain).includes(indicator))) return "connection";
  return "sighting";
}

function intelligence(events, findings, options) {
  const groups = new Map();
  const titles = {
    blocked: "Blocked activity involving a reputation-listed indicator", execution: "Execution of a reputation-listed process hash",
    "dns-query": "DNS query involving a reputation-listed indicator", connection: "Allowed connection involving a reputation-listed indicator",
    sighting: "Reputation-listed indicator sighting"
  };
  for (const event of events) {
    const indicators = [
      ...eventIndicators(event)[0][1].map((value) => ["ip", value]),
      ...event.domains.map((value) => ["domain", value]), ...event.hashes.map((value) => ["hash", value])
    ];
    for (const [type, indicator] of indicators) {
      const reputation = reputationFor(options.reputations, type, indicator);
      options.indicators.add(`${type}:${indicator}`);
      if (reputation.verdict !== "unknown") options.matchedIndicators.add(`${type}:${indicator}`);
      if (!adverse(reputation)) continue;
      if (resolverNoise(event, type, indicator, reputation)) continue;
      if (excepted(event, type, indicator, options)) continue;
      const mode = intelligenceMode(event, type, indicator);
      const scope = JSON.stringify([hostKey(event), mode]);
      const key = JSON.stringify([type, indicator, scope]);
      if (!groups.has(key)) groups.set(key, { type, indicator, reputation, mode, scope, events: [] });
      groups.get(key).events.push(event);
    }
  }
  for (const { type, indicator, reputation, mode, scope, events: sightings } of groups.values()) {
    const active = mode === "execution" || mode === "connection";
    const reason = mode === "blocked" ? "Blocked/prevented activity; the indicator was observed but successful access or execution is not shown."
      : mode === "dns-query" ? "DNS query observed; a query alone does not establish a connection or execution."
        : mode === "execution" ? "Process start/execution event contains this exact process hash."
          : mode === "connection" ? "Allowed network activity contains this exact indicator."
            : "Exact ECS indicator sighting; connection or execution is not established.";
    addFinding(findings, {
      category: "intelligence", title: titles[mode], indicatorType: type, indicator, scope,
      behaviorScore: mode === "execution" ? 90 : mode === "connection" ? 75 : mode === "blocked" ? 40 : 25,
      confidence: mode === "execution" ? 95 : active ? 85 : 75,
      severity: reputation.verdict === "malicious" && mode === "execution" ? "critical" : active ? "high" : "medium",
      reputation, reasons: [`Caller-supplied reputation: ${reputation.verdict}.`, reason],
      limitations: ["Reputation plus a sighting does not by itself establish compromise.",
        ...(mode === "execution" ? ["Process telemetry establishes execution, not the effects of that execution."] : [])]
    }, sightings, options.config, (event) => `${proofReason(event)}. ${reason}`);
  }
}

function groupOutbound(events, options) {
  const groups = new Map();
  for (const event of events) {
    if (!outbound(event) || routineDns(event) || isDns(event) || !hostKey(event)) continue;
    const peer = peerReputation(event, options.reputations);
    if (excepted(event, peer.type, peer.indicator, options)) continue;
    const key = JSON.stringify([hostKey(event), event.destinationIp, event.destinationDomain, event.port, event.processEntityId]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(event);
  }
  return groups;
}

function peerReputation(event, reputations) {
  const ipReputation = reputationFor(reputations, "ip", event.destinationIp);
  const domainReputation = event.destinationDomain ? reputationFor(reputations, "domain", event.destinationDomain) : { verdict: "unknown" };
  if (adverse(domainReputation) && !adverse(ipReputation)) return { type: "domain", indicator: event.destinationDomain, reputation: domainReputation };
  return { type: "ip", indicator: event.destinationIp, reputation: ipReputation };
}

function beacons(events, findings, options) {
  for (const connections of groupOutbound(events, options).values()) {
    // A peer's established history, and different local days, must not change an interval series.
    const days = new Map();
    for (const event of connections) {
      const day = options.local(event.timestamp).day;
      if (!days.has(day)) days.set(day, []);
      days.get(day).push(event);
    }
    for (const [day, samples] of days) {
      const starts = samples.filter((event) => strings(event.rawFields, "event.type").includes("start")
        || !strings(event.rawFields, "event.type").some((value) => ["end", "info"].includes(value)));
      const times = unique(starts.map((event) => Date.parse(event.timestamp)));
      if (times.length < options.settings.beaconMinConnections || times.at(-1) - times[0] < 5 * 60_000) continue;
      const intervals = times.slice(1).map((time, index) => time - times[index]);
      const mean = intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;
      const cv = Math.sqrt(intervals.reduce((sum, interval) => sum + (interval - mean) ** 2, 0) / intervals.length) / mean;
      if (!Number.isFinite(cv) || cv > options.settings.beaconMaxCv) continue;
      const event = starts.at(-1);
      const past = history(options.baselines, "hosts", hostKey(event), day, options.settings.baselineDays);
      const peer = peerKey(event);
      const peerDays = past.days.filter((record) => Object.hasOwn(record.peers, peer)).length;
      const rarePeer = past.mature && peerDays / past.days.length <= 0.1;
      const intelligence = peerReputation(event, options.reputations);
      if (!rarePeer && !adverse(intelligence.reputation)) continue;
      addFinding(findings, {
        category: "beacon", title: "Regular outbound connections requiring investigation",
        indicatorType: intelligence.type, indicator: intelligence.indicator,
        scope: JSON.stringify([hostKey(event), event.port, event.processEntityId]),
        behaviorScore: 75, confidence: adverse(intelligence.reputation) ? 90 : 80, severity: adverse(intelligence.reputation) ? "high" : "medium",
        reputation: intelligence.reputation,
        reasons: [`${times.length} allowed private-to-public connections over ${Math.round((times.at(-1) - times[0]) / 1000)} seconds; interval CV ${cv.toFixed(3)}.`,
          ...(rarePeer ? [`Peer observed on ${peerDays} of ${past.days.length} preceding baseline days; the host baseline is mature.`] : []),
          ...(adverse(intelligence.reputation) ? [`Peer reputation is ${intelligence.reputation.verdict}.`] : [])],
        limitations: ["Regular timing can also occur in legitimate automation; this is not proof of command and control.",
          ...(!past.mature ? ["Host baseline is immature; adverse reputation supplies the additional evidence."] : [])]
      }, starts, options.config, (item) => `Allowed outbound connection to ${item.destinationIp}:${item.port ?? "unknown port"}; regular interval series`);
    }
  }
}

function exfiltration(events, findings, options) {
  const groups = new Map();
  for (const connections of groupOutbound(events, options).values()) {
    for (const event of connections) {
      if (event.bytesOut === null) continue;
      const local = options.local(event.timestamp);
      const key = JSON.stringify([hostKey(event), event.destinationIp, local.day, local.hour]);
      if (!groups.has(key)) groups.set(key, { local, events: [] });
      groups.get(key).events.push(event);
    }
  }
  for (const { local, events: transfers } of groups.values()) {
    const event = transfers.at(-1);
    const bytes = transfers.reduce((sum, item) => sum + item.bytesOut, 0);
    if (bytes < options.settings.exfilMinBytes) continue;
    const past = history(options.baselines, "hosts", hostKey(event), local.day, options.settings.baselineDays);
    const hourDays = past.days.filter((day) => Object.hasOwn(day.outboundBytesByHour, local.hour));
    if (!past.mature || hourDays.length < options.settings.baselineDays) continue;
    const usualBytes = hourDays.reduce((sum, day) => sum + day.outboundBytesByHour[local.hour], 0) / hourDays.length;
    // A zero/missing denominator is not evidence of a volume ratio.
    if (!(usualBytes > 0) || bytes / usualBytes < options.settings.exfilRatio) continue;
    const intelligence = peerReputation(event, options.reputations);
    addFinding(findings, {
      category: "exfiltration", title: "Outbound transfer above the historical baseline",
      indicatorType: intelligence.type, indicator: intelligence.indicator, scope: JSON.stringify([hostKey(event), local.hour]),
      behaviorScore: 85, confidence: 85, severity: "high", reputation: intelligence.reputation,
      reasons: [`${bytes} source bytes sent on allowed private-to-public traffic in local hour ${local.hour}.`,
        `${(bytes / usualBytes).toFixed(2)} times the mean ${Math.round(usualBytes)} outbound bytes for this hour across ${hourDays.length} preceding distinct days.`],
      limitations: ["A large transfer can be legitimate; byte counters do not establish stolen data.",
        "Baseline compares host outbound source bytes in the same local hour; historical collection completeness is not independently verified."]
    }, transfers, options.config, (item) => `Allowed private-to-public transfer: ${item.bytesOut} source bytes to ${item.destinationIp}`);
  }
}

function outsideHours(local, allowedHours) {
  if (Array.isArray(allowedHours)) return !allowedHours.includes(local.hour);
  if (!isRecord(allowedHours)) return false;
  if (Array.isArray(allowedHours.weekdays) && !allowedHours.weekdays.includes(local.weekday)) return true;
  const toMinutes = (value) => typeof value === "number" && value >= 0 && value <= 24 ? value * 60
    : typeof value === "string" && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value) ? Number(value.slice(0, 2)) * 60 + Number(value.slice(3)) : null;
  const start = toMinutes(allowedHours.start);
  const end = toMinutes(allowedHours.end);
  if (start === null || end === null || start === end) return false;
  const minutes = local.hour * 60 + local.minute;
  return start < end ? minutes < start || minutes >= end : minutes < start && minutes >= end;
}

function reviewContexts(events, options) {
  const contexts = new Map();
  const accounts = Array.isArray(options.config.accounts) ? options.config.accounts : [];
  for (const event of events) {
    const local = options.local(event.timestamp);
    const account = accounts.find((item) => item?.identity === event.identity);
    const reasons = [];
    if (account && outsideHours(local, account.allowedHours)) reasons.push(`Activity outside configured hours for ${account.kind === "service" ? "service" : "human"} account.`);
    if (account && Array.isArray(account.hosts) && event.host && !account.hosts.includes(event.host)) reasons.push("Account observed on a host outside its configured host list.");
    const past = history(options.baselines, "users", event.identity, local.day, options.settings.baselineDays);
    if (past.mature && event.host && !past.days.some((day) => Object.hasOwn(day.hosts, event.host))) reasons.push("New host for this identity relative to its mature baseline.");
    if (past.mature && !past.days.some((day) => day.weekday === local.weekday && Object.hasOwn(day.hours, local.hour))) reasons.push("Unusual local hour/weekday for this identity; review context only.");
    for (const reason of reasons) {
      const key = JSON.stringify([event.identity, event.host, reason]);
      if (!contexts.has(key)) contexts.set(key, { host: event.host, identity: event.identity, timestamp: event.timestamp, reason });
    }
  }
  return [...contexts.values()].slice(0, 100);
}

function correlationEvents(previous, events, now) {
  const combined = new Map();
  const anchor = events.at(-1)?.timestamp ?? now;
  const prior = (Array.isArray(previous.events) ? previous.events : []).filter((event) => Date.parse(event.timestamp) >= Date.parse(anchor) - CORRELATION_MS);
  for (const event of [...prior, ...events]) {
    if (isRecord(event) && timestamp(event.timestamp) && event.timestamp <= now && isRecord(event.rawFields)) combined.set(eventKey(event), event);
  }
  return [...combined.values()].sort((left, right) => left.timestamp.localeCompare(right.timestamp) || eventKey(left).localeCompare(eventKey(right)));
}

function retainCorrelation(events, cutoffDay, local) {
  const latest = events.at(-1)?.timestamp;
  if (!latest) return { events: [] };
  const cutoff = Date.parse(latest) - CORRELATION_MS;
  const retained = events.filter((event) => Date.parse(event.timestamp) >= cutoff && local(event.timestamp).day >= cutoffDay &&
    ((event.category.includes("authentication") && event.identity && event.sourceIp)
      || (event.category.includes("network") && (outbound(event) || (addressScope(event.sourceIp) === "public" && disposition(event) === "blocked")))));
  return { events: retained.slice(-CORRELATION_LIMIT).map((event) => {
    const rawFields = {};
    for (const path of ["event.type", "network.protocol", "dns.question.name", "url.domain", ...Object.keys(HASH_LENGTHS).map((algorithm) => `process.hash.${algorithm}`)]) {
      const values = fieldValues(event.rawFields, path);
      if (values.length) rawFields[path] = values;
    }
    return { ...event, message: null, rawFields };
  }), truncated: retained.length > CORRELATION_LIMIT };
}

/**
 * Accepts normalized events or ES hits. No network or model calls are made.
 * Persist the returned version-1 baselines unchanged between runs. Host/user
 * local-day buckets aggregate peers, hours, weekdays, hosts and outbound bytes.
 * One shared bounded event ledger supports deduplication and retraction.
 * Calendar buckets and IDs expire after retentionDays (default 30). Limits are
 * 100k tracked IDs and 5k hosts/users; incomplete days disable dependent alerts.
 * Only preceding days establish maturity. Adverse sightings and confident
 * findings cannot teach normal.
 * Correlation keeps up to 100k compact events over the latest hour across chunks.
 * Reputations use `type|indicator`; plain, colon and nested keys also work.
 * Account hours accept hour arrays or {start, end, weekdays} in the chosen timezone.
 */
export function analyzeEvidence(events, { reputations = {}, baselines = {}, config = {}, now = new Date().toISOString() } = {}) {
  config = isRecord(config) ? config : {};
  reputations = isRecord(reputations) ? reputations : {};
  baselines = isRecord(baselines) ? baselines : {};
  const policy = settings(config);
  const local = calendar(policy.timezone);
  const currentTime = timestamp(now) ?? new Date().toISOString();
  const baseline = loadBaselines(baselines, policy.timezone);
  const today = local(currentTime).day;
  const cutoff = pruneBaselines(baseline, today, policy.retentionDays);
  const budget = { cutoff, events: Object.keys(baseline.observedEvents).length,
    hosts: Object.keys(baseline.hosts).length, users: Object.keys(baseline.users).length, dropped: 0 };
  const normalized = [];
  const seen = new Set();
  const coverage = { inputEvents: Array.isArray(events) ? events.length : 0, validEvents: 0, invalidEvents: 0, duplicateEvents: 0, futureEvents: 0,
    timezone: policy.timezone, baselineDays: policy.baselineDays, retentionDays: policy.retentionDays, missingFields: {}, limitations: [] };
  for (const value of Array.isArray(events) ? events : []) {
    const isNormalized = isRecord(value?.rawFields);
    const time = isNormalized ? timestamp(value.timestamp) : null;
    const event = isNormalized && time ? normalizeEvent({ _id: value.id, _index: value.index,
      _source: { ...value.rawFields, "@timestamp": time } }) : isNormalized ? null : normalizeEvent(value, config);
    // Preserve a normalized event's caller-selected paths and its original proof fields.
    const prepared = event && isNormalized ? { ...event, ...value, id: value.id || event.id, timestamp: time,
      category: Array.isArray(value.category) ? value.category : event.category,
      domains: Array.isArray(value.domains) ? value.domains : event.domains,
      hashes: Array.isArray(value.hashes) ? value.hashes : event.hashes } : event;
    if (!prepared) { coverage.invalidEvents += 1; continue; }
    if (prepared.timestamp > currentTime) { coverage.futureEvents += 1; continue; }
    const key = eventKey(prepared);
    if (seen.has(key)) { coverage.duplicateEvents += 1; continue; }
    seen.add(key);
    normalized.push(prepared);
    for (const field of ["sourceIp", "destinationIp", "host", "identity", "infrastructure", "bytesOut"]) {
      if (prepared[field] === null || prepared[field] === undefined) increment(coverage.missingFields, field);
    }
  }
  normalized.sort((left, right) => left.timestamp.localeCompare(right.timestamp) || eventKey(left).localeCompare(eventKey(right)));
  coverage.validEvents = normalized.length;
  const correlated = correlationEvents(baseline.correlation, normalized, currentTime);
  coverage.correlatedEvents = correlated.length - normalized.length;
  const options = { settings: policy, config, reputations, baselines: baseline, local, indicators: new Set(), matchedIndicators: new Set(), exceptions: exclusions(config, currentTime) };
  const findings = new Map();
  authentication(correlated, findings, options);
  scans(correlated, findings, options);
  intelligence(correlated, findings, options);
  const rejected = new Set(correlated.filter((event) => adverseEvent(event, reputations)).map(eventKey));
  for (const finding of findings.values()) if (finding.confidence >= 80) for (const key of finding._eventKeys) rejected.add(key);
  for (const event of correlated) if (rejected.has(eventKey(event))) rejectObservation(baseline, event, local(event.timestamp), budget);
  rebuildRejectedDays(baseline);
  budget.hosts = Object.keys(baseline.hosts).length;
  budget.users = Object.keys(baseline.users).length;
  for (const event of normalized) if (!event.sampled && normalObservation(event)) observe(baseline, event, local(event.timestamp), budget);
  beacons(correlated, findings, options);
  exfiltration(correlated, findings, options);
  for (const finding of findings.values()) if (finding.confidence >= 80) for (const key of finding._eventKeys) rejected.add(key);
  for (const event of correlated) if (rejected.has(eventKey(event))) rejectObservation(baseline, event, local(event.timestamp), budget);
  rebuildRejectedDays(baseline);
  baseline.correlation = retainCorrelation(correlated, cutoff, local);
  if (baseline.correlation.truncated) for (const event of baseline.correlation.events) incomplete(baseline, local(event.timestamp).day, "correlation event limit");
  coverage.baselineHosts = Object.keys(baseline.hosts).length;
  coverage.baselineUsers = Object.keys(baseline.users).length;
  coverage.matureHosts = Object.keys(baseline.hosts).filter((key) => history(baseline, "hosts", key, today, policy.baselineDays).mature).length;
  coverage.matureUsers = Object.keys(baseline.users).filter((key) => history(baseline, "users", key, today, policy.baselineDays).mature).length;
  coverage.reputationIndicators = options.indicators.size;
  coverage.reputationMatchedIndicators = options.matchedIndicators.size;
  coverage.excludedFromBaseline = rejected.size;
  coverage.baselineTrackedEvents = Object.keys(baseline.observedEvents).length;
  coverage.baselineIncompleteDays = Object.keys(baseline.incompleteDays).length;
  coverage.baselineDroppedObservations = budget.dropped;
  coverage.reviewContexts = reviewContexts(normalized, options);
  coverage.limitations.push("Baseline maturity counts distinct preceding days with observations; source collection completeness is not known.");
  if (!coverage.matureHosts) coverage.limitations.push("No mature host baseline; baseline-dependent detections are limited.");
  const resetReason = baselineResetReason(baselines, policy.timezone);
  if (resetReason) coverage.limitations.push(resetReason);
  if (baseline.correlation.truncated) coverage.limitations.push("Correlation event budget reached; cross-chunk analysis has reduced coverage.");
  if (coverage.baselineIncompleteDays) coverage.limitations.push("Baseline tracking limits left incomplete days; baseline-dependent alerts are disabled while those days are retained.");
  const result = [...findings.values()].filter((finding) => [...finding._eventKeys].some((key) => seen.has(key)))
    .map(({ _eventKeys, ...finding }) => ({ ...finding, eventKeys: [..._eventKeys].sort() }))
    .sort((left, right) => right.priority - left.priority || left.fingerprint.localeCompare(right.fingerprint));
  const byCategory = {};
  for (const finding of result) increment(byCategory, finding.category);
  const metrics = { analyzedEvents: normalized.length, findings: result.length, byCategory,
    allowedEvents: normalized.filter((event) => disposition(event) === "allowed").length,
    blockedEvents: normalized.filter((event) => disposition(event) === "blocked").length,
    outboundBytes: normalized.filter(outbound).reduce((sum, event) => sum + (event.bytesOut ?? 0), 0),
    reviewContexts: coverage.reviewContexts.length };
  return { findings: result, baselines: baseline, coverage, metrics };
}

export function activityContext(events) {
  const ordered = [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  return {
    infrastructures: unique(ordered.map(event => event.infrastructure)).slice(0, 16),
    targets: unique(ordered.map(event => event.destinationIp)).slice(0, 16),
    ports: unique(ordered.map(event => event.port)).sort((a, b) => a - b).slice(0, 128),
    countries: unique(ordered.map(event => event.sourceCountry)).slice(0, 8),
    allowed: ordered.filter(event => disposition(event) === "allowed").slice(-5).map(event => ({
      eventId: event.id, index: event.index, timestamp: event.timestamp, action: event.action, outcome: event.outcome,
      sourceIp: event.sourceIp, destinationIp: event.destinationIp, port: event.port, infrastructure: event.infrastructure
    }))
  };
}

export function liveScanCandidates(raw, config, from, to) {
  const policy = settings(config);
  return raw.aggregations.sources.buckets.filter(bucket => {
    if (addressScope(bucket.key) !== "public" || DNS_RESOLVERS.has(ip(bucket.key)) || bucket.doc_count < policy.scanMinAttempts) return false;
    const ports = bucket.ports.buckets.filter(item => Number.isInteger(item.key) && item.key > 0 && item.key <= 65535);
    const targets = bucket.targets.buckets.filter(item => ip(item.key));
    if (ports.length < policy.scanMinPorts && targets.length < policy.scanMinTargets) return false;
    // A scoped exception cannot safely be subtracted from an all-source aggregate.
    if ((config.exceptions || []).some(e => e.enabled !== false && e.indicatorType === "ip" && ip(e.indicatorValue) === ip(bucket.key)
      && (!e.expiresAt || Date.parse(e.expiresAt) > Date.parse(to)))) return false;
    const proof = bucket.proof.hits.hits.map(hit => normalizeEvent(hit, config)).filter(event => event && event.sourceIp === ip(bucket.key)
      && event.timestamp >= from && event.timestamp <= to && disposition(event) === "blocked" && event.category.includes("network"));
    if (proof.length && ports.length && ports.every(item => item.key >= 49152) && proof.every(event => {
      const port = firstNumber(event.rawFields, "source.port", 65535);
      return port !== null && port > 0 && port <= 1024;
    })) return false;
    return proof.length > 0;
  });
}

export function analyzeLiveScans(raw, context, config, reputations, from, to) {
  const findings = new Map();
  for (const bucket of liveScanCandidates(raw, config, from, to)) {
    const source = ip(bucket.key);
    const blocked = bucket.proof.hits.hits.map(hit => normalizeEvent(hit, config)).filter(event => event && event.sourceIp === source
      && event.timestamp >= from && event.timestamp <= to && disposition(event) === "blocked");
    const accepted = (context?.aggregations?.sources?.buckets || []).filter(item => ip(item.key) === source)
      .flatMap(item => item.proof.hits.hits).map(hit => normalizeEvent(hit, config))
      .filter(event => event && event.sourceIp === source && event.timestamp >= from && event.timestamp <= to && disposition(event) === "allowed");
    const ports = bucket.ports.buckets.map(item => item.key).filter(port => Number.isInteger(port) && port > 0 && port <= 65535);
    const targets = bucket.targets.buckets.map(item => ip(item.key)).filter(Boolean);
    const contextDetails = activityContext([...blocked, ...accepted]);
    const reputation = reputationFor(reputations, "ip", source);
    addFinding(findings, {
      category: "scan", title: accepted.length ? "Active probing with accepted network activity" : "Active blocked network probing",
      indicatorType: "ip", indicator: source, scope: source, behaviorScore: accepted.length ? 90 : 80, confidence: 90,
      severity: accepted.length ? "high" : "medium", reputation,
      activity: { ...contextDetails, ports: unique([...ports, ...contextDetails.ports]).sort((a, b) => a - b), targets: unique([...targets, ...contextDetails.targets]), from, to, blockedAttemptsLowerBound: bucket.doc_count,
        portCountLowerBound: ports.length, targetCountLowerBound: targets.length, countsExact: bucket.doc_count_error_upper_bound === 0 },
      reasons: [`At least ${bucket.doc_count} blocked network events from this public source between ${from} and ${to}, across at least ${targets.length} targets and ${ports.length} ports.`,
        ...(contextDetails.infrastructures.length ? [`Evidence infrastructure: ${contextDetails.infrastructures.join(", ")}.`] : []),
        ...(contextDetails.countries.length ? [`Source GeoIP recorded in evidence: ${contextDetails.countries.join(", ")}.`] : []),
        ...accepted.map(event => `${event.action || event.outcome} to ${event.destinationIp || "unknown target"}:${event.port || "unknown port"} at ${event.timestamp}.`)],
      limitations: ["Counts and distinct targets/ports are lower bounds from bounded source buckets, not a complete inventory.",
        "Blocked fanout is consistent with probing, but configuration faults and legitimate traffic also require analyst review; intent is not proven.",
        "Evidence is sampled. Accepted activity from the same source in this window is context, not proof that a scanned port was exploited.",
        "GeoIP, when present, is log-supplied attribution, not proof of the operator's location.",
        ...(context ? [] : ["Accepted-connection context was unavailable."])]
    }, [...blocked, ...accepted], config, event => `${proofReason(event)} to ${event.destinationIp || "unknown target"}:${event.port || "unknown port"} via ${event.infrastructure || "unknown infrastructure"}`);
  }
  return [...findings.values()].map(({ _eventKeys, ...finding }) => ({ ...finding, eventKeys: [..._eventKeys] }));
}

export function analyzeSiemAlerts(events, config) {
  const findings = new Map();
  for (const event of events) {
    const severity = firstString(event.rawFields, "kibana.alert.severity");
    const rule = firstString(event.rawFields, "kibana.alert.rule.name");
    if (!strings(event.rawFields, "event.kind").includes("alert") || !["high", "critical"].includes(severity) || !rule) continue;
    const indicator = event.hashes[0] || event.domains[0] || (addressScope(event.sourceIp) === "public" ? event.sourceIp : event.destinationIp) || event.identity;
    if (!indicator) continue;
    const type = event.hashes[0] ? "hash" : event.domains[0] ? "domain" : isIP(indicator) ? "ip" : "identity";
    addFinding(findings, { category: "siem_alert", title: `ELK security alert: ${rule}`, indicatorType: type, indicator,
      scope: JSON.stringify([rule, event.host, event.infrastructure]), severity, behaviorScore: 85, confidence: 85,
      activity: activityContext([event]), reasons: [`ELK supplied a ${severity}-severity security alert for rule ${rule} at ${event.timestamp}.`],
      limitations: ["Severity and rule assessment are supplied by ELK; SOC Watch has not independently proved this alert's conclusion."]
    }, [event], config);
  }
  return [...findings.values()].map(({ _eventKeys, ...finding }) => ({ ...finding, eventKeys: [..._eventKeys] }));
}
