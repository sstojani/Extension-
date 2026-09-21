export type IdentitySeverity = "critical" | "high" | "medium" | "low";

export type IdentityObservation = {
  identity: string;
  rawIdentity: string;
  identityType: "email" | "account" | "service_account";
  sourceField: string;
  encodedValue: boolean;
  sourceIp: string;
  destinationIp: string;
  service: string;
  events: number;
  authenticationEvents: number;
  failedEvents: number;
  successfulEvents: number;
  infrastructureCount: number;
  infrastructures: string[];
  sourceIpCount: number;
  sourceIps: string[];
  destinationPorts: number[];
  actions: Array<{ key: string; count: number }>;
  datasets: Array<{ key: string; count: number }>;
  firstSeen?: string;
  lastSeen?: string;
};

export type IdentityBaselineRecord = {
  identity: string;
  firstSeen: string;
  lastSeen: string;
  observations: number;
  observationDays: string[];
  hours: number[];
  sourceIps: string[];
  infrastructures: string[];
  typicalMaxEvents: number;
};

export type IdentityBaseline = Record<string, IdentityBaselineRecord>;

export type IdentityAnomaly = IdentityObservation & {
  score: number;
  severity: IdentitySeverity;
  reasons: string[];
  firstObserved: boolean;
  baselineObservations: number;
  offHours: boolean;
  promoted: boolean;
};

const SERVICE_ACCOUNT_TOKENS = [
  "admin",
  "backup",
  "batch",
  "bot",
  "daemon",
  "logrhythm",
  "monitor",
  "root",
  "scanner",
  "service",
  "svc",
  "system",
  "test"
];

const NON_PUBLIC_REPUTATION_DOMAIN_SUFFIXES = [
  "arpa",
  "corp",
  "example",
  "example.com",
  "example.net",
  "example.org",
  "home",
  "home.arpa",
  "internal",
  "intranet",
  "invalid",
  "lan",
  "local",
  "localdomain",
  "localhost",
  "private",
  "test"
];

export function normalizeIdentityTelemetryValue(raw: string): { value: string; encodedValue: boolean } {
  let value = raw.trim();
  let encodedValue = false;

  // Telemetry pipelines sometimes serialize Python byte strings inside another
  // quoted value, for example `"b'host.example'"`. Unwrap a few safe layers.
  for (let depth = 0; depth < 4; depth += 1) {
    const bytesMatch = value.match(/^b(['"])([\s\S]*)\1$/i);
    if (bytesMatch) {
      value = (bytesMatch[2] ?? "").trim();
      encodedValue = true;
      continue;
    }
    const quotedMatch = value.match(/^(['"])([\s\S]*)\1$/);
    if (!quotedMatch) break;
    value = (quotedMatch[2] ?? "").trim();
  }
  return { value: value.trim().toLowerCase(), encodedValue };
}

export function classifyIdentityValue(raw: string, allowAccount = false): {
  value: string;
  type: IdentityObservation["identityType"];
  encodedValue: boolean;
} | undefined {
  const normalized = normalizeIdentityTelemetryValue(raw);
  if (!normalized.value || normalized.value.length > 320 || /[\s<>]/.test(normalized.value)) return undefined;
  const emailLike = /^[^@\s]{1,128}@[a-z0-9](?:[a-z0-9._-]{0,189}[a-z0-9])?$/i.test(normalized.value);
  if (!emailLike && !allowAccount) return undefined;
  if (!emailLike && !/^[a-z0-9][a-z0-9._\\$@-]{0,127}$/i.test(normalized.value)) return undefined;
  const localPart = normalized.value.split("@")[0] ?? normalized.value;
  const serviceStyle = SERVICE_ACCOUNT_TOKENS.some((token) => (
    localPart === token
      || localPart.startsWith(`${token}.`)
      || localPart.startsWith(`${token}_`)
      || localPart.startsWith(`${token}-`)
      || localPart.startsWith(`${token}$`)
  ));
  return {
    value: normalized.value,
    type: serviceStyle ? "service_account" : emailLike ? "email" : "account",
    encodedValue: normalized.encodedValue
  };
}

export function normalizeReputationDomain(raw: string): string | undefined {
  const normalized = normalizeIdentityTelemetryValue(raw).value;
  const value = normalized.endsWith(".") ? normalized.slice(0, -1) : normalized;
  if (!value || value.includes("@") || value.length > 253) return undefined;
  const labels = value.split(".");
  if (labels.length < 2) return undefined;
  if (labels.some((label) => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/i.test(label))) return undefined;
  const suffix = labels.at(-1) ?? "";
  if (!/[a-z]/i.test(suffix) || suffix.length < 2) return undefined;
  if (NON_PUBLIC_REPUTATION_DOMAIN_SUFFIXES.some((blocked) => value === blocked || value.endsWith(`.${blocked}`))) {
    return undefined;
  }
  return value;
}

export function normalizeReputationHash(raw: string): string | undefined {
  const { value } = normalizeIdentityTelemetryValue(raw);
  return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value) ? value : undefined;
}

export function assessIdentityObservations(
  observations: IdentityObservation[],
  baseline: IdentityBaseline,
  observedAt: string
): { findings: IdentityAnomaly[]; baseline: IdentityBaseline } {
  const nextBaseline: IdentityBaseline = { ...baseline };
  const findings = observations.map((observation) => assessIdentityObservation(observation, baseline[identityKey(observation.identity)]));

  for (const finding of findings) {
    const key = identityKey(finding.identity);
    const prior = baseline[key];
    const observedHour = hourOf(finding.lastSeen ?? observedAt);
    const observedDay = dayOf(finding.lastSeen ?? observedAt);
    const learnContext = isSafeBaselineObservation(finding);
    const observationDays = learnContext && observedDay
      ? uniqueStrings([...(prior?.observationDays ?? []), observedDay], 45)
      : prior?.observationDays ?? [];
    nextBaseline[key] = {
      identity: finding.identity,
      firstSeen: prior?.firstSeen ?? finding.firstSeen ?? observedAt,
      lastSeen: finding.lastSeen ?? observedAt,
      observations: Math.min(10_000, (prior?.observations ?? 0) + (learnContext ? 1 : 0)),
      observationDays,
      hours: learnContext ? uniqueNumbers([...(prior?.hours ?? []), ...(observedHour === undefined ? [] : [observedHour])], 24) : prior?.hours ?? [],
      sourceIps: learnContext ? uniqueStrings([...(prior?.sourceIps ?? []), ...finding.sourceIps], 32) : prior?.sourceIps ?? [],
      infrastructures: learnContext ? uniqueStrings([...(prior?.infrastructures ?? []), ...finding.infrastructures], 32) : prior?.infrastructures ?? [],
      typicalMaxEvents: learnContext ? Math.max(prior?.typicalMaxEvents ?? 0, finding.events) : prior?.typicalMaxEvents ?? 0
    };
  }

  const cutoff = Date.parse(observedAt) - 30 * 24 * 60 * 60 * 1000;
  const retained = Object.fromEntries(Object.entries(nextBaseline)
    .filter(([, item]) => !Number.isFinite(cutoff) || Date.parse(item.lastSeen) >= cutoff)
    .sort(([, left], [, right]) => Date.parse(right.lastSeen) - Date.parse(left.lastSeen))
    .slice(0, 2_000));
  return {
    findings: findings.filter((finding) => finding.score >= 20).sort((left, right) => right.score - left.score || right.events - left.events),
    baseline: retained
  };
}

function assessIdentityObservation(observation: IdentityObservation, prior?: IdentityBaselineRecord): IdentityAnomaly {
  const reasons: string[] = [];
  let score = 0;
  let evidenceFamilies = 0;
  const explicitCredentialAttack = hasExplicitCredentialAttackEvidence(observation.actions);

  if (explicitCredentialAttack) {
    score += 18;
    evidenceFamilies += 1;
    reasons.push("Authentication telemetry explicitly identifies a credential attack pattern");
  }

  const strongFailureEvidence = observation.failedEvents >= 20;
  if (observation.failedEvents >= 100) {
    score += 42;
    evidenceFamilies += 1;
    reasons.push(`${observation.failedEvents} failed authentication events`);
  } else if (observation.failedEvents >= 20) {
    score += 30;
    evidenceFamilies += 1;
    reasons.push(`${observation.failedEvents} failed authentication events`);
  } else if (observation.failedEvents >= 5) {
    score += 18;
    evidenceFamilies += 1;
    reasons.push(`${observation.failedEvents} repeated authentication failures`);
  }

  if (observation.failedEvents >= 5 && observation.successfulEvents > 0) {
    score += 10;
    reasons.push("Failures and successes occurred in the same window; ordering is not verified");
  }
  if (observation.sourceIpCount >= 5) {
    score += 22;
    evidenceFamilies += 1;
    reasons.push(`Account used from ${observation.sourceIpCount} source IPs`);
  } else if (observation.sourceIpCount >= 2) {
    score += 8;
    reasons.push(`Account used from ${observation.sourceIpCount} source IPs`);
  }
  if (observation.infrastructureCount >= 5) {
    score += 20;
    evidenceFamilies += 1;
    reasons.push(`Account observed in ${observation.infrastructureCount} infrastructures`);
  } else if (observation.infrastructureCount >= 2) {
    score += 8;
    reasons.push(`Account observed in ${observation.infrastructureCount} infrastructures`);
  }

  const observedHour = hourOf(observation.lastSeen);
  const offHours = observedHour !== undefined && (observedHour < 6 || observedHour >= 22);
  if (offHours && observation.authenticationEvents > 0) {
    score += 8;
    reasons.push("Authentication activity outside business hours");
  }
  if (!prior) {
    score += 8;
    reasons.push("Identity not observed by earlier Threat Radar scans");
  }
  if (observation.identityType === "service_account") {
    score += 6;
    reasons.push("Service-style or non-human account name");
  }
  if (observation.encodedValue) {
    score += 4;
    reasons.push("Data-quality signal: identity arrived in an encoded byte-string format");
  }
  if (observation.sourceField.includes("domain")) {
    score += 4;
    reasons.push(`Data-quality signal: account-like value stored in ${observation.sourceField}`);
  }

  const priorObservationDays = prior?.observationDays ?? [];
  const matureBaseline = Boolean(prior && prior.observations >= 3 && priorObservationDays.length >= 3);
  let learnedContextSignals = 0;
  if (matureBaseline && prior) {
    const newSources = observation.sourceIps.filter((source) => !prior.sourceIps.includes(source));
    if (newSources.length > 0 && prior.sourceIps.length > 0) {
      score += 18;
      evidenceFamilies += 1;
      learnedContextSignals += 1;
      reasons.push(`New source IP for this identity: ${newSources.slice(0, 3).join(", ")}`);
    }
    const newInfrastructure = observation.infrastructures.filter((item) => !prior.infrastructures.includes(item));
    if (newInfrastructure.length > 0 && prior.infrastructures.length > 0) {
      score += 15;
      evidenceFamilies += 1;
      learnedContextSignals += 1;
      reasons.push(`New infrastructure for this identity: ${newInfrastructure.slice(0, 3).join(", ")}`);
    }
    if (observedHour !== undefined && prior.hours.length > 0 && !isNearLearnedHour(observedHour, prior.hours)) {
      score += 14;
      evidenceFamilies += 1;
      learnedContextSignals += 1;
      reasons.push("Activity outside this identity's learned hours");
    }
    if (prior.typicalMaxEvents >= 5 && observation.events >= Math.max(20, prior.typicalMaxEvents * 4)) {
      score += 16;
      evidenceFamilies += 1;
      learnedContextSignals += 1;
      reasons.push(`Activity volume is above the learned baseline of ${prior.typicalMaxEvents}`);
    }
  }

  const promoted = score >= 65
    && evidenceFamilies >= 2
    && ((explicitCredentialAttack
      && strongFailureEvidence
      && (observation.sourceIpCount >= 2 || observation.infrastructureCount >= 2 || observation.successfulEvents > 0))
      || (matureBaseline && learnedContextSignals >= 2 && strongFailureEvidence));
  return {
    ...observation,
    score,
    severity: severityForScore(score),
    reasons,
    firstObserved: !prior,
    baselineObservations: prior?.observations ?? 0,
    offHours,
    promoted
  };
}

function hasExplicitCredentialAttackEvidence(actions: Array<{ key: string; count: number }>): boolean {
  return actions.some(({ key, count }) => count >= 5 && /(?:brute.?force|password.?spray|credential.?stuff|failed.?password|invalid.?user|authentication.?failed|login.?failed|logon.?failed|ssh.?login.?failed)/i.test(key));
}

function identityKey(value: string): string {
  return value.trim().toLowerCase();
}

function hourOf(value?: string): number | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.getHours() : undefined;
}

function dayOf(value?: string): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return undefined;
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function isSafeBaselineObservation(finding: IdentityAnomaly): boolean {
  return finding.authenticationEvents > 0
    && finding.successfulEvents > 0
    && finding.failedEvents === 0
    && !finding.encodedValue
    && !finding.sourceField.includes("domain")
    && !finding.promoted;
}

function isNearLearnedHour(hour: number, learnedHours: number[]): boolean {
  return learnedHours.some((learned) => {
    const distance = Math.abs(hour - learned);
    return Math.min(distance, 24 - distance) <= 1;
  });
}

function severityForScore(score: number): IdentitySeverity {
  return score >= 80 ? "critical" : score >= 55 ? "high" : score >= 25 ? "medium" : "low";
}

function uniqueStrings(values: string[], limit: number): string[] {
  return [...new Set(values.filter(Boolean))].slice(-limit);
}

function uniqueNumbers(values: number[], limit: number): number[] {
  return [...new Set(values.filter((value) => Number.isInteger(value) && value >= 0 && value <= 23))].slice(-limit);
}
