export type AlertIndicatorType = "ip" | "domain" | "hash" | "identity";

export type ThreatAlertRule = {
  id: string;
  name: string;
  indicatorType: AlertIndicatorType;
  indicatorValue: string;
  minScore: number;
  enabled: boolean;
  createdAt: string;
};

type AlertGti = {
  verdict?: string | undefined;
  threatScore?: number | undefined;
  malicious?: number | undefined;
  suspicious?: number | undefined;
};

export type AlertableFinding = {
  ip: string;
  role: "source" | "destination";
  direction: "inbound" | "outbound" | "internal" | "external" | "unknown";
  score: number;
  sourceIp: string;
  destinationIp: string;
  events: number;
  dangerousPorts: number[];
  actions: Array<{ key: string; count: number }>;
  deniedEvents: number;
  outboundEvents: number;
  matchedKeywords: string[];
  reasons: string[];
  latest?: { action?: string | undefined; message?: string | undefined };
  gti?: AlertGti | undefined;
  active?: boolean | undefined;
};

export type AlertableIndicator = {
  value: string;
  type: "domain" | "hash";
  score: number;
  events: number;
  reasons: string[];
  gti?: AlertGti | undefined;
  active?: boolean | undefined;
};

export type AlertableIdentity = {
  identity: string;
  score: number;
  severity: "critical" | "high" | "medium" | "low";
  events: number;
  failedEvents: number;
  successfulEvents: number;
  sourceIp: string;
  destinationIp: string;
  promoted: boolean;
  reasons: string[];
  active?: boolean | undefined;
};

export type ThreatAlertCandidate = {
  fingerprint: string;
  title: string;
  category: "watched_ioc" | "access_risk" | "outbound_risk" | "malicious_indicator" | "identity_risk";
  severity: "critical" | "high";
  indicatorType: AlertIndicatorType;
  indicator: string;
  sourceIp?: string;
  destinationIp?: string;
  score: number;
  events: number;
  reasons: string[];
  ruleIds: string[];
  ruleNames: string[];
};

export function normalizeAlertIndicator(value: string): string {
  return value
    .trim()
    .replace(/\[\.\]|\(\.\)|\{\.}/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\s+/g, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

export function buildThreatAlertCandidates(
  report: { suspects?: AlertableFinding[]; suspiciousIndicators?: AlertableIndicator[]; identityAnomalies?: AlertableIdentity[] },
  rules: ThreatAlertRule[]
): ThreatAlertCandidate[] {
  const enabledRules = rules.filter((rule) => rule.enabled);
  const candidates: ThreatAlertCandidate[] = [];

  for (const finding of report.suspects ?? []) {
    if (finding.active === false) continue;
    const matchingRules = enabledRules.filter((rule) => rule.minScore <= finding.score && ruleMatchesFinding(rule, finding));
    const automaticCategory = automaticFindingCategory(finding);
    if (!automaticCategory && matchingRules.length === 0) continue;

    const watchedValue = matchingRules[0]?.indicatorValue;
    const indicator = watchedValue ?? finding.ip ?? finding.sourceIp;
    const category = automaticCategory ?? "watched_ioc";
    candidates.push({
      fingerprint: `${category}|${normalizeAlertIndicator(indicator)}|${normalizeAlertIndicator(finding.sourceIp)}|${normalizeAlertIndicator(finding.destinationIp)}`,
      title: category === "access_risk"
        ? "High-confidence access risk"
        : category === "outbound_risk"
          ? "High-confidence outbound risk"
          : "Watched IOC detected",
      category,
      severity: finding.score >= 100 ? "critical" : "high",
      indicatorType: matchingRules[0]?.indicatorType ?? "ip",
      indicator,
      sourceIp: finding.sourceIp,
      destinationIp: finding.destinationIp,
      score: finding.score,
      events: finding.events,
      reasons: finding.reasons,
      ruleIds: matchingRules.map((rule) => rule.id),
      ruleNames: matchingRules.map((rule) => rule.name)
    });
  }

  for (const indicator of report.suspiciousIndicators ?? []) {
    if (indicator.active === false) continue;
    const matchingRules = enabledRules.filter((rule) => rule.minScore <= indicator.score && ruleMatchesIndicator(rule, indicator));
    const malicious = isAdverseReputation(indicator.gti) && indicator.score >= 80;
    if (!malicious && matchingRules.length === 0) continue;
    const category = malicious ? "malicious_indicator" : "watched_ioc";
    candidates.push({
      fingerprint: `${category}|${indicator.type}|${normalizeAlertIndicator(indicator.value)}`,
      title: malicious ? "Malicious indicator detected" : "Watched IOC detected",
      category,
      severity: indicator.score >= 100 ? "critical" : "high",
      indicatorType: indicator.type,
      indicator: indicator.value,
      score: indicator.score,
      events: indicator.events,
      reasons: indicator.reasons,
      ruleIds: matchingRules.map((rule) => rule.id),
      ruleNames: matchingRules.map((rule) => rule.name)
    });
  }

  for (const identity of report.identityAnomalies ?? []) {
    if (identity.active === false) continue;
    const matchingRules = enabledRules.filter((rule) => (
      rule.indicatorType === "identity"
      && rule.minScore <= identity.score
      && normalizeAlertIndicator(rule.indicatorValue) === normalizeAlertIndicator(identity.identity)
    ));
    if ((!identity.promoted || identity.score < 55) && matchingRules.length === 0) continue;
    candidates.push({
      fingerprint: `identity_risk|${normalizeAlertIndicator(identity.identity)}|${normalizeAlertIndicator(identity.sourceIp)}`,
      title: "High-confidence identity risk",
      category: "identity_risk",
      severity: identity.score >= 80 ? "critical" : "high",
      indicatorType: "identity",
      indicator: identity.identity,
      sourceIp: identity.sourceIp,
      destinationIp: identity.destinationIp,
      score: identity.score,
      events: identity.events,
      reasons: identity.reasons,
      ruleIds: matchingRules.map((rule) => rule.id),
      ruleNames: matchingRules.map((rule) => rule.name)
    });
  }

  return [...new Map(candidates.map((candidate) => [candidate.fingerprint, candidate])).values()];
}

function automaticFindingCategory(finding: AlertableFinding): "access_risk" | "outbound_risk" | undefined {
  const riskyAuthenticationPorts = [22, 23, 3389, 445, 5900];
  const hasRiskyService = finding.dangerousPorts.some((port) => riskyAuthenticationPorts.includes(port));
  const failedAttempts = finding.deniedEvents || finding.actions
    .filter((action) => /fail|denied|blocked|drop|reject|invalid|auth/i.test(action.key))
    .reduce((total, action) => total + action.count, 0);
  const latest = `${finding.latest?.action ?? ""} ${finding.latest?.message ?? ""}`.toLowerCase();
  const successfulAuthentication = /(successful|succeeded|accepted password|authenticated|session opened)/.test(latest)
    && /(ssh|sshd|rdp|login|auth|session)/.test(latest);
  if (hasRiskyService && failedAttempts >= 20 && successfulAuthentication && isAdverseReputation(finding.gti)) {
    return "access_risk";
  }

  const outboundThreatLanguage = finding.matchedKeywords.some((keyword) => ["malware", "command_control", "exfiltration", "exploit"].includes(keyword));
  if (finding.role === "source" && finding.direction === "outbound" && finding.outboundEvents >= 20 && finding.score >= 80 && outboundThreatLanguage && isAdverseReputation(finding.gti)) {
    return "outbound_risk";
  }
  return undefined;
}

function isAdverseReputation(gti: AlertGti | undefined): boolean {
  if (!gti) return false;
  return /malicious|suspicious/i.test(gti.verdict ?? "")
    || (gti.threatScore ?? 0) >= 50
    || (gti.malicious ?? 0) >= 2
    || (gti.suspicious ?? 0) >= 4;
}

function ruleMatchesFinding(rule: ThreatAlertRule, finding: AlertableFinding): boolean {
  if (rule.indicatorType !== "ip") return false;
  const target = normalizeAlertIndicator(rule.indicatorValue);
  return [finding.ip, finding.sourceIp, finding.destinationIp].some((value) => normalizeAlertIndicator(value) === target);
}

function ruleMatchesIndicator(rule: ThreatAlertRule, indicator: AlertableIndicator): boolean {
  if (rule.indicatorType !== indicator.type) return false;
  return normalizeAlertIndicator(rule.indicatorValue) === normalizeAlertIndicator(indicator.value);
}
