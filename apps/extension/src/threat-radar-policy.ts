import {
  DEFAULT_THREAT_RADAR_CARD_RULES,
  DEFAULT_THREAT_RADAR_RISKY_PORTS,
  DEFAULT_THREAT_RADAR_SIGNAL_RULES,
  threatRadarAgentConfigSchema,
  type ThreatRadarAgentConfig,
  type ThreatRadarCardId,
  type ThreatRadarCardRule,
  type ThreatRadarSignalRule
} from "@soc-watch/protocol";

export function normalizeThreatRadarAgentConfig(value: unknown): ThreatRadarAgentConfig {
  const parsed = threatRadarAgentConfigSchema.parse(value ?? {});
  return {
    ...parsed,
    historyRetentionHours: parsed.historyRetentionHours,
    riskyPorts: [...new Set(parsed.riskyPorts)].sort((left, right) => left - right),
    signalRules: mergeSignalRules(parsed.signalRules),
    cardRules: mergeCardRules(parsed.cardRules)
  };
}

export function getThreatRadarCardRule(
  config: Pick<ThreatRadarAgentConfig, "cardRules">,
  id: ThreatRadarCardId
): ThreatRadarCardRule {
  return config.cardRules.find((rule) => rule.id === id)
    ?? DEFAULT_THREAT_RADAR_CARD_RULES.find((rule) => rule.id === id)
    ?? { id, enabled: true, minScore: 0, query: "" };
}

export function enabledThreatSignalRules(
  config?: Pick<ThreatRadarAgentConfig, "signalRules">
): ThreatRadarSignalRule[] {
  return mergeSignalRules(config?.signalRules ?? DEFAULT_THREAT_RADAR_SIGNAL_RULES)
    .filter((rule) => rule.enabled);
}

export function threatRadarRiskyPorts(
  config?: Pick<ThreatRadarAgentConfig, "riskyPorts">
): number[] {
  const ports = config?.riskyPorts ?? DEFAULT_THREAT_RADAR_RISKY_PORTS;
  return [...new Set(ports)].sort((left, right) => left - right);
}

function mergeSignalRules(rules: ThreatRadarSignalRule[]): ThreatRadarSignalRule[] {
  const byKey = new Map(rules.map((rule) => [rule.key, rule]));
  return DEFAULT_THREAT_RADAR_SIGNAL_RULES.map((fallback) => ({
    ...fallback,
    ...byKey.get(fallback.key)
  }));
}

function mergeCardRules(rules: ThreatRadarCardRule[]): ThreatRadarCardRule[] {
  const byId = new Map(rules.map((rule) => [rule.id, rule]));
  return DEFAULT_THREAT_RADAR_CARD_RULES.map((fallback) => ({
    ...fallback,
    ...byId.get(fallback.id)
  }));
}
