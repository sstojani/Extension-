export const DETECTION_PACK_VERSION = "2.0.1";

export type DetectionCoverageRow = {
  id: string;
  label: string;
  description: string;
  techniques: string[];
  evidenceFields: string[];
  activeCount: number;
  status: "active" | "watching";
};

type DetectionPackDefinition = Omit<DetectionCoverageRow, "activeCount" | "status"> & {
  signalKeys: string[];
};

export const DETECTION_PACKS: DetectionPackDefinition[] = [
  {
    id: "external-hostile-behavior",
    label: "External hostile behavior",
    description: "Correlates public-source scanning, denied volume, risky services, and adverse reputation.",
    techniques: ["T1046", "T1110", "T1190"],
    evidenceFields: ["source.ip", "destination.port", "event.action", "gti/virustotal"],
    signalKeys: ["denied", "dangerous_ports", "external_sources"]
  },
  {
    id: "suspicious-outbound",
    label: "Suspicious outbound communication",
    description: "Looks for internal hosts communicating with public indicators or unusual external services.",
    techniques: ["T1041", "T1071", "T1105"],
    evidenceFields: ["source.ip", "destination.ip", "destination.domain", "destination.port"],
    signalKeys: ["outbound", "suspicious_outbound", "indicators"]
  },
  {
    id: "identity-abuse",
    label: "Credential attack evidence",
    description: "Requires authentication-scoped failures or unusual account activity before promotion.",
    techniques: ["T1078", "T1110", "T1021"],
    evidenceFields: ["user.name", "event.outcome", "source.ip", "host.name"],
    signalKeys: ["identity_auth"]
  },
  {
    id: "indicator-correlation",
    label: "Indicator correlation",
    description: "Checks domains and file hashes against configured reputation and threat-intelligence evidence.",
    techniques: ["T1583", "T1588"],
    evidenceFields: ["dns.question.name", "url.domain", "file.hash.*", "gti/virustotal"],
    signalKeys: ["indicators", "domain_hash"]
  }
];

export function buildDetectionCoverage(
  signals: Array<{ key: string; count: number }> = [],
  indicatorCount = 0,
  identityCount = 0,
  outboundCount = 0,
  deniedCount = 0,
  dangerousPortCount = 0
): DetectionCoverageRow[] {
  const counts = new Map(signals.map((signal) => [signal.key, signal.count]));
  counts.set("indicators", Math.max(indicatorCount, counts.get("indicators") ?? 0));
  counts.set("identity_auth", Math.max(identityCount, counts.get("identity_auth") ?? 0));
  counts.set("outbound", Math.max(outboundCount, counts.get("outbound") ?? 0));
  counts.set("denied", Math.max(deniedCount, counts.get("denied") ?? 0));
  counts.set("dangerous_ports", Math.max(dangerousPortCount, counts.get("dangerous_ports") ?? 0));

  return DETECTION_PACKS.map((pack) => {
    const activeCount = pack.signalKeys.reduce((sum, key) => sum + (counts.get(key) ?? 0), 0);
    return {
      id: pack.id,
      label: pack.label,
      description: pack.description,
      techniques: pack.techniques,
      evidenceFields: pack.evidenceFields,
      activeCount,
      status: activeCount > 0 ? "active" : "watching"
    };
  });
}
