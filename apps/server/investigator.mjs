import { normalizeEvent } from "./intelligence.mjs";

export async function investigateFinding(finding, elastic, config, reputations) {
  const steps = [], facts = [], limitations = [...(finding.limitations || [])], events = [];
  for (const ref of finding.evidence.slice(-5)) {
    try {
      const hit = await elastic.evidence(ref.index, ref.eventId);
      const e = normalizeEvent(hit, config);
      if (e) events.push(e);
      steps.push({ tool: "read_evidence", index: ref.index, id: ref.eventId, status: "complete" });
    } catch (error) { steps.push({ tool: "read_evidence", index: ref.index, id: ref.eventId, status: "failed" }); limitations.push(error.message); }
  }
  const rule = { indicatorType: finding.indicatorType, indicatorValue: finding.indicator, includeSubdomains: false, requireSuccess: false, scope: {} };
  if (finding.indicatorType !== "identity" || finding.indicator) {
    const from = new Date(Date.parse(finding.firstSeen) - 15 * 60000).toISOString();
    const to = new Date(Date.parse(finding.lastSeen) + 15 * 60000).toISOString();
    try {
      const context = await elastic.watched({ ...config, pageSize: 500 }, rule, from, to);
      events.push(...context.hits.map(h => normalizeEvent(h, config)).filter(Boolean));
      steps.push({ tool: "indicator_context", from, to, matched: context.total, sampled: context.hits.length, status: "complete" });
      if (context.total > context.hits.length) limitations.push(`Context is sampled: ${context.hits.length} of ${context.total} events.`);
    } catch (error) { limitations.push(error.message); steps.push({ tool: "indicator_context", status: "failed" }); }
  }
  const timeline = [...new Map(events.map(e => [`${e.index}|${e.id}`, e])).values()].sort((a,b) => a.timestamp.localeCompare(b.timestamp));
  const assets = [...new Set(timeline.map(e => e.host || e.destinationIp).filter(Boolean))];
  const users = [...new Set(timeline.map(e => e.identity).filter(Boolean))];
  const denied = timeline.filter(e => /fail|denied|blocked|drop|reject/i.test(`${e.outcome} ${e.action}`)).length;
  facts.push({ claim: `${timeline.length} referenced/context events retrieved.`, evidenceIds: timeline.map(e => e.id) });
  facts.push({ claim: `${assets.length} observed host/target identifiers and ${users.length} user identifiers.`, evidenceIds: timeline.map(e => e.id) });
  if (denied) facts.push({ claim: `${denied} retrieved events record a failure or blocked action; those do not prove successful access.`, evidenceIds: timeline.filter(e => /fail|denied|blocked|drop|reject/i.test(`${e.outcome} ${e.action}`)).map(e => e.id) });
  const reputation = reputations[`${finding.indicatorType}|${finding.indicator}`] || finding.reputation;
  limitations.push("This bounded investigation is evidence correlation, not a claim that a host is compromised. Missing endpoint, payload or identity telemetry can prevent a conclusion.");
  return { id: finding.id, status: steps.some(s => s.status === "failed") ? "reduced" : "complete", completedAt: new Date().toISOString(),
    briefing: `${finding.title}. ${finding.reasons.join(" ")} Reputation: ${reputation?.verdict || "unknown"}. ${timeline.length} events retrieved for review.`,
    facts, limitations: [...new Set(limitations)], steps, assets, users, reputation,
    timeline: timeline.slice(-100).map(e => ({ eventId: e.id, index: e.index, timestamp: e.timestamp, action: e.action, outcome: e.outcome, host: e.host, identity: e.identity, sourceIp: e.sourceIp, destinationIp: e.destinationIp, port: e.port, process: e.process, domains: e.domains, hashes: e.hashes })) };
}
