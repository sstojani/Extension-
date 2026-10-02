import { analyzeEvidence } from "./intelligence.mjs";
import { Store } from "./store.mjs";
import { runtimeConfig } from "./config.mjs";
import { resolve } from "node:path";

const now = "2026-10-02T12:00:00.000Z", hash = "a".repeat(64);
const event = (id, second, source = {}) => ({ _index: "offline-fixture", _id: id, _source: {
  "@timestamp": new Date(Date.parse(now) - 3600000 + second * 1000).toISOString(),
  host: { name: "fixture-workstation" }, observer: { name: "fixture-firewall" }, ...source
} });
const normalNetwork = { source: { ip: "192.168.1.20", bytes: 1000 }, destination: { ip: "1.1.1.1", port: 53 }, event: { category: "network", action: "allowed", outcome: "success" } };
const auth = (outcome) => ({ source: { ip: "51.20.30.40" }, user: { name: "fixture-user" }, event: { category: "authentication", action: "login", outcome } });
const scenarios = [
  { name: "Routine public DNS", expected: [], events: Array.from({ length: 80 }, (_,i) => event(`dns-${i}`, i * 20, normalNetwork)) },
  { name: "Routine internal traffic", expected: [], events: Array.from({ length: 80 }, (_,i) => event(`internal-${i}`, i * 20, { ...normalNetwork, destination: { ip: "10.0.0.10", port: 445 } })) },
  { name: "Ordinary login", expected: [], events: [event("ordinary", 30, auth("success"))] },
  { name: "Failures before success", expected: ["authentication"], events: [...Array.from({ length: 10 }, (_,i) => event(`failure-${i}`, i * 10, auth("failure"))), event("success", 110, auth("success"))] },
  { name: "Failures after success", expected: [], events: [event("earlier-success", 0, auth("success")), ...Array.from({ length: 10 }, (_,i) => event(`after-${i}`, 20 + i * 10, auth("failure")))] },
  { name: "Public cross-infrastructure scan", expected: ["scan"], events: Array.from({ length: 30 }, (_,i) => event(`scan-${i}`, i, { source: { ip: "51.20.30.40" }, destination: { ip: `10.0.0.${i % 6 + 1}`, port: 22 }, observer: { name: `firewall-${i % 3}` }, event: { category: "network", action: "denied", outcome: "failure" } })) },
  { name: "Malicious hash execution", expected: ["intelligence"], reputations: { [`hash|${hash}`]: { verdict: "malicious", malicious: 10 } }, events: [event("process", 0, { process: { hash: { sha256: hash }, entity_id: "process-1" }, event: { category: "process", action: "start", type: "start", outcome: "success" } })] },
  { name: "Undetected hash is not malicious", expected: [], reputations: { [`hash|${hash}`]: { verdict: "undetected" } }, events: [event("file", 0, { file: { hash: { sha256: hash } }, event: { category: "file", action: "created", outcome: "success" } })] }
];
let truePositive = 0, falsePositive = 0, falseNegative = 0;
const results = scenarios.map(s => {
  const report = analyzeEvidence(s.events, { reputations: s.reputations || {}, now });
  const actual = [...new Set(report.findings.map(f => f.category))];
  const tp = actual.filter(c => s.expected.includes(c)).length, fp = actual.filter(c => !s.expected.includes(c)).length, fn = s.expected.filter(c => !actual.includes(c)).length;
  truePositive += tp; falsePositive += fp; falseNegative += fn;
  return { name: s.name, expected: s.expected, actual, pass: fp === 0 && fn === 0, events: s.events.length };
});
const evaluation = { available: true, evaluatedAt: new Date().toISOString(), dataset: "Synthetic offline regression scenarios; not production precision/recall", scenarios: results,
  truePositive, falsePositive, falseNegative, fixturePrecision: truePositive / (truePositive + falsePositive || 1), fixtureRecall: truePositive / (truePositive + falseNegative || 1) };
console.log(JSON.stringify(evaluation, null, 2));
const store = new Store(resolve(runtimeConfig().dataDir, "soc-watch.sqlite"));
store.set("evaluation", evaluation); store.close();
if (results.some(r => !r.pass)) process.exitCode = 1;
