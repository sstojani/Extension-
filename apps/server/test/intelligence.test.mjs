import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeEvidence, normalizeEvent, eventIndicators } from "../intelligence.mjs";

const NOW = "2026-10-02T20:00:00.000Z";
const HASH = "a".repeat(64);
const PRIVATE = "10.0.0.7";
const PUBLIC = "45.77.22.99";

test("all explicit indicator arrays, client/server IPs and email identities survive normalization without inventing flow direction", () => {
  const event = normalizeEvent(hit("all-indicators", {
    "client.ip": ["invalid", "45.77.22.99"], "server.ip": "93.184.216.34",
    "source.domain": ["one.example.com", "two.example.com"], "user.email": "alice@example.com",
    "process.hash.md5": "b".repeat(32)
  }));
  assert.equal(event.sourceIp, null); assert.equal(event.destinationIp, null);
  assert.deepEqual(eventIndicators(event)[0][1], [PUBLIC, "93.184.216.34"]);
  assert.deepEqual(event.domains, ["one.example.com", "two.example.com"]);
  assert.equal(event.identity, "alice@example.com");
  assert.deepEqual(event.hashes, ["b".repeat(32)]);
  const finding = analyze([event], { reputations: { [`ip|${PUBLIC}`]: { verdict: "malicious" } } }).findings[0];
  assert.ok(finding); assert.match(finding.title, /sighting/);
});

function hit(id, fields = {}, time = "2026-10-02T10:00:00.000Z") {
  return { _id: id, _index: "security-2026.10", _source: { "@timestamp": time, ...fields } };
}

function network(id, fields = {}, time) {
  return hit(id, { "event.category": ["network"], "event.outcome": "success", "event.action": "allowed",
    "source.ip": PRIVATE, "destination.ip": PUBLIC, "destination.port": 443, "host.name": "workstation-1", "observer.name": "edge-a", ...fields }, time);
}

function auth(id, outcome, identity = "alice", source = PUBLIC, seconds = 0, fields = {}) {
  return hit(id, { "event.category": "authentication", "event.outcome": outcome, "user.name": identity,
    "source.ip": source, "destination.ip": PRIVATE, "host.name": "auth-server", ...fields },
  new Date(Date.parse("2026-10-02T10:00:00Z") + seconds * 1000).toISOString());
}

function analyze(events, options = {}) {
  return analyzeEvidence(events, { now: NOW, ...options });
}

function category(result, name) {
  return result.findings.filter((finding) => finding.category === name);
}

function train({ days = 7, peer = "93.184.216.34", bytes = 1_000_000, time = "10:00:00", host = "workstation-1", user = "alice" } = {}) {
  const events = Array.from({ length: days }, (_, index) => network(`history-${index}`, {
    "source.bytes": bytes, "destination.ip": peer, "user.name": user, "host.name": host
  }, `2026-09-${String(24 + index).padStart(2, "0")}T${time}.000Z`));
  return analyze(events).baselines;
}

function periodic({ peer = PUBLIC, count = 8, spacing = 60, fields = {} } = {}) {
  return Array.from({ length: count }, (_, index) => network(`periodic-${index}`, {
    "destination.ip": peer, "event.type": "start", ...fields
  }, new Date(Date.parse("2026-10-02T10:00:00Z") + index * spacing * 1000).toISOString()));
}

function scan({ count = 30, targets = 5, ports = 1, infrastructures = 2, source = PUBLIC, spacing = 1, fields = {} } = {}) {
  return Array.from({ length: count }, (_, index) => network(`scan-${index}`, {
    "source.ip": source, "destination.ip": `10.0.1.${index % targets + 1}`, "destination.port": ports === 1 ? 22 : 20 + index % ports,
    "event.action": "denied", "event.outcome": "failure", "observer.name": `edge-${index % infrastructures}`, ...fields
  }, new Date(Date.parse("2026-10-02T10:00:00Z") + index * spacing * 1000).toISOString()));
}

test("normalizes exact nested ECS fields, flattened keys and scalar arrays", () => {
  const raw = hit("nested", {
    source: [{ ip: ["invalid", PRIVATE], domain: ["FROM.Example."] , bytes: ["4096"] }],
    "destination.ip": [PUBLIC], destination: { domain: ["TO.Example."], port: ["443"], bytes: [1024] },
    "dns.question": [{ name: ["Lookup.Example.", "TO.Example."] }], url: { domain: "Web.Example" },
    "file.hash.sha256": [HASH.toUpperCase(), "invalid"], process: { hash: { sha256: [HASH] }, name: ["curl"], entity_id: ["proc-1"] },
    "user.name": ["alice"], host: { name: ["workstation-1"] }, observer: { name: ["edge-a"] },
    event: { action: ["allowed"], outcome: ["SUCCESS"], category: ["network", "process"] }, message: ["message"]
  });
  const event = normalizeEvent(raw);
  assert.equal(event.sourceIp, PRIVATE);
  assert.equal(event.destinationIp, PUBLIC);
  assert.equal(event.sourceDomain, "from.example");
  assert.equal(event.destinationDomain, "to.example");
  assert.deepEqual(event.domains, ["from.example", "to.example", "lookup.example", "web.example"]);
  assert.deepEqual(event.hashes, [HASH]);
  assert.equal(event.identity, "alice");
  assert.equal(event.host, "workstation-1");
  assert.equal(event.infrastructure, "edge-a");
  assert.equal(event.port, 443);
  assert.equal(event.outcome, "success");
  assert.equal(event.bytesOut, 4096);
  assert.equal(event.bytesIn, 1024);
  assert.equal(event.process, "curl");
  assert.equal(event.processEntityId, "proc-1");
  assert.equal(event.rawFields, raw._source);
  assert.deepEqual(Object.keys(event).sort(), ["id", "index", "timestamp", "sourceIp", "destinationIp", "sourceDomain", "destinationDomain",
    "ips", "domains", "hashes", "identity", "host", "infrastructure", "port", "action", "outcome", "category", "bytesOut", "bytesIn", "process", "processEntityId", "message", "rawFields"].sort());
});

test("does not infer indicators, identity, execution or byte direction from arbitrary names/messages", () => {
  const event = normalizeEvent(hit("unsafe", { name: "alice", ip: PUBLIC, hostname: "bad.example", sha256: HASH,
    "threat.indicator.ip": PUBLIC, "threat.indicator.file.hash.sha256": HASH, "client.ip": PRIVATE,
    "network.bytes": 99_000_000, message: `malware executed ${HASH} connected to ${PUBLIC}`, "event.category": "file" }));
  assert.equal(event.sourceIp, null);
  assert.equal(event.identity, null);
  assert.equal(event.host, null);
  assert.equal(event.bytesOut, null);
  assert.deepEqual(event.domains, []);
  assert.deepEqual(event.hashes, []);
  assert.equal(analyze([hit("only-message", event.rawFields)], { reputations: { [PUBLIC]: { verdict: "malicious" }, [HASH]: { verdict: "malicious" } } }).findings.length, 0);
});

test("validates timestamps, ports, bytes, IPs and domains without losing valid array entries", () => {
  assert.equal(normalizeEvent(hit("invalid", {}, "not-a-date")), null);
  assert.equal(normalizeEvent(hit("invalid-day", {}, "2026-02-30T10:00:00Z")), null);
  assert.equal(normalizeEvent({ _source: { "source.ip": PRIVATE } }), null);
  const event = normalizeEvent(hit("valid", { "@timestamp": ["bad", 1_790_935_200_000], "source.ip": ["bad", "2001:4860:4860:0:0:0:0:8888"],
    "destination.domain": ["https://bad.example/path", "OK.Example."], "source.bytes": [-1, "64"], "destination.port": 70000 }));
  assert.equal(event.timestamp, new Date(1_790_935_200_000).toISOString());
  assert.equal(event.sourceIp, "2001:4860:4860::8888");
  assert.equal(event.destinationDomain, "ok.example");
  assert.equal(event.bytesOut, 64);
  assert.equal(event.port, null);
  assert.equal(normalizeEvent(hit("epoch-string", {}, "1790935200000")).timestamp, new Date(1_790_935_200_000).toISOString());
  assert.equal(normalizeEvent(hit("iso-minutes", {}, "2026-10-02T10:00Z")).timestamp, "2026-10-02T10:00:00.000Z");
});

test("caller-selected timestamp/infrastructure fields survive analysis of normalized events", () => {
  const event = normalizeEvent({ _id: "custom", _index: "custom-index", _source: {
    time: ["2026-10-02T10:00:00Z"], tenant: { device: ["edge-custom"] }, "source.ip": PUBLIC
  } }, { timestampField: "time", infrastructureField: "tenant.device" });
  assert.equal(event.infrastructure, "edge-custom");
  const result = analyze([event], { reputations: { [PUBLIC]: { verdict: "malicious" } } });
  assert.equal(result.coverage.validEvents, 1);
  assert.equal(result.findings[0].evidence[0].eventId, "custom");
  assert.equal(result.findings[0].evidence[0].index, "custom-index");
});

test("synthetic event IDs are stable across source object key order", () => {
  const first = normalizeEvent({ _source: { "@timestamp": NOW, "source.ip": PRIVATE } });
  const second = normalizeEvent({ _source: { "source.ip": PRIVATE, "@timestamp": NOW } });
  assert.equal(first.id, second.id);
  assert.equal(analyze([first, second]).coverage.duplicateEvents, 1);
});

test("routine known DNS resolver traffic never becomes beaconing or exfiltration from volume/ports", () => {
  for (const resolver of ["1.1.1.1", "8.8.8.8", "9.9.9.9", "2001:4860:4860::8888"]) {
    for (const port of [53, 443, 853]) {
      const events = periodic({ peer: resolver, fields: { "destination.port": port, "source.bytes": 80_000_000 } });
      const result = analyze(events, { baselines: train() });
      assert.equal(result.findings.length, 0, `${resolver}:${port}`);
    }
  }
});

test("DNS queries to arbitrary peers cannot establish connection beacons or exfiltration", () => {
  const events = periodic({ fields: { "network.protocol": "dns", "dns.question.name": "bad.example", "source.bytes": 80_000_000 } });
  const result = analyze(events, { baselines: train(), reputations: { [PUBLIC]: { verdict: "malicious" }, "bad.example": { verdict: "malicious" } } });
  assert.equal(category(result, "beacon").length, 0);
  assert.equal(category(result, "exfiltration").length, 0);
  assert.ok(result.findings.every((finding) => finding.title.startsWith("DNS query")));
});

test("private-to-private routine traffic is not a threat based on bytes, timing or risky ports", () => {
  const events = periodic({ peer: "192.168.1.10", count: 40, fields: { "destination.port": 445, "source.bytes": 80_000_000 } });
  assert.equal(analyze(events, { baselines: train() }).findings.length, 0);
  assert.equal(analyze(scan({ source: "172.16.1.7", targets: 10 })).findings.length, 0);
});

test("auth correlates genuine ordered failures then success for the exact account and source", () => {
  const events = [...Array.from({ length: 10 }, (_, index) => auth(`f-${index}`, "failure", "alice", PUBLIC, index * 20)), auth("success", "success", "alice", PUBLIC, 210)];
  const result = analyze([...events].reverse());
  const finding = category(result, "authentication")[0];
  assert.equal(finding.indicatorType, "identity");
  assert.equal(finding.indicator, "alice");
  assert.equal(finding.sourceIp, PUBLIC);
  assert.equal(finding.count, 11);
  assert.equal(finding.firstSeen, events[0]._source["@timestamp"]);
  assert.equal(finding.lastSeen, events.at(-1)._source["@timestamp"]);
  assert.match(finding.evidence.at(-1).reason, /Allowed authentication success/);
});

test("auth does not join failures after success, different identities or different sources", () => {
  const failures = Array.from({ length: 10 }, (_, index) => auth(`failure-${index}`, "failure", "alice", PUBLIC, 10 + index));
  assert.equal(category(analyze([auth("success", "success"), ...failures]), "authentication").length, 0);
  assert.equal(category(analyze([...failures, auth("success", "success", "bob", PUBLIC, 40)]), "authentication").length, 0);
  assert.equal(category(analyze([...failures, auth("success", "success", "alice", "45.33.32.156", 40)]), "authentication").length, 0);
});

test("auth requires distinct preceding events within 15 minutes, including strict timestamp order", () => {
  const failures = Array.from({ length: 10 }, (_, index) => auth(`f-${index}`, "failure", "alice", PUBLIC, index));
  assert.equal(category(analyze([...failures, auth("late", "success", "alice", PUBLIC, 1000)]), "authentication").length, 0);
  assert.equal(category(analyze([...Array(10).fill(failures[0]), auth("success", "success", "alice", PUBLIC, 30)]), "authentication").length, 0);
  const equal = failures.map((event) => ({ ...event, _source: { ...event._source, "@timestamp": failures[0]._source["@timestamp"] } }));
  assert.equal(category(analyze([...equal, auth("success", "success")]), "authentication").length, 0);
  assert.equal(category(analyze([...failures.slice(0, 9), auth("success", "success", "alice", PUBLIC, 30)]), "authentication").length, 0);
});

test("auth successes consume their preceding failures and blocked success claims are excluded", () => {
  const failures = Array.from({ length: 10 }, (_, index) => auth(`f-${index}`, "failure", "alice", PUBLIC, index));
  const result = analyze([...failures, auth("first-success", "success", "alice", PUBLIC, 20), auth("second-success", "success", "alice", PUBLIC, 40)]);
  assert.equal(category(result, "authentication")[0].count, 11);
  const blocked = analyze([...failures, auth("blocked-success", "success", "alice", PUBLIC, 20, { "event.type": "denied" })]);
  assert.equal(category(blocked, "authentication").length, 0);
});

test("user domains separate accounts that share a name", () => {
  const failures = Array.from({ length: 10 }, (_, index) => auth(`f-${index}`, "failure", "alice", PUBLIC, index, { "user.domain": "A" }));
  assert.equal(category(analyze([...failures, auth("success", "success", "alice", PUBLIC, 20, { "user.domain": "B" })]), "authentication").length, 0);
  assert.equal(normalizeEvent(failures[0]).identity, "A\\alice");
});

test("unknown-reputation public multi-target scans produce an investigation with blocked proof", () => {
  const result = analyze(scan());
  const finding = category(result, "scan")[0];
  assert.equal(finding.indicator, PUBLIC);
  assert.equal(finding.reputation.verdict, "unknown");
  assert.equal(finding.severity, "medium");
  assert.equal(finding.count, 30);
  assert.ok(finding.evidence.every((proof) => proof.reason.startsWith("Blocked attempt")));
  assert.ok(finding.limitations.some((reason) => reason.includes("investigate")));
});

test("scans accept unique-port evidence OR unique-target evidence", () => {
  assert.equal(category(analyze(scan({ targets: 1, ports: 10 })), "scan").length, 1);
  assert.equal(category(analyze(scan({ targets: 5, ports: 1 })), "scan").length, 1);
  assert.equal(category(analyze(scan({ targets: 4, ports: 9 })), "scan").length, 0);
});

test("scans require thresholds, cross-infrastructure evidence and explicitly blocked attempts", () => {
  for (const events of [scan({ count: 29 }), scan({ infrastructures: 1 }), scan({ spacing: 40 }),
    scan({ fields: { "observer.name": null } }), scan({ fields: { "event.action": "allowed", "event.outcome": "success" } }),
    scan({ fields: { "event.action": "connection", "event.outcome": "failure" } })]) {
    assert.equal(category(analyze(events), "scan").length, 0);
  }
});

test("scan policy thresholds and risky ports are configurable", () => {
  const result = analyze(scan({ count: 6, targets: 3, fields: { "destination.port": 65000 } }), {
    config: { scanMinAttempts: 6, scanMinTargets: 3, scanMinPorts: 10, riskyPorts: [65000] }
  });
  assert.equal(category(result, "scan").length, 1);
  assert.ok(result.findings[0].reasons.some((reason) => reason.includes("65000")));
});

test("intelligence distinguishes malicious hash execution, prevention and file-only sightings", () => {
  const events = [
    hit("executed", { "event.category": "process", "event.type": "start", "process.hash.sha256": HASH, "process.entity_id": "proc-1", "host.name": "host-a" }),
    hit("blocked", { "event.category": "process", "event.type": ["start", "denied"], "event.outcome": "success", "process.hash.sha256": HASH, "host.name": "host-a" }),
    hit("sighting", { "event.category": "file", "file.hash.sha256": HASH, "host.name": "host-a" }),
    hit("unrelated-file", { "event.category": "process", "event.type": "start", "file.hash.sha256": HASH, "process.hash.sha256": "b".repeat(64), "host.name": "host-a" })
  ];
  const result = analyze(events, { reputations: { hash: { [HASH]: { verdict: "malicious", sources: ["feed-a"] } } } });
  const findings = category(result, "intelligence");
  assert.equal(findings.length, 3);
  const execution = findings.find((finding) => finding.title.startsWith("Execution"));
  assert.equal(execution.count, 1);
  assert.equal(execution.severity, "critical");
  assert.deepEqual(execution.reputation.sources, ["feed-a"]);
  assert.equal(findings.find((finding) => finding.title.startsWith("Blocked")).count, 1);
  assert.equal(findings.find((finding) => finding.title.endsWith("sighting")).count, 2);
  assert.ok(findings.every((finding) => finding.limitations.some((reason) => reason.includes("does not by itself establish compromise"))));
});

test("intelligence differentiates domain query, blocked activity and allowed connection", () => {
  const events = [
    network("dns", { "dns.question.name": "bad.example", "network.protocol": "dns", "destination.ip": "8.8.8.8", "destination.port": 53 }),
    network("blocked", { "destination.domain": "bad.example", "event.action": "blocked" }),
    network("connected", { "destination.domain": "bad.example", "event.type": "connection" })
  ];
  const result = analyze(events, { reputations: { "domain:bad.example": { verdict: "malicious", reference: "provided-reference" } } });
  assert.equal(result.findings.length, 3);
  assert.ok(result.findings.some((finding) => finding.title.startsWith("DNS query")));
  assert.ok(result.findings.some((finding) => finding.title.startsWith("Blocked")));
  assert.ok(result.findings.some((finding) => finding.title.startsWith("Allowed connection")));
  assert.equal(result.coverage.reputationMatchedIndicators, 1);
});

test("benign, undetected, unknown and unsupported reputation verdicts do not become intelligence alerts", () => {
  for (const verdict of ["benign", "undetected", "unknown", "bad", undefined]) {
    assert.equal(analyze([network("network")], { reputations: { [PUBLIC]: { verdict, score: 100, malicious: 100 } } }).findings.length, 0);
  }
  const result = analyze([network("suspicious")], { reputations: { [PUBLIC]: { verdict: "suspicious" } } });
  assert.equal(category(result, "intelligence").length, 1);
});

test("beaconing needs mature baseline AND rare peer unless there is adverse reputation", () => {
  const events = periodic();
  assert.equal(category(analyze(events), "beacon").length, 0);
  assert.equal(category(analyze(events, { baselines: train({ days: 6 }) }), "beacon").length, 0);
  assert.equal(category(analyze(events, { baselines: train() }), "beacon").length, 1);
  assert.equal(category(analyze(events, { baselines: train({ peer: PUBLIC }) }), "beacon").length, 0);
  const adverse = analyze(events, { reputations: { [PUBLIC]: { verdict: "malicious" } } });
  assert.equal(category(adverse, "beacon").length, 1);
  assert.ok(category(adverse, "beacon")[0].limitations.some((reason) => reason.includes("immature")));
});

test("beacon minimum connections, duration and coefficient of variation are enforced", () => {
  const options = { baselines: train() };
  assert.equal(category(analyze(periodic({ count: 7 }), options), "beacon").length, 0);
  assert.equal(category(analyze(periodic({ count: 8, spacing: 30 }), options), "beacon").length, 0);
  assert.equal(category(analyze(periodic({ count: 7 }), { ...options, config: { beaconMinConnections: 2 } }), "beacon").length, 0);
  const irregular = periodic();
  irregular[7]._source["@timestamp"] = "2026-10-02T10:20:00.000Z";
  assert.equal(category(analyze(irregular, options), "beacon").length, 0);
  assert.equal(category(analyze(periodic(), { ...options, config: { beaconMinConnections: 10 } }), "beacon").length, 0);
});

test("beacons do not count duplicate timestamps, blocked attempts or connection ends", () => {
  const options = { baselines: train() };
  assert.equal(category(analyze(periodic({ fields: { "event.action": "blocked" } }), options), "beacon").length, 0);
  assert.equal(category(analyze(periodic({ fields: { "event.type": "end" } }), options), "beacon").length, 0);
  const sameTime = periodic().map((event) => ({ ...event, _source: { ...event._source, "@timestamp": "2026-10-02T10:00:00Z" } }));
  assert.equal(category(analyze(sameTime, options), "beacon").length, 0);
});

test("beacon intervals do not join different hosts, ports or process entities", () => {
  const events = periodic().map((event, index) => ({ ...event, _source: { ...event._source, "process.entity_id": `proc-${index % 2}` } }));
  assert.equal(category(analyze(events, { baselines: train() }), "beacon").length, 0);
  for (const field of ["host.name", "destination.port"]) {
    const split = periodic().map((event, index) => ({ ...event, _source: { ...event._source, [field]: field === "host.name" ? `host-${index % 2}` : 443 + index % 2 } }));
    assert.equal(category(analyze(split, { reputations: { [PUBLIC]: { verdict: "malicious" } } }), "beacon").length, 0);
  }
});

test("exfiltration requires directional bytes, absolute threshold and mature comparable-hour baseline ratio", () => {
  const baselines = train();
  const transfer = network("large", { "source.bytes": 60_000_000 });
  const finding = category(analyze([transfer], { baselines }), "exfiltration")[0];
  assert.equal(finding.count, 1);
  assert.ok(finding.reasons.some((reason) => reason.includes("60.00 times")));
  assert.match(finding.evidence[0].reason, /Allowed private-to-public transfer: 60000000/);
  assert.equal(category(analyze([transfer]), "exfiltration").length, 0);
  assert.equal(category(analyze([transfer], { baselines: train({ days: 6 }) }), "exfiltration").length, 0);
  assert.equal(category(analyze([transfer], { baselines: train({ bytes: 20_000_000 }) }), "exfiltration").length, 0);
  assert.equal(category(analyze([network("small", { "source.bytes": 10_000_000 })], { baselines }), "exfiltration").length, 0);
  assert.equal(category(analyze([network("unknown-direction", { "network.bytes": 80_000_000 })], { baselines }), "exfiltration").length, 0);
});

test("exfiltration combines peer transfers per hour across ports without combining different hours", () => {
  const transfers = [network("a", { "source.bytes": 30_000_000, "destination.port": 443 }), network("b", { "source.bytes": 30_000_000, "destination.port": 22 }, "2026-10-02T10:10:00Z")];
  assert.equal(category(analyze(transfers, { baselines: train() }), "exfiltration")[0].count, 2);
  transfers[1]._source["@timestamp"] = "2026-10-02T11:10:00Z";
  assert.equal(category(analyze(transfers, { baselines: train() }), "exfiltration").length, 0);
});

test("exfiltration excludes private peers, public sources, blocked transfers, missing/zero baseline and unrelated hours", () => {
  const baselines = train();
  for (const fields of [{ "destination.ip": "10.1.1.1" }, { "source.ip": "45.33.32.156" }, { "event.action": "blocked" }, { "event.outcome": "failure" },
    { "source.ip": "127.0.0.1" }, { "destination.ip": "169.254.1.1" }]) {
    assert.equal(category(analyze([network("transfer", { "source.bytes": 80_000_000, ...fields })], { baselines }), "exfiltration").length, 0);
  }
  for (const baseline of [train({ bytes: 0 }), train({ time: "09:00:00" })]) {
    assert.equal(category(analyze([network("transfer", { "source.bytes": 80_000_000 })], { baselines: baseline }), "exfiltration").length, 0);
  }
});

test("IPv6 private-to-public scope and mapped IPv4 addresses are supported", () => {
  const baselines = train();
  const events = periodic({ peer: "2606:4700:3030::6815:1234", fields: { "source.ip": "fd12::7" } });
  assert.equal(category(analyze(events, { baselines }), "beacon").length, 1);
  assert.equal(category(analyze([network("mapped", { "source.ip": "::ffff:10.0.0.7", "source.bytes": 60_000_000 })], { baselines }), "exfiltration").length, 1);
  assert.equal(category(analyze(periodic({ peer: "fd12::1" }), { baselines }), "beacon").length, 0);
});

test("baseline counts distinct preceding local days, deduplicates retries and leaves input untouched", () => {
  const first = network("one", { "source.bytes": 100, "user.name": "alice" });
  const baseline = analyze([first, first]).baselines;
  const saved = structuredClone(baseline);
  const retry = analyze([first], { baselines: baseline }).baselines;
  assert.deepEqual(baseline, saved);
  assert.deepEqual(retry, saved);
  const day = retry.hosts["workstation-1"].days["2026-10-02"];
  assert.equal(day.observations, 1);
  assert.equal(day.peers[PUBLIC], 1);
  assert.equal(day.hours[12], 1);
  assert.equal(day.weekday, 5);
  assert.equal(day.outboundBytesByHour[12], 100);
  assert.equal(analyze(periodic({ count: 70 }), { baselines: baseline }).coverage.matureHosts, 0);
});

test("baseline maturity is configurable and is available within a chronological multi-day batch", () => {
  const history = Array.from({ length: 7 }, (_, index) => network(`day-${index}`, { "destination.ip": "93.184.216.34" }, `2026-09-${24 + index}T10:00:00Z`));
  assert.equal(category(analyze([...periodic(), ...history]), "beacon").length, 1);
  assert.equal(category(analyze(periodic(), { baselines: train({ days: 3 }), config: { baselineDays: 3 } }), "beacon").length, 1);
  assert.equal(category(analyze(periodic(), { baselines: train(), config: { baselineDays: 8 } }), "beacon").length, 0);
});

test("baseline cannot use later history to mature an earlier finding", () => {
  const early = periodic().map((event) => ({ ...event, _source: { ...event._source, "@timestamp": event._source["@timestamp"].replace("2026-10-02", "2026-09-23") } }));
  assert.equal(category(analyze(early, { baselines: train() }), "beacon").length, 0);
});

test("calendar defaults to Tirane, respects timezone configuration and resets incompatible history", () => {
  const event = network("midnight", { "user.name": "alice" }, "2026-10-01T22:30:00Z");
  const tirane = analyze([event]);
  assert.ok(tirane.baselines.hosts["workstation-1"].days["2026-10-02"]);
  assert.equal(tirane.baselines.hosts["workstation-1"].days["2026-10-02"].hours[0], 1);
  const utc = analyze([event], { config: { timezone: "UTC" } });
  assert.equal(utc.baselines.hosts["workstation-1"].days["2026-10-01"].hours[22], 1);
  const reset = analyze([], { baselines: tirane.baselines, config: { timezone: "UTC" } });
  assert.deepEqual(reset.baselines.hosts, {});
  assert.ok(reset.coverage.limitations.some((reason) => reason.includes("timezone changed")));
  assert.equal(analyze([], { config: { timezone: "Invalid/Timezone" } }).coverage.timezone, "Europe/Tirane");
});

test("off-hour, new-host and account host restrictions alone produce review context without alerts", () => {
  const event = auth("normal-login", "success", "alice", PUBLIC, 0, { "host.name": "new-host" });
  const result = analyze([event], { baselines: train(), config: {
    accounts: [{ identity: "alice", kind: "human", allowedHours: [9, 10], hosts: ["workstation-1"] }]
  } });
  assert.equal(result.findings.length, 0);
  assert.ok(result.coverage.reviewContexts.some((context) => context.reason.includes("outside configured hours")));
  assert.ok(result.coverage.reviewContexts.some((context) => context.reason.includes("New host")));
  assert.ok(result.coverage.reviewContexts.some((context) => context.reason.includes("configured host list")));
});

test("service accounts and overnight allowed hours remain context without suppressing genuine auth evidence", () => {
  const config = { accounts: [{ identity: "backup", kind: "service", allowedHours: { start: "22:00", end: "06:00", weekdays: [5] }, hosts: ["auth-server"] }] };
  const overnight = auth("overnight", "success", "backup");
  overnight._source["@timestamp"] = "2026-10-02T02:00:00Z";
  assert.equal(analyze([overnight], { config }).coverage.reviewContexts.length, 0);
  const failures = Array.from({ length: 10 }, (_, index) => auth(`f-${index}`, "failure", "backup", PUBLIC, index));
  assert.equal(category(analyze([...failures, auth("success", "success", "backup", PUBLIC, 20)], { config }), "authentication").length, 1);
});

test("asset CIDRs/criticality affect ranking but expected/risky services alone do not cause alerts", () => {
  const events = scan();
  const config = { assets: [{ id: "prod", name: "Production", criticality: "critical", cidrs: ["10.0.1.0/24"], expectedServices: [22] }] };
  const ordinary = category(analyze(events), "scan")[0];
  const critical = category(analyze(events, { config }), "scan")[0];
  assert.equal(critical.priority, Math.min(100, ordinary.priority + 10));
  assert.equal(analyze([network("expected", { "destination.port": 22 })], { config }).findings.length, 0);
});

test("findings satisfy score/status/proof contracts, stable fingerprints and at most 30 references", () => {
  const events = scan({ count: 100 });
  const first = analyze(events);
  const second = analyze([...events].reverse());
  assert.deepEqual(first.findings, second.findings);
  const finding = category(first, "scan")[0];
  assert.equal(finding.count, 100);
  assert.equal(finding.events, 100);
  assert.equal(finding.evidence.length, 30);
  assert.equal(finding.evidence[0].eventId, "scan-0");
  assert.equal(finding.evidence.at(-1).eventId, "scan-99");
  assert.match(finding.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(finding.status, "open");
  for (const score of [finding.behaviorScore, finding.confidence, finding.priority]) assert.ok(Number.isInteger(score) && score >= 0 && score <= 100);
  for (const proof of finding.evidence) assert.deepEqual(Object.keys(proof).sort(), ["eventId", "index", "timestamp", "reason"].sort());
});

test("long authentication sequences retain the success proof when evidence is capped", () => {
  const failures = Array.from({ length: 40 }, (_, index) => auth(`f-${index}`, "failure", "alice", PUBLIC, index));
  const finding = category(analyze([...failures, auth("success", "success", "alice", PUBLIC, 50)]), "authentication")[0];
  assert.equal(finding.count, 41);
  assert.equal(finding.evidence.length, 30);
  assert.equal(finding.evidence.at(-1).eventId, "success");
  assert.match(finding.evidence.at(-1).reason, /Allowed authentication success/);
});

test("coverage accounts for bad/future/duplicate data and keeps same IDs in different indices", () => {
  const event = network("same");
  const result = analyze([event, event, { ...event, _index: "another-index" }, hit("invalid", {}, "bad"), network("future", {}, "2026-10-03T00:00:00Z"), null]);
  assert.equal(result.coverage.inputEvents, 6);
  assert.equal(result.coverage.validEvents, 2);
  assert.equal(result.coverage.duplicateEvents, 1);
  assert.equal(result.coverage.invalidEvents, 2);
  assert.equal(result.coverage.futureEvents, 1);
  assert.equal(result.metrics.analyzedEvents, 2);
  assert.deepEqual(analyze(null).findings, []);
});

test("unusual object keys do not pollute prototype objects or lose legitimate identity observations", () => {
  const before = {}.polluted;
  const event = network("keys", { "host.name": "__proto__", "user.name": "constructor", "destination.domain": "constructor" });
  const result = analyze([event]);
  assert.equal({}.polluted, before);
  assert.equal(result.baselines.hosts.__proto__.days["2026-10-02"].observations, 1);
  assert.equal(result.baselines.users.constructor.days["2026-10-02"].observations, 1);
});

test("worker pipe-separated reputation keys correlate IP, domain and hash evidence", () => {
  const events = [network("peer", { "destination.domain": "bad.example" }), hit("hash", { "event.category": "process", "event.type": "start", "process.hash.sha256": HASH })];
  const result = analyze(events, { reputations: { [`ip|${PUBLIC}`]: { verdict: "malicious" }, "domain|bad.example": { verdict: "suspicious" }, [`hash|${HASH}`]: { verdict: "malicious" } } });
  assert.equal(category(result, "intelligence").length, 3);
  assert.equal(result.coverage.reputationMatchedIndicators, 3);
});

test("overlapping reanalysis cannot add observations, bytes, peer counts or mature days", () => {
  const events = Array.from({ length: 30 }, (_, index) => network(`overlap-${index}`, { "source.bytes": 1000, "user.name": "alice" }));
  let baselines = analyze(events).baselines;
  const original = structuredClone(baselines);
  for (let run = 0; run < 8; run += 1) {
    const result = analyze([...events.slice(10), ...events.slice(0, 20)], { baselines });
    baselines = result.baselines;
    assert.equal(result.coverage.matureHosts, 0);
    assert.equal(result.coverage.matureUsers, 0);
  }
  assert.deepEqual(baselines, original);
  assert.equal(baselines.hosts["workstation-1"].days["2026-10-02"].outboundBytesByHour[12], 30_000);
});

test("the same document ID cannot create multiple baseline days after timestamp updates", () => {
  let baselines = {};
  for (let day = 24; day <= 30; day += 1) {
    baselines = analyze([network("stable-id", {}, `2026-09-${day}T10:00:00Z`)], { baselines }).baselines;
  }
  assert.equal(Object.keys(baselines.hosts["workstation-1"].days).length, 1);
  assert.equal(analyze([], { baselines }).coverage.matureHosts, 0);
});

test("authentication, scans and beacons correlate across chunks and overlapping pages", () => {
  const authEvents = [...Array.from({ length: 10 }, (_, index) => auth(`f-${index}`, "failure", "alice", PUBLIC, index)), auth("success", "success", "alice", PUBLIC, 20)];
  const authFirst = analyze(authEvents.slice(0, 7));
  const authSecond = analyze(authEvents.slice(5), { baselines: authFirst.baselines });
  const finding = category(authSecond, "authentication")[0];
  assert.equal(finding.count, 11);
  assert.equal(finding.eventKeys.length, 11);
  const scanEvents = scan();
  const scanFirst = analyze(scanEvents.slice(0, 20));
  const scanSecond = analyze(scanEvents.slice(15), { baselines: scanFirst.baselines });
  assert.equal(category(scanSecond, "scan")[0].count, 30);
  const beaconEvents = periodic();
  const beaconFirst = analyze(beaconEvents.slice(0, 4), { baselines: train() });
  assert.equal(category(beaconFirst, "beacon").length, 0);
  const beaconSecond = analyze(beaconEvents.slice(3), { baselines: beaconFirst.baselines });
  assert.equal(category(beaconSecond, "beacon")[0].count, 8);
});

test("exfiltration combines bytes across chunks without learning those transfers as normal", () => {
  const events = [network("transfer-a", { "source.bytes": 30_000_000 }), network("transfer-b", { "source.bytes": 30_000_000 }, "2026-10-02T10:10:00Z")];
  const first = analyze(events.slice(0, 1), { baselines: train() });
  assert.equal(category(first, "exfiltration").length, 0);
  const second = analyze(events.slice(1), { baselines: first.baselines });
  assert.equal(category(second, "exfiltration")[0].count, 2);
  assert.equal(second.baselines.hosts["workstation-1"].days["2026-10-02"], undefined);
  for (const event of events) assert.equal(second.baselines.observedEvents[JSON.stringify([event._index, event._id])].excluded, true);
});

test("adverse events and high-confidence detections cannot teach normal baseline behavior", () => {
  const maliciousHistory = Array.from({ length: 7 }, (_, index) => network(`malicious-${index}`, { "source.bytes": 1000, "user.name": "alice" }, `2026-09-${24 + index}T10:00:00Z`));
  const malicious = analyze(maliciousHistory, { reputations: { [`ip|${PUBLIC}`]: { verdict: "malicious" } } });
  assert.equal(malicious.coverage.matureHosts, 0);
  assert.deepEqual(malicious.baselines.hosts, {});
  assert.deepEqual(malicious.baselines.users, {});
  const beaconEvents = periodic({ fields: { "user.name": "alice", "source.bytes": 1000 } });
  const first = analyze(beaconEvents.slice(0, 4), { baselines: train() });
  assert.equal(first.baselines.hosts["workstation-1"].days["2026-10-02"].observations, 4);
  const second = analyze(beaconEvents.slice(4), { baselines: first.baselines });
  assert.equal(second.baselines.hosts["workstation-1"].days["2026-10-02"], undefined);
  assert.equal(second.baselines.users.alice.days["2026-10-02"], undefined);
  const third = analyze(beaconEvents, { baselines: second.baselines });
  assert.equal(category(third, "beacon")[0].count, 8);
  assert.equal(third.baselines.hosts["workstation-1"].days["2026-10-02"], undefined);
});

test("late reputation enrichment retracts the original observation even if its host fields changed", () => {
  const event = network("late-reputation", { "source.bytes": 1000, "user.name": "alice" });
  const first = analyze([event]);
  const changed = { ...event, _source: { ...event._source, "host.name": "new-host", "user.name": "bob" } };
  const second = analyze([changed], { baselines: first.baselines, reputations: { [`ip|${PUBLIC}`]: { verdict: "malicious" } } });
  assert.deepEqual(second.baselines.hosts, {});
  assert.deepEqual(second.baselines.users, {});
  assert.equal(Object.values(second.baselines.observedEvents)[0].excluded, true);
});

test("baseline retraction preserves other normal observations and their exact byte counters", () => {
  const bad = network("eventually-bad", { "source.bytes": 1000, "user.name": "alice" });
  const good = network("good", { "source.bytes": 500, "user.name": "alice", "destination.ip": "93.184.216.34" }, "2026-10-02T10:01:00Z");
  const first = analyze([bad, good]);
  const second = analyze([bad], { baselines: first.baselines, reputations: { [`ip|${PUBLIC}`]: { verdict: "malicious" } } });
  const day = second.baselines.hosts["workstation-1"].days["2026-10-02"];
  assert.equal(day.observations, 1);
  assert.equal(day.outboundBytesByHour[12], 500);
  assert.equal(day.peers[PUBLIC], undefined);
  assert.equal(second.baselines.hosts["workstation-1"].firstSeen, normalizeEvent(good).timestamp);
});

test("baseline retention expires old calendar buckets, ledger IDs, exclusions and correlation", () => {
  const baselines = train();
  const retained = analyze([], { baselines, config: { retentionDays: 3 } });
  assert.deepEqual(Object.keys(retained.baselines.hosts["workstation-1"].days), ["2026-09-29", "2026-09-30"]);
  assert.equal(Object.keys(retained.baselines.observedEvents).length, 2);
  const expired = analyze([], { baselines, now: "2026-11-08T10:00:00Z", config: { retentionDays: 30 } });
  assert.deepEqual(expired.baselines.hosts, {});
  assert.deepEqual(expired.baselines.users, {});
  assert.deepEqual(expired.baselines.observedEvents, {});
  assert.deepEqual(expired.baselines.correlation.events, []);
  const oldReplay = analyze([network("old-replay", {}, "2026-09-24T10:00:00Z")], { config: { retentionDays: 3 } });
  assert.deepEqual(oldReplay.baselines.observedEvents, {});
  assert.deepEqual(oldReplay.baselines.correlation.events, []);
});

test("scoped enabled exceptions suppress matching evidence without suppressing other hosts/infrastructure", () => {
  const events = [network("a", { "host.name": "host-a", "observer.name": "edge-a" }), network("b", { "host.name": "host-b", "observer.name": "edge-b" })];
  const exception = { indicatorType: "ip", indicatorValue: PUBLIC, host: "host-a", infrastructure: "edge-a", reason: "Approved test", expiresAt: "2026-10-03T00:00:00Z", enabled: true };
  const result = analyze(events, { reputations: { [`ip|${PUBLIC}`]: { verdict: "malicious" } }, config: { exceptions: [exception] } });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].host, "host-b");
  assert.equal(result.findings[0].infrastructure, "edge-b");
  assert.deepEqual(result.findings[0].evidence.map((proof) => proof.eventId), ["b"]);
  assert.deepEqual(result.baselines.hosts, {});
});

test("disabled, expired, invalid and nonmatching exceptions do not suppress evidence", () => {
  const base = { indicatorType: "ip", indicatorValue: PUBLIC, reason: "Approved test", enabled: true };
  for (const change of [{ enabled: false }, { expiresAt: "2026-10-01T00:00:00Z" }, { expiresAt: NOW }, { expiresAt: "invalid" }, { host: "other-host" }, { infrastructure: "other-edge" }, { indicatorType: "domain" }]) {
    const result = analyze([network("evidence")], { reputations: { [`ip|${PUBLIC}`]: { verdict: "malicious" } }, config: { exceptions: [{ ...base, ...change }] } });
    assert.equal(result.findings.length, 1);
  }
});

test("identity exceptions apply before auth correlation and peer exceptions apply to beacon/exfil", () => {
  const failures = Array.from({ length: 10 }, (_, index) => auth(`f-${index}`, "failure", "alice", PUBLIC, index));
  const config = { exceptions: [{ indicatorType: "identity", indicatorValue: "alice", reason: "Approved authentication test", enabled: true }] };
  assert.equal(category(analyze([...failures, auth("success", "success", "alice", PUBLIC, 20)], { config }), "authentication").length, 0);
  const peerConfig = { exceptions: [{ indicatorType: "ip", indicatorValue: PUBLIC, host: "workstation-1", reason: "Approved transfer", enabled: true }] };
  assert.equal(analyze(periodic({ fields: { "source.bytes": 60_000_000 } }), { config: peerConfig, baselines: train() }).findings.length, 0);
});

test("reputation increases priority by malicious +15 / suspicious +7 and blocked IoCs remain reviews", () => {
  const events = scan();
  const ordinary = category(analyze(events), "scan")[0];
  const suspicious = category(analyze(events, { reputations: { [`ip|${PUBLIC}`]: { verdict: "suspicious" } } }), "scan")[0];
  const malicious = category(analyze(events, { reputations: { [`ip|${PUBLIC}`]: { verdict: "malicious" } } }), "scan")[0];
  assert.equal(suspicious.priority, Math.min(100, ordinary.priority + 7));
  assert.equal(malicious.priority, Math.min(100, ordinary.priority + 15));
  const prevented = analyze([hit("prevented", { "event.category": "process", "event.type": ["start", "denied"], "process.hash.sha256": HASH })], { reputations: { [`hash|${HASH}`]: { verdict: "malicious" } } }).findings[0];
  assert.ok(prevented.priority < 80);
  assert.equal(prevented.severity, "medium");
  const executed = analyze([hit("executed", { "event.category": "process", "event.type": "start", "process.hash.sha256": HASH })], { reputations: { [`hash|${HASH}`]: { verdict: "malicious" } } }).findings[0];
  assert.ok(executed.priority > ordinary.priority);
});

test("benign primary DNS reputation with two vendor votes is isolated resolver noise", () => {
  const reputations = { "ip|1.1.1.1": { verdict: "suspicious", gtiVerdict: '{"value":"benign"}', malicious: 2, score: 0 } };
  const events = periodic({ peer: "1.1.1.1", fields: { "network.protocol": "dns", "dns.question.name": "normal.example", "destination.port": 53, "source.bytes": 80_000_000 } });
  assert.equal(analyze(events, { reputations, baselines: train() }).findings.length, 0);
  reputations["domain|normal.example"] = { verdict: "malicious" };
  const result = analyze(events, { reputations, baselines: train() });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].indicatorType, "domain");
  assert.equal(result.findings[0].indicator, "normal.example");
  assert.ok(result.findings[0].title.startsWith("DNS query"));
});

test("resolver noise suppression preserves adverse primary verdicts, stronger votes/scores and unusual services", () => {
  const noisy = { verdict: "suspicious", gtiVerdict: "benign", malicious: 2, score: 0 };
  for (const patch of [{ gtiVerdict: "malicious" }, { gtiVerdict: "suspicious" }, { malicious: 3 }, { score: 20 }, { verdict: "malicious" }]) {
    const result = analyze([network("dns", { "destination.ip": "8.8.8.8", "destination.port": 53, "network.protocol": "dns" })], {
      reputations: { "ip|8.8.8.8": { ...noisy, ...patch } }
    });
    assert.equal(category(result, "intelligence").length, 1);
  }
  assert.equal(category(analyze([network("ssh", { "destination.ip": "8.8.8.8", "destination.port": 22 })], { reputations: { "ip|8.8.8.8": noisy } }), "intelligence").length, 1);
});

test("full eventKeys include every proof identity despite the 30-reference evidence cap", () => {
  const events = scan({ count: 100 });
  const finding = category(analyze(events), "scan")[0];
  assert.equal(finding.eventKeys.length, 100);
  assert.equal(new Set(finding.eventKeys).size, finding.count);
  assert.ok(finding.eventKeys.includes(JSON.stringify([events[50]._index, events[50]._id])));
  assert.equal(finding.evidence.length, 30);
});

test("entity limits mark baseline coverage incomplete instead of establishing sampled normality", () => {
  const events = Array.from({ length: 5001 }, (_, index) => network(`entity-${index}`, { "host.name": `host-${index}` }));
  const result = analyze(events);
  assert.equal(Object.keys(result.baselines.hosts).length, 5000);
  assert.equal(result.coverage.baselineIncompleteDays, 1);
  assert.ok(result.coverage.limitations.some((reason) => reason.includes("baseline-dependent alerts are disabled")));
  assert.equal(result.coverage.matureHosts, 0);
});

test("100k event budget is bounded, replay-safe and disables incomplete byte baselines", (context) => {
  const start = performance.now();
  const events = Array.from({ length: 100_001 }, (_, index) => network(`budget-${index}`, { "source.bytes": 1 }));
  const result = analyze(events, { baselines: train() });
  assert.equal(Object.keys(result.baselines.observedEvents).length, 100_000);
  assert.ok(result.baselines.correlation.events.length <= 100_000);
  assert.equal(result.coverage.baselineIncompleteDays, 1);
  assert.ok(result.coverage.baselineDroppedObservations > 0);
  assert.equal(result.coverage.matureHosts, 0);
  const retry = analyze(events.slice(-20), { baselines: result.baselines });
  assert.equal(Object.keys(retry.baselines.observedEvents).length, 100_000);
  const transfer = analyze([network("post-cap-transfer", { "source.bytes": 60_000_000 })], { baselines: retry.baselines });
  assert.equal(category(transfer, "exfiltration").length, 0);
  context.diagnostic(`100k analysis plus overlap/cap checks: ${Math.round(performance.now() - start)} ms`);
});

test("25k scan chunk retains exact counts and stays deduplicated when the worker replays it", (context) => {
  const start = performance.now();
  const events = scan({ count: 25_000, spacing: 0.01 });
  const result = analyze(events);
  assert.equal(category(result, "scan")[0].count, 25_000);
  assert.equal(category(result, "scan")[0].evidence.length, 30);
  const replay = analyze(events, { baselines: result.baselines });
  assert.equal(category(replay, "scan")[0].count, 25_000);
  assert.equal(Object.keys(replay.baselines.observedEvents).length, 25_000);
  context.diagnostic(`25k scan and replay: ${Math.round(performance.now() - start)} ms`);
});

test("25k same-account failures use a bounded rolling window and retain exact success evidence", (context) => {
  const start = performance.now();
  const failures = Array.from({ length: 25_000 }, (_, index) => auth(`large-failure-${index}`, "failure", "alice", PUBLIC, index / 100));
  const result = analyze([...failures, auth("large-success", "success", "alice", PUBLIC, 251)]);
  const finding = category(result, "authentication")[0];
  assert.equal(finding.count, 25_001);
  assert.equal(finding.eventKeys.length, 25_001);
  assert.equal(finding.evidence.at(-1).eventId, "large-success");
  assert.equal(finding.evidence.length, 30);
  assert.deepEqual(result.baselines.hosts, {});
  context.diagnostic(`25k failures plus success: ${Math.round(performance.now() - start)} ms`);
});

test("oversized or obsolete persisted baseline layouts are reset with explicit coverage", () => {
  const obsolete = { version: 1, timezone: "Europe/Tirane", hosts: { old: { days: {} } } };
  const reset = analyze([], { baselines: obsolete });
  assert.deepEqual(reset.baselines.hosts, {});
  assert.ok(reset.coverage.limitations.some((reason) => reason.includes("incompatible baseline layout reset")));
  const oversized = train();
  for (let index = 0; index < 5001; index += 1) oversized.hosts[`imported-${index}`] = { days: {} };
  const limited = analyze([], { baselines: oversized });
  assert.deepEqual(limited.baselines.hosts, {});
  assert.ok(limited.coverage.limitations.some((reason) => reason.includes("Oversized baseline reset")));
});
