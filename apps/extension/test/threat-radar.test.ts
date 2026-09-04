import { describe, expect, it } from "vitest";
import { buildThreatRadarBody } from "../src/kibana";

describe("Threat Radar query generation", () => {
  it("aggregates all supported network identities without retrieving raw events", () => {
    const body = buildThreatRadarBody({
      timestampField: "@timestamp",
      from: "now-15m",
      to: "now",
      size: 50
    });

    expect(body.size).toBe(0);
    expect(body.aggs).toMatchObject({
      source_entities: { terms: { field: "source.ip" } },
      destination_entities: { terms: { field: "destination.ip" } },
      client_entities: { terms: { field: "client.ip" } },
      server_entities: { terms: { field: "server.ip" } }
    });
    expect(JSON.stringify(body)).toContain("event.outcome");
    expect(JSON.stringify(body)).not.toContain("DELETE");
  });
});
