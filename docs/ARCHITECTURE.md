# Architecture

SOC Watch has two runtime surfaces:

- SOC Watch Web: analyst UI, configuration, diagnostics, and workflows.
- SOC Watch Bridge: Chrome Manifest V3 service worker that performs explicit read-only Kibana operations.

The web app never calls Kibana directly. It sends versioned RPC messages to the extension with `chrome.runtime.sendMessage`. The extension validates the sender origin, validates the request schema, executes only the named operation, sanitizes responses, and returns a protocol response.

```text
SOC Watch Web -> Chrome external messaging -> SOC Watch Bridge -> Kibana -> Elasticsearch
```

Kibana base URL, space, data view, index pattern, and field mappings are configuration values. Authentication remains owned by Chrome and Kibana.

## Adapters

- Fleet adapter: `/api/fleet/*`
- Data View adapter: `/api/data_views*`
- Search adapter: isolated `/api/console/proxy` read-only `_search` implementation
- Deep link adapter: Kibana URLs for opening Fleet, agents, and Discover

## Threat Radar Runtime

Threat Radar runs bounded, staged Elasticsearch aggregations from the extension. Each run receives an ID and records its mode, range, event coverage, completed and skipped stages, alert results, and notification results. Failed automatic runs preserve the last successful report instead of replacing it with an empty dashboard. The Diagnostics view exposes this ledger and ECS field coverage.

Detection pack 2.0 binds outbound ports, actions, failures, signals, infrastructure counts, and byte totals to an exact source-destination pair. Major public DNS resolver addresses are removed from the outbound IP candidate lane; suspicious DNS use is evaluated through the queried domain instead. Authentication findings require explicit credential-attack telemetry plus an independent source-spread or learned-baseline signal. These controls prevent source-wide volume from being presented as evidence against an unrelated destination.

Candidate collection is intentionally bounded for Kibana reliability. Separate lanes retain high-risk denied activity, risky services, security-signal matches, and top-volume traffic; rare domains and hashes selected by a security-signal lane are preserved even when absent from the volume lane. The report distinguishes evaluated IP flows, domain/hash candidates, authentication-risk candidates, promoted findings, and queued reviews.

Detection logic is versioned independently from the application. Detection-pack metadata names the evidence fields and ATT&CK coverage intent used by each family; ATT&CK mappings do not themselves prove compromise.

Finding history, structured exceptions, analyst dispositions, alert rules, notification configuration, and cases are stored in the local Chrome extension profile. Cases therefore provide durable evidence snapshots for one browser profile, not a shared multi-user case backend. A future shared deployment should move these records to an authenticated service with RBAC and an append-only audit log.

Analyst feedback never deletes source logs and does not silently retrain scoring. Benign or expected dispositions temporarily suppress matching automatic notifications; permanent suppression requires an explicit structured allowlist entry.

Internal or implementation-specific Kibana endpoints are isolated so they can be replaced later.
