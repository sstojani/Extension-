# Security

SOC Watch keeps the Kibana session inside Chrome. The extension never reads, copies, stores, logs, displays, or forwards Kibana cookies, bearer tokens, API keys, or Fleet access keys.

## Invariants

- No Chrome `cookies` permission.
- No arbitrary `fetch(url, options)` bridge.
- Only explicit read-only actions are accepted.
- Sender origins are validated at runtime in addition to `externally_connectable`.
- Fleet data is sanitized by allowlist.
- No destructive Elastic, Kibana, or Fleet operations.
- No hidden product analytics or arbitrary telemetry.
- No network discovery, port scanning, brute forcing, or credential guessing.
- Kibana RBAC remains the authority for data access.

## Approved Outbound Data

- Threat-intelligence enrichment sends only the candidate public IP, domain, or hash to the configured or bundled intelligence provider. Raw Kibana events are not sent to reputation services.
- Discord and Telegram delivery is disabled until an analyst configures the corresponding destination. Alert messages contain the promoted finding summary, indicator or route, score, event count, and evidence labels.
- Browser notifications remain local to Chrome.
- API keys and webhook credentials are kept in extension-local storage and are never returned to the web UI; the UI receives configured/not-configured flags only.

SOC owners should approve outbound providers and notification destinations before production rollout. Do not configure consumer channels for classified indicators or internal addressing unless policy explicitly permits it.

## Local Decision State

Structured allowlist entries, feedback, cases, alert history, and scan history are local to the Chrome profile. They do not alter or delete Elastic data. Expected/benign feedback suppresses matching notifications for seven days; a permanent exception requires a reasoned allowlist entry and can include an expiry and ECS field condition.

## Auth Handling

The bridge maps `401`, `403`, redirects, and HTML login responses to safe protocol errors such as `KIBANA_AUTH_REQUIRED` or `KIBANA_FORBIDDEN`. The UI tells the analyst to open Kibana and authenticate normally. SOC Watch never asks for a Kibana password.
