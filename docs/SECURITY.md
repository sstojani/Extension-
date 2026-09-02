# Security

SOC Watch keeps the Kibana session inside Chrome. The extension never reads, copies, stores, logs, displays, or forwards Kibana cookies, bearer tokens, API keys, or Fleet access keys.

## Invariants

- No Chrome `cookies` permission.
- No arbitrary `fetch(url, options)` bridge.
- Only explicit read-only actions are accepted.
- Sender origins are validated at runtime in addition to `externally_connectable`.
- Fleet data is sanitized by allowlist.
- No destructive Elastic, Kibana, or Fleet operations.
- No external telemetry.
- No network discovery, port scanning, brute forcing, or credential guessing.
- Kibana RBAC remains the authority for data access.

## Auth Handling

The bridge maps `401`, `403`, redirects, and HTML login responses to safe protocol errors such as `KIBANA_AUTH_REQUIRED` or `KIBANA_FORBIDDEN`. The UI tells the analyst to open Kibana and authenticate normally. SOC Watch never asks for a Kibana password.
