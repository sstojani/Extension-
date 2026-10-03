# Changelog

## 0.16.0 - 2026-10-03

- Separate fresh live detection from historical pagination, reputation retries, investigations and feed collection. Prioritize fixed-window live jobs in the authenticated browser relay; raw Today/Baseline collection remains optional background work.
- Use bounded, extension-constructed Elasticsearch aggregation templates with a 15-second search timeout and fixed saved scope. Inspect up to 32 blocked source groups and sampled authentication/security evidence instead of downloading every matching event.
- Report scan fanout lower bounds, log-supplied GeoIP, targets, ports and exact accepted-action timestamps. Suppress routine resolver/response traffic; preserve explicit exceptions and original ELK high-severity alert attribution. No invented C2, location or compromise conclusions.
- Keep sampled evidence out of normal baseline learning; retain deduplicated proof/alert history. Deliver fresh alerts before backfill and guard concurrent delivery from duplicate sends.
- Add live monitoring controls, stage coverage, recent versus retained findings, and cancellable historical collection without deleting evidence or advancing unfinished checkpoints. Preserve denied-request codes and pause permanently rejected historical reads.
- Add live/backlog concurrency, scope, sampling, false-positive, notification and production browser relay regressions. Organization-specific permissions, query latency, mappings and browser/OS notification delivery still require deployment validation.

## 0.15.3 - 2026-10-03

- Replace the restrictive 16 KiB snapshot-ID cap with a shared 1 MiB UTF-8 byte limit across extension, console and server relay validation; keep the saved log scope, 500-record page cap and 8 MiB response limit unchanged.
- Validate rotated snapshot IDs and response sizes before changing snapshot ownership. Size failures report numeric limits without revealing IDs or implying an authentication failure.
- Add large-ID connection, pagination, cleanup, byte-boundary and transport regressions, including the production browser/API/worker path with simulated ELK evidence. Live organization connectivity still requires deployment verification.

## 0.15.2 - 2026-10-03

- Honor Elasticsearch status headers and error bodies inside Kibana Console HTTP 200 responses in both extension fetch paths; report the real operation/status/error type without exposing raw error payloads.
- Distinguish rejected PIT requests, actual permission denials, expired snapshots, oversized IDs and malformed/incomplete responses; never authorize collection from a failed snapshot check.
- Stop retrying missing-endpoint and size/configuration failures; retain reconnect recovery for temporary failures and expired snapshots.
- Add transport-level and browser regressions for denied reads and truthful paused/connected state. The live organization's underlying ELK error still needs deployment verification.

## 0.15.1 - 2026-10-03

- Use documented field-capabilities URL parameters for browser-relay and direct probes; distinguish missing indexes, unmapped time fields, incompatible mappings, incomplete responses and permissions.
- Stop retrying configuration/permission failures until the analyst corrects them; preserve transient/authentication reconnects and show truthful connect/reconnect controls.
- Add explicit Kibana data-view selection in Server Agent settings, using the view's actual index and time field without auto-saving or broadening collection scope.
- Add connection/probe regressions and desktop/mobile recovery checks. Live organization field mappings still require deployment validation.

## 0.15.0 - 2026-10-02

- Added explicitly authorized browser-relay collection for the Server Agent using the work browser's authenticated Kibana session, without copying credentials or requiring an Elasticsearch API key.
- Added scoped read-only relay jobs, authenticated session/tab ownership, size/page limits, source binding, reconnect/pause states and checkpoint-safe retries.
- Added Browser relay controls and offline scan gating. Server reputation and durable notification delivery remain available when collection is paused.
- Updated the protected environment example and deployment instructions. Browser relay requires an open work browser and console; it does not promise unattended collection after the browser closes.

## 0.14.0 - 2026-10-02

- Add an opt-in persistent server agent: SQLite evidence/checkpoints, PIT/search_after continuation, independent watch queries, reputation retry queue and durable server notifications.
- Add evidence-based ordered authentication, cross-infrastructure scans, intelligence sightings, baseline-dependent beacon/transfer investigation and bounded read-only investigation traces.
- Add a server console independent of extension installation, policy/allowlist/assets/accounts settings, finding workflows, watch rules, delivery status and explicit browser notification permission.
- Freeze browser IOC Hunt campaigns so later 500-indicator batches never refetch/reorder the snapshot; add optional server feed campaigns with priority/provenance and safe retries.
- Separate undetected/unknown reputation from benign guarantees, retain conflicting provider evidence, and add offline evaluation plus deployment/security guidance for Node.js 24 LTS.

## 0.13.0 - 2026-09-30

### Threat Radar control

- Added a persisted Detection Policy editor for every dashboard panel, including enablement, minimum score, optional evidence expressions, signal-family queries, risky destination ports, and finding retention.
- Made active findings the default view, added an explicit retained-history toggle, and added a true Clear Findings action that preserves settings and scan history.
- Turned benign, expected-scanner, and expected-service analyst dispositions into scoped, expiring learning exceptions that immediately remove matching visible findings.

### IOC intelligence and alerts

- Risk-ranked deduplicated feed indicators using provider confidence, cross-feed corroboration, malware/C2/phishing context, freshness, and IOC type before slicing 500-item batches.
- Added automatic browser, Discord, and Telegram alert processing for high-priority IP, domain, and hash matches found in Elastic.
- Fixed ThreatView large-feed ingestion, changed missing ThreatFox and MalwareBazaar credentials to explicit skipped states, and prevented allowlisted IOCs from shrinking a batch.
- Made vendor collection concurrent, added bounded retries and request timeouts, and retained the strongest threat context when feeds disagree about the same IOC.
- Corrected the IOC checked counter to report unique indicators rather than summed per-provider coverage.

## 0.12.5 - 2026-09-23

- Isolated the classic content script so Chrome can inject it repeatedly without redeclaring top-level bindings or creating duplicate relays.
- Packaged `manifest.json` at the ZIP root so a normal extraction produces a folder Chrome can load on the first attempt.
- Added build checks for repeated injection, the ZIP manifest location, and matching web/bridge versions.
- Kept outdated bridge installations from unlocking a newer web console and clarified replacement steps.

## 0.12.4 - 2026-09-23

- Added the active Tailscale HTTPS root to the bridge's manifest, content relay, and service-worker allowlists while retaining the dedicated port.
- Made the installation gate recheck automatically after Chrome regains focus and stopped showing a development extension ID on deployed sites.
- Verified both approved deployment origins in the packaged extension build.

## 0.12.3 - 2026-09-22

- Restored the Chrome content script as a standalone classic script while retaining the exact Tailscale origin allowlist.
- Added a production-build verification step that rejects module imports and missing Tailscale permissions before packaging.

## 0.12.2 - 2026-09-22

- Added the port-specific Tailscale deployment origin to the bridge relay, external messaging allowlist, tab recovery, and extension permissions.
- Kept the original application on the hostname's standard HTTPS port outside the SOC Watch bridge trust boundary.
- Fixed remote unpacked installations so the page relay discovers and saves Chrome's actual per-profile extension ID.
- Hardened origin validation to compare ports as well as scheme and hostname.
- Cleaned extension output before production packaging so obsolete bundles cannot remain in the downloadable ZIP.

## 0.12.1 - 2026-09-22

- Updated Vitest and its nested Vite, mocker, and esbuild toolchain to patched releases.
- Removed all npm audit findings without using force or changing production runtime dependencies.
- Documented Node.js 20 or newer as the minimum supported build environment.

## 0.12.0 - 2026-09-22

- Added a mandatory startup check that opens the SOC console only after the Chrome bridge is detected.
- Added a focused installation screen with a downloadable version-matched package, Chrome setup steps, extension-ID verification, and reload-based confirmation.
- Made the content-script handshake report the real extension ID, name, and version so shared unpacked installs configure themselves after the first reload.
- Added automatic ZIP packaging to the extension build while excluding source maps from the distributable archive.

## 0.11.2 - 2026-09-20

- Separated extension transport availability from verified Kibana authentication and Fleet access.
- Replaced stale restored connection claims with immediate and periodic live health checks.
- Added connected, degraded, and disconnected states across the dashboard, proof path, popup, and extension icon.
- Prevented failed Fleet requests from appearing as valid zero counters and added a one-minute background health alarm.

## 0.11.1 - 2026-09-14

- Prevented Python-style byte-string wrappers from reaching public reputation lookups.
- Excluded `.local`, reverse-DNS, reserved, and common internal DNS namespaces from GTI/VT domain scoring.
- Normalized public fully qualified domain names before reputation checks and invalidated earlier affected scan history.

## 0.11.0 - 2026-09-14

### Detection precision

- Bound outbound evidence to each exact source-destination pair so actions, ports, denied events, signals, and byte counts cannot leak across unrelated flows.
- Added context-aware handling for major public DNS resolvers; routine DNS and DoH traffic is suppressed without globally allowlisting the destination.
- Required category-specific corroboration for command control, exfiltration, malware, scanning, exploit, phishing, and brute-force labels.
- Prevented clean GTI/VT domain and hash results from being promoted by repeated threat words alone.
- Tightened authentication promotion to explicit credential-attack telemetry plus independent evidence; ordinary usernames and generic failures remain unpromoted.

### Candidate coverage

- Expanded bounded IP and domain/hash candidate pools and retained rare indicators selected by threat-signal lanes even when they are absent from top-volume terms.
- Increased manual Threat Radar results from 20 to 50 and exposed separate IP-flow, domain/hash, and authentication-risk candidate counts.
- Added exact egress event and byte evidence to outbound tables and signal details.
- Bumped the detection policy to pack `2.0.0` and the web application and Chrome bridge to `0.11.0`.

## 0.10.0 - 2026-09-11

### Detection assurance

- Added per-run scan IDs, health state, completed/skipped stages, notification outcomes, and a retained scan ledger.
- Added all-log event and ECS field coverage telemetry so reduced coverage is visible beside results.
- Added versioned detection-pack coverage with ATT&CK intent mappings and evidence-field descriptions.
- Preserved the last successful automatic report when a later scan fails.

### Analyst workflow

- Added structured IP, domain, hash, identity, keyword, and exact-value exceptions with optional ECS field conditions, reasons, and expiry.
- Added audited alert dispositions; expected or benign feedback suppresses matching notifications for seven days without deleting evidence.
- Added local investigation cases with assignment, status, severity, immutable alert evidence snapshots, notes, and JSON export.
- Added alert-delivery tests and Diagnostics views for reputation and browser notification health.

### Reliability

- Added persistent automatic-scan leases and separate manual/automatic run records.
- Added regression tests for exception matching, feedback expiry, case normalization, identity learning, threat scoring, and finding history.
- Replaced Windows-sensitive Vitest config loading in the app workspaces with config-free launchers.
- Bumped the web application and Chrome bridge to `0.10.0`.
