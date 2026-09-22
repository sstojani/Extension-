# Changelog

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
