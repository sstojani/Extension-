# Persistent Server Agent (0.16.1)

## What Changes

The optional server agent adds a persistent SQLite database, a scheduler, read-only log queries, a reputation queue, evidence correlation, cases/findings, and durable notification delivery. Browser-relay mode collects through the Chrome extension on an authenticated work computer. Direct mode can collect independently if the server has approved network access and read-only Elasticsearch credentials. Fleet/browser features remain in the Bridge Console.

Open `/#server-agent` for the console. The bridge installation gate has a Server Agent link. Browser relay requires the matching extension; direct mode does not. Both modes show actual connection/coverage state separately.

This is an evidence-driven rule/correlation engine, not a generative AI model or a guarantee of attack detection. No logs are sent to an LLM. GTI receives eligible public IP/domain/hash lookup values when a server key is configured or the authenticated browser relay advertises a saved GTI key. Browser-held keys are NOT copied to the server. Obtain approval for external threat-intelligence lookups as well as telemetry storage.

## Server Setup

Use Node.js 24 LTS. Server authentication is mandatory. Browser relay does not require an Elasticsearch API key or direct ELK connectivity from the home server. Keep the existing web port/Tailscale mapping; do not replace another application's Funnel configuration.

On the Linux server after pulling this release:

```bash
cd /opt/soc-watch
sudo -u socwatch npm ci
sudo -u socwatch npm run build
sudo install -d -m 700 /etc/soc-watch
sudo install -m 600 deploy/agent.env.example /etc/soc-watch/agent.env
sudoedit /etc/soc-watch/agent.env
```

Generate a strong access token (run once and put the output in the protected environment file):

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Set these values in `/etc/soc-watch/agent.env`:

- `SOC_WATCH_SERVER_AGENT=true`
- `SOC_WATCH_DATA_DIR=/var/lib/soc-watch`
- `SOC_WATCH_PUBLIC_ORIGIN` to the exact console origin, including `:8443` if that is the port you use.
- `SOC_WATCH_AGENT_TOKEN` to your generated token.
- `SOC_WATCH_DATA_SOURCE=browser_relay` to use the authenticated work browser. Remove the Elasticsearch URL/key lines in this mode; stale direct values are ignored. When the mode is omitted, a supplied Elasticsearch key selects direct mode, otherwise browser relay is selected.
- For optional direct access only: set `SOC_WATCH_DATA_SOURCE=direct`, `SOC_WATCH_ELASTIC_URL` to Elasticsearch (usually port 9200, NOT Kibana), and `SOC_WATCH_ELASTIC_API_KEY` to an encoded dedicated read-only key.
- Optional GTI, ThreatFox and MalwareBazaar keys. Missing provider keys are shown as skipped, not healthy.

In direct mode, restrict the Elasticsearch key to the selected log indices, with `read` and `view_index_metadata`. No write/delete/admin privilege is needed. In browser mode, the current Kibana user's existing permissions apply to PIT searches and field-capability checks; this cannot bypass a permissions denial. Certificate verification remains enabled; never disable TLS verification.

Install the updated service definition, preserving any existing `port.conf` drop-in:

```bash
sudo install -m 644 deploy/soc-watch-web.service /etc/systemd/system/soc-watch-web.service
sudo systemctl daemon-reload
sudo systemctl restart soc-watch-web
sudo systemctl status soc-watch-web --no-pager
sudo journalctl -u soc-watch-web -n 30 --no-pager
```

The unit creates `/var/lib/soc-watch` owned by `socwatch` and allows writes only there. The environment file stays root-readable. Login to Server Agent using the access token, configure the actual index/fields/timezone, and run a Live scan. Enable automatic scanning only after confirming connectivity and coverage. Run Baseline to collect prior days if desired; large windows continue in bounded pages and may take many cycles.

## Connect The Work Browser

1. Open the hosted console on the work computer that can reach Kibana. Download Bridge v0.16.1 from the installation page, fully extract it to a permanent folder and load the folder containing `manifest.json` at `chrome://extensions`. Reload the console once. For updates, replace the contents of that same permanent folder and reload the existing extension; do not remove it first or switch profiles.
2. Set the correct Kibana URL/space in the Bridge settings and open a signed-in Kibana tab in the same browser profile.
3. Sign in to Server Agent with an administrator token. In **Agent Settings**, click **Load Kibana data views** and explicitly choose the time-based log view used in Discover, or enter the exact index/time field manually. Selection changes only the draft: review the index, timestamp and infrastructure fields and click **Save settings**, then **Connect this browser**. This explicitly authorizes returning log evidence to the SOC Watch server. Obtain your organization's approval before moving security telemetry to a home-hosted service.
4. Verify **This browser connected**, run a Live scan, then explicitly enable **Live monitoring enabled**. Existing disabled schedules remain disabled after upgrade. Both this console tab and the authenticated work browser must remain open. In Delivery, enable browser notifications and grant Chrome permission, or configure an enabled webhook/Discord/Telegram channel and test its delivery.

The console polls bounded server jobs. The extension permits only scoped search snapshots, searches of up to 500 records, fixed live-detection aggregation templates, field-capability checks, referenced evidence reads and fixed public IP/domain/hash reputation lookups. The live operation cannot carry caller-defined aggregation DSL; reputation cannot carry a URL or credential. No API key, cookie or password is exported by the relay. Source fields and response sizes are bounded. System indexes, writes, scripts and arbitrary endpoints are rejected. Data-stream backing indexes are supported. One authenticated administrator session/tab provides a relay at a time. The database is bound to its first Kibana URL/space to prevent accidental cross-organization mixing; use a separate data directory for another source.

Snapshot IDs are opaque and can grow with shard coverage. Bridge v0.15.3 accepts IDs up to 1 MiB of UTF-8 bytes for connection, paging, rotation and cleanup, replacing the old 16,384-character cap. Responses remain limited to 8 MiB. Install both the updated web build and extension; an older extension still enforces its older limit. Do not narrow `logs-*` just because of the previous cap, or select a data view by its display name alone: inspect its actual index pattern/time field first. If an ID exceeds the new bound, the error reports its byte size and the limit without disclosing the ID. Choosing a narrower raw-log scope is then an explicit coverage tradeoff, never an automatic change.

Changing the saved log index or field scope disconnects the provider and requires explicit reconnection. The administrator token here is SOC Watch's server token, not a requirement for Kibana administrator privileges.

The connection check requires a mapped searchable `date`/`date_nanos` time field and confirms log-read permission with a scoped PIT. Missing indexes/time fields and mapping conflicts are settings errors, not proof of a login failure. These errors (and permission denials) stop automatic reconnect attempts and offer **Review Agent Settings**. Temporary connectivity or expired Kibana authentication continues to retry while opted in; **Stop reconnecting** cancels that attempt. The scope is never broadened automatically. Field-capability parameters follow the [Elasticsearch API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-field-caps).

Kibana Console may return HTTP 200 while reporting Elasticsearch's actual status in `x-console-proxy-status-code`. Both background and tab fetches check this status and error bodies before accepting evidence. Failures show the operation, status and a bounded error type, not raw provider bodies or credentials. A 403 is an actual permission denial; a 400/404/405 when opening a snapshot requires checking the chosen data view and PIT compatibility. PIT requires [Elasticsearch 7.10 or newer and index read privilege](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-open-point-in-time). Missing snapshot IDs and incomplete shards are not relabeled as permission denials. See [Elastic's Console proxy implementation](https://github.com/elastic/kibana/blob/main/src/platform/plugins/shared/console/server/routes/api/console/proxy/create_handler.ts).

Closing the browser/tab, signing out, losing connectivity or expiring the eight-hour server login pauses collection. The provider lease expires within 60 seconds after its last poll. Temporary failures reconnect automatically while this console is open and opted in; login expiry requires signing in again. Reloading/navigating away disconnects the provider and requires clicking Connect again. Pending fixed windows resume without advancing past unread events; expired snapshots are replayed with evidence deduplication. Browser sleep/timer throttling may pause collection. Reputation follow-ups using a server-managed GTI key and already-queued notification delivery can continue without the browser, but **new ELK events and browser-key reputation cannot be collected while the relay is offline**. A home service alone is not an always-on route into the organization.

## Integration Keys

Bridge Settings stores GTI, ThreatFox and MalwareBazaar keys in `chrome.storage.local`, scoped to the current browser profile and extension ID. A PC/browser restart or reload of the same extension does not intentionally clear keys. Moving an unpacked installation, removing/reinstalling it, switching profile or clearing extension storage can make previous keys unavailable. Updating the same permanent folder preserves the ID/storage; genuinely deleted keys cannot be recovered by the app. Blank fields on Save leave stored keys unchanged, and successful saves are read back before confirmation. An unavailable extension read is displayed as unavailable, not as proof that keys were deleted.

Server Agent's **Integrations** tab provides a separate optional administrator-only key store. It writes `integrations.json` atomically in `SOC_WATCH_DATA_DIR` (normally `/var/lib/soc-watch`) with Unix mode `600`. Keys survive service restart/rebuild while that directory is retained. This is permission-protected plaintext, not encryption: protect the directory and its backups. API responses and audit entries return only configured/source flags. Blank submissions keep existing keys; **Remove saved key** explicitly removes a server-saved key. Keys supplied by the service environment are authoritative and cannot be overwritten from this form.

`scripts/serve-web.mjs` loads an optional `.env` at the repository root, or the explicit file in `SOC_WATCH_ENV_FILE`, before configuring the server. Existing process/systemd variables take precedence, including explicitly empty values. An explicitly requested missing/unreadable file fails startup rather than silently dropping credentials. The installed systemd service already loads `/etc/soc-watch/agent.env`; retain its root ownership and mode `600`. Do not point `SOC_WATCH_ENV_FILE` at that root-only file for the unprivileged service; systemd reads it for the service. Never add keys to `VITE_*`, which embeds values in public browser assets. Provider keys are runtime server/extension configuration, not frontend build configuration.

For agent reputation, a server-managed GTI key takes precedence. Otherwise the connected work-browser relay uses its saved GTI key locally and returns a bounded normalized assessment. The server receives a capability flag and key-change revision, not the key. New keys clear provider backoff so pending/failed jobs can retry. Active findings are prioritized before the remainder of the queue. Missing keys, 404s, authorization errors, unavailable reports and quota limits remain distinct; failures are never converted into benign verdicts.

Both paths request GTI assessment metadata with `x-tool`. An account without GTI entitlement may only return VirusTotal engine statistics; the UI preserves the provider verdict and engine counts. An undetected report is not proof of safety. See [GTI domain assessment documentation](https://gtidocs.virustotal.com/reference/domains-object). Browser reputation pauses with its authenticated relay; server-key follow-ups can continue independently.

## Scanning And Evidence

- Live detection examines the most recent five minutes by default, using bounded aggregation queries inside Elasticsearch, rather than downloading every matching raw log. The default delay is 30 seconds **after a check finishes**, plus scheduler/browser/query latency; this is near-live polling, not an instantaneous push stream. Configure a 1-15 minute window and 30-300 second delay. Late-ingested events older than the window can be missed by live checks and require a historical scan.
- Fresh detection has its own scheduler, independent of historical pagination, reputation enrichment and feed backfill. Fresh jobs receive the next available relay slot; an already executing browser request cannot be preempted. Findings and delivery are processed after the scan stage, without waiting for the security stage or historical EOF. Stage failures preserve valid other-stage evidence and show reduced coverage, never a successful all-clear.
- The scan template excludes internal/reserved source networks and common resolvers before selecting up to 32 busy public sources with blocked network activity. It returns at most 128 ports/targets per source and five proof records. Accepted context for qualifying sources adds at most three records per source. Blocked fanout is a reviewable probing candidate, not proof of malicious intent. Missing GeoIP is not replaced with a guessed country. Accepted context is not proof a scanned port was exploited.
- Source-wide live scan counts cannot safely subtract a host/infrastructure exception from unsampled traffic. Therefore any active matching IP exception conservatively suppresses that source's aggregate scan candidate, including its other scopes. Historical evidence correlation and exact watches still apply the precise configured scope. This live-coverage tradeoff prevents excluded traffic from inflating a malicious finding; review scoped exclusions before rollout.
- The security template samples up to 20 accounts with 20 authentication events each and up to 100 ELK alert/threat-indicator events. Explicit high/critical ELK alerts remain attributed to their originating rule. It only sees events in the saved readable log scope, not inaccessible system alert indexes. Normal usernames and off-hours alone are not promoted to attacks.
- Live coverage is always labeled **sampled**, or **reduced** when a stage fails. Source/account selection can omit quieter activity; bounded terms counts and distinct ports/targets are lower bounds, not a complete inventory. Fields must have compatible ECS mappings (`source.ip`/`destination.ip` as `ip`, numeric ports, and aggregatable keyword account/action/category fields). Missing/incompatible telemetry cannot provide complete detection. Elasticsearch timeouts, partial shards and malformed evidence are rejected; a 403 remains a real permission denial requiring a readable scope or an ELK administrator's review.
- **Recent N minutes** is the default finding view; **Retained history** exposes older open findings separately. Stale checks are marked overdue. Query/detection-policy changes invalidate the displayed live status and discard in-flight results from the superseded policy. A current exception also hides retained matching findings without deleting their evidence.
- Old unfinished v0.15 scans are not silently skipped or declared complete. **Stop historical scan** cancels the old window after its current read returns, retains collected proof/findings and does not advance its checkpoint. Permanent permission/settings errors pause historical retries. Today/Baseline collection remains an explicit lower-priority task; it cannot replace a newer finding's analysis with older evidence.
- Historical pagination resumes from the saved fixed window with stable event-ID deduplication. Legacy live checkpoints advance only after EOF. A PIT/cursor error replays the same window; it does not skip ahead.
- Today scans use midnight in the configured timezone. Historical collection has a fixed end time and resumes in bounded chunks. It does not replace browser-pinned results.
- `maxEventsPerRun` is a historical ingestion budget, not a claim that the whole window was analyzed. With live detection available, historical work reads one page per tick to leave room for fresh detection. `pageSize` is 100-1000, clamped to 500 in browser relay. Raising it does not accelerate the independent live checks. In-progress/reduced coverage and missing telemetry remain visible.
- Authentication sequences require actual ordered failures followed by success for the same account/source. An unusual hour or unfamiliar username alone is review context, not an attack.
- Scanning requires public-source blocked attempts with diverse targets/ports and infrastructure corroboration. Private-to-private routine traffic is not classified from volume/risky ports.
- Beaconing requires interval regularity, enough observations, and rarity against a mature baseline or adverse peer intelligence. It is a candidate for investigation, not proof of C2.
- Transfer anomalies require directional byte counters, mature comparable-hour history and a volume ratio. DNS/resolver traffic is excluded from generic beacon/exfiltration volume logic.
- Intelligence sightings distinguish DNS queries, blocked traffic, file sightings, allowed connections, and process-start hashes. A file hash in a log is not assumed to have executed.
- Every finding includes original index/event IDs, time, reasons, separate behavior/confidence/priority and reputation, and limitations. Proof samples are capped; cumulative known event IDs are deduplicated in SQLite. Explicit watch findings group evidence by host/infrastructure; their whole-query total is not a per-host count.
- Baselines use distinct local days and stable IDs, excluding adverse/attack evidence. Mature does not mean globally complete collection. Baseline truncation/immaturity disables dependent conclusions rather than fabricating certainty.
- Live samples never train the normal baseline. A later full historical read upgrades the corresponding sampled event to full evidence. Beaconing/exfiltration conclusions still require their actual telemetry/baseline evidence; this release does not infer C2 merely from a scan, domain name or an accepted firewall action. Exact IP/domain/hash watches and optional feed hunting remain independently configurable.

## Alerts And Investigation

Create an IP/domain/hash/identity watch rule with exact matching, optional domain subdomains, asset/infrastructure scope, success requirement, event minimum, priority threshold, cooldown and selected channels. Watch queries run independently of dashboard promotion. A private IP can be watched but is never sent for public reputation lookup.

Automatic high-confidence findings and explicitly watched sightings create persistent alerts. Unknown/404/quota/failure is never labeled clean. GTI primary verdict, vendor results and lookup timestamps are retained; an undetected report is not a benign guarantee.

Late GTI responses reconsider retained matching evidence, including earlier hours. Re-evaluating the same proof updates the finding without repeatedly creating the same alert. These follow-up queries/reanalysis are bounded and expose sampling limitations. Detection thresholds are editable in Agent Settings; changes must be tested against representative local examples.

Server channels support generic HTTPS webhooks, Discord and Telegram. Delivery is queued, retried with backoff, and only marked delivered after a successful provider response. Permanent errors and exhausted retries remain visible. Delivery is at-least-once: a crash after the provider receives a request may retry it. Generic webhook receivers should use the supplied `Idempotency-Key`. Discord/Telegram cannot guarantee cross-crash exactly-once delivery.

Browser notifications require explicit permission and the console to remain open. Server channels work with the browser closed. OS/browser focus/notification settings can still suppress a displayed notification; an in-app alert is not proof of notification receipt.

The bounded investigator retrieves up to five original evidence records plus a sampled exact-indicator context query. It records tool steps, facts, timeline, failures and limitations. It cannot execute scripts, modify Elasticsearch, or make unbounded arbitrary queries. It does not claim a compromise merely from a domain lookup or reputation score.

Analysts can acknowledge, assign, annotate, resolve and reopen findings. Clear Findings resolves the current open queue without deleting evidence/audit history. The same old evidence does not reopen it; a later sighting can. False-positive review does not create a permanent blanket whitelist. Add a scoped exception explicitly, with reason and optional expiration. Exemptions suppress findings; they do not falsify the external reputation verdict.

## IOC Campaigns

Browser IOC Hunt saves an immutable ranked vendor snapshot. Fresh Scan collects a new snapshot; Run Again uses the next non-overlapping batch, at most 500. Failed queries retain retry progress. Changing the hunt query or expiration requires Fresh Scan. Snapshots are bounded to fit extension storage; truncation metadata remains explicit.

The server can separately enable automated IOC campaigns. It collects Feodo's recommended current C2 list, OpenPhish, and keyed ThreatFox/MalwareBazaar feeds, freezes a one-day snapshot, and checks up to 500 IOCs per batch using paginated exact-match queries. A failed batch does not advance. Feed priority is a hunting order, not a malicious verdict; provider provenance and coverage/errors are retained. Identical data from multiple feeds is not counted as independent corroboration. Other browser feed vendors are still available in IOC Hunt.

## Access, Backups And Rollout

The default token is administrator access. Optional `SOC_WATCH_ANALYST_TOKENS` defines named tokens allowed to inspect/review/investigate/request scans but not change policy, rules, allowlists or delivery. Use unique tokens, rotate them through the service environment, and restart to expire all sessions. Tokens/credentials are never returned through the API. Cookies are HttpOnly, SameSite=Strict, and Secure for the configured HTTPS origin. Mutation endpoints enforce exact Origin and JSON content type. No cross-origin API is enabled.

Keep this deployment private with Tailscale access controls. A public Funnel URL is not authentication; do not treat it as sufficient protection for government telemetry. This release does not provide enterprise SSO/MFA, granular per-infrastructure tenant separation, encrypted SQLite, immutable external audit logging, or a validated production detection model. Those need a dedicated security/deployment review before organization-wide rollout.

Back up the database with the service stopped (or a proper SQLite online backup), including protection for stored evidence and delivery secrets. Do not copy a live WAL database file alone. The retention setting prunes evidence/runs/closed delivery data, but operational policies and checkpoints remain. Service users should not have unnecessary shell/admin rights.

Run offline regression evaluation:

```bash
npm test
npm run typecheck
npm run evaluate
```

Evaluation is on synthetic normal/attack scenarios and is NOT a measurement of production recall/precision. Before deployment, replay approved redacted local examples, review the query/field mappings, collect a representative baseline, measure false positives/missed attacks/alert latency and query load, then tune thresholds. Preserve detection/version changes and compare against the same fixtures. There is no promise of zero mistakes or complete detection without the necessary telemetry.

Primary references: [PIT/search_after pagination](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/paginate-search-results), [Elastic event-correlation rules](https://www.elastic.co/docs/solutions/security/detect-and-alert/eql), [Feodo current versus historical lists](https://feodotracker.abuse.ch/blocklist/), [ThreatFox authentication](https://threatfox.abuse.ch/api/), [Node SQLite](https://nodejs.org/docs/latest-v24.x/api/sqlite.html).
