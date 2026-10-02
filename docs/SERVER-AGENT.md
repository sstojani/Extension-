# Persistent Server Agent (0.15.0)

## What Changes

The optional server agent adds a persistent SQLite database, a scheduler, read-only log queries, a reputation queue, evidence correlation, cases/findings, and durable notification delivery. Browser-relay mode collects through the Chrome extension on an authenticated work computer. Direct mode can collect independently if the server has approved network access and read-only Elasticsearch credentials. Fleet/browser features remain in the Bridge Console.

Open `/#server-agent` for the console. The bridge installation gate has a Server Agent link. Browser relay requires the matching extension; direct mode does not. Both modes show actual connection/coverage state separately.

This is an evidence-driven rule/correlation engine, not a generative AI model or a guarantee of attack detection. No logs are sent to an LLM. GTI only receives eligible public IP/domain/hash lookup values when its optional server key is configured. Browser-only settings/keys are NOT silently copied to the server.

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

1. Open the hosted console on the work computer that can reach Kibana. Download Bridge v0.15.0 from the installation page, fully extract it to a permanent folder and load the folder containing `manifest.json` at `chrome://extensions`. Reload the console once.
2. Set the correct Kibana URL/space in the Bridge settings and open a signed-in Kibana tab in the same browser profile.
3. Sign in to Server Agent with an administrator token, save the log index, timestamp and infrastructure fields, then click **Connect this browser**. This explicitly authorizes returning log evidence to the SOC Watch server. Obtain your organization's approval before moving security telemetry to a home-hosted service.
4. Verify **This browser connected**, run a Live scan, then enable Scheduled scanning in Agent Settings. Both this console tab and the authenticated work browser must remain open.

The console polls bounded server jobs. The extension permits only scoped search snapshots, searches of up to 500 records, field-capability checks and referenced evidence reads. No API key, cookie or password is exported. Source fields and response sizes are bounded. System indexes, writes, scripts and arbitrary endpoints are rejected. Data-stream backing indexes are supported. One authenticated administrator session/tab provides a relay at a time. The database is bound to its first Kibana URL/space to prevent accidental cross-organization mixing; use a separate data directory for another source.

Changing the saved log index or field scope disconnects the provider and requires explicit reconnection. The administrator token here is SOC Watch's server token, not a requirement for Kibana administrator privileges.

Closing the browser/tab, signing out, losing connectivity or expiring the eight-hour server login pauses collection. The provider lease expires within 60 seconds after its last poll. Temporary failures reconnect automatically while this console is open and opted in; login expiry requires signing in again. Reloading/navigating away disconnects the provider and requires clicking Connect again. Pending fixed windows resume without advancing past unread events; expired snapshots are replayed with evidence deduplication. Browser sleep/timer throttling may pause collection. Server reputation follow-ups and already-queued notification delivery can continue without the browser, but **new ELK events cannot be collected while the relay is offline**. A home service alone is not an always-on route into the organization.

## Scanning And Evidence

- Live scanning resumes from a persisted checkpoint with overlapping lookback and stable event-ID deduplication. The checkpoint advances only after the fixed window completes. A PIT/cursor error replays the same window; it does not skip ahead.
- Today scans use midnight in the configured timezone. Historical collection has a fixed end time and resumes in bounded chunks. It does not replace browser-pinned results.
- `maxEventsPerRun` is the per-cycle ingestion budget, not a claim that the whole window was analyzed. `pageSize` is 100-1000. In-progress/reduced coverage and missing telemetry remain visible.
- Authentication sequences require actual ordered failures followed by success for the same account/source. An unusual hour or unfamiliar username alone is review context, not an attack.
- Scanning requires public-source blocked attempts with diverse targets/ports and infrastructure corroboration. Private-to-private routine traffic is not classified from volume/risky ports.
- Beaconing requires interval regularity, enough observations, and rarity against a mature baseline or adverse peer intelligence. It is a candidate for investigation, not proof of C2.
- Transfer anomalies require directional byte counters, mature comparable-hour history and a volume ratio. DNS/resolver traffic is excluded from generic beacon/exfiltration volume logic.
- Intelligence sightings distinguish DNS queries, blocked traffic, file sightings, allowed connections, and process-start hashes. A file hash in a log is not assumed to have executed.
- Every finding includes original index/event IDs, time, reasons, separate behavior/confidence/priority and reputation, and limitations. Proof samples are capped; cumulative known event IDs are deduplicated in SQLite. Explicit watch findings group evidence by host/infrastructure; their whole-query total is not a per-host count.
- Baselines use distinct local days and stable IDs, excluding adverse/attack evidence. Mature does not mean globally complete collection. Baseline truncation/immaturity disables dependent conclusions rather than fabricating certainty.

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
