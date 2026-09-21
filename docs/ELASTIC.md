# Elastic And Kibana Endpoints

Configured default Kibana base URL:

```text
https://10.10.254.202:8888
```

All endpoint access goes through the extension.

## Used In v0.10

- `GET /api/status` - Kibana health and version.
- `GET /api/fleet/agent_status` - Fleet agent summary.
- `GET /api/fleet/agents` - paginated Fleet agent listing.
- `GET /api/fleet/agents/{agentId}` - individual Fleet agent details.
- `GET /api/fleet/agent_status/data` - incoming data status for selected agents.
- `GET /api/data_views` - list data views.
- `GET /api/data_views/data_view/{viewId}` - retrieve data view metadata.
- `POST /api/console/proxy?path=<index>/_search&method=POST` - adapter-isolated read-only Elasticsearch search through Kibana.

The console proxy adapter is implementation-specific and intentionally isolated.

Threat Radar uses staged, bounded aggregation queries through this read-only `_search` route. Wide windows may be reduced or marked partial when Kibana cannot complete every stage. Each report exposes the analyzed index pattern, requested range, event count, stage outcomes, field coverage, query latency, and an overall coverage status; zero promoted findings must be interpreted together with that coverage data.

Outbound classification uses nested source-destination aggregations so evidence from one peer cannot be attributed to another. Known public resolver IPs are excluded from outbound IP candidates because the resolver is infrastructure, not the requested indicator; `dns.question.name`, `url.domain`, and `destination.domain` remain available for domain reputation and threat-signal analysis.

The bridge does not call Elasticsearch indexing, update, delete, rule-management, or response-action endpoints. Allowlist entries, scan history, alert history, analyst feedback, and cases are stored in the local extension profile.
