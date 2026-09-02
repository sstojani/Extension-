# Elastic And Kibana Endpoints

Configured default Kibana base URL:

```text
https://10.10.254.202:8888
```

All endpoint access goes through the extension.

## Used In V1

- `GET /api/status` - Kibana health and version.
- `GET /api/fleet/agent_status` - Fleet agent summary.
- `GET /api/fleet/agents` - paginated Fleet agent listing.
- `GET /api/fleet/agents/{agentId}` - individual Fleet agent details.
- `GET /api/fleet/agent_status/data` - incoming data status for selected agents.
- `GET /api/data_views` - list data views.
- `GET /api/data_views/data_view/{viewId}` - retrieve data view metadata.
- `POST /api/console/proxy?path=<index>/_search&method=POST` - adapter-isolated read-only Elasticsearch search through Kibana.

The console proxy adapter is implementation-specific and intentionally isolated.
