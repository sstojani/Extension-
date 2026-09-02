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

Internal or implementation-specific Kibana endpoints are isolated so they can be replaced later.
