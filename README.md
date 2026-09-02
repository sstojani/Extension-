# SOC Watch

SOC Watch is an internal cybersecurity console for Elastic/Kibana environments. It is split into a Chrome Manifest V3 bridge extension and a separate web application. The bridge reuses the analyst's already-authenticated Kibana browser session through `fetch(..., { credentials: "include" })` without reading, storing, or forwarding cookies or authentication material.

## Workspace

- `apps/extension` - SOC Watch Bridge, a read-only Chrome MV3 extension.
- `apps/web` - SOC Watch web console.
- `packages/protocol` - shared message contracts, runtime schemas, sanitizers, and Kibana route helpers.
- `packages/ioc` - IOC refanging, normalization, and classification.
- `packages/health` - health-state evaluation primitives.
- `docs` - architecture, protocol, Elastic endpoint, security, testing, and deployment notes.

## Quick Start

```bash
npm install
npm run build
npm test
```

For development:

```bash
npm run dev -w apps/web
```

Configure the web app with the extension ID:

```bash
VITE_SOC_WATCH_EXTENSION_ID=<stable-extension-id>
```

Load `apps/extension/dist` as an unpacked Chrome extension after running the extension build.

## Security Baseline

SOC Watch V1 is read-only. It does not request the Chrome `cookies` permission, does not implement an arbitrary authenticated proxy, and exposes only explicit RPC actions. Fleet responses are sanitized with allowlists before leaving the extension.
