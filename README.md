# SOC Watch

SOC Watch is an internal cybersecurity console for Elastic/Kibana environments. It is split into a Chrome Manifest V3 bridge extension and a separate web application. The bridge reuses the analyst's already-authenticated Kibana browser session through `fetch(..., { credentials: "include" })` without reading, storing, or forwarding cookies or authentication material.

Current product version: `0.12.2`. The web app verifies the bridge before opening the console, and the sidebar shows both the web and loaded bridge versions so analysts can confirm that Chrome is using the expected build.

## Workspace

- `apps/extension` - SOC Watch Bridge, a read-only Chrome MV3 extension.
- `apps/web` - SOC Watch web console.
- `packages/protocol` - shared message contracts, runtime schemas, sanitizers, and Kibana route helpers.
- `packages/ioc` - IOC refanging, normalization, and classification.
- `packages/health` - health-state evaluation primitives.
- `docs` - architecture, protocol, Elastic endpoint, security, testing, and deployment notes.

## Quick Start

Use Node.js 20, 22, or 24 or newer. Node.js 18 is not supported by the patched test toolchain.

```bash
npm install
npm run build
npm test
```

For development:

```bash
npm run dev -w apps/web
```

To run the web app and rebuild the extension automatically when source files change:

```powershell
npm.cmd run dev:all
```

The web app hot-reloads in the browser. The extension watcher rebuilds `apps/extension/dist`; use the reload button on `chrome://extensions` to activate the updated extension service worker.

Each production extension build also creates `apps/web/public/downloads/soc-watch-bridge-v<version>.zip`. This is the version-matched package offered by the web installation screen. Extract it, open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select the extracted folder containing `manifest.json`.

Configure the web app with the extension ID:

```bash
VITE_SOC_WATCH_EXTENSION_ID=<stable-extension-id>
```

The configured ID is used as a direct-message fallback. The web app normally learns and saves the actual extension ID from the content-script handshake after the first page reload, which also supports shared unpacked installations whose Chrome IDs differ.

## Security Baseline

SOC Watch V1 is read-only. It does not request the Chrome `cookies` permission, does not implement an arbitrary authenticated proxy, and exposes only explicit RPC actions. Fleet responses are sanitized with allowlists before leaving the extension.

Threat Radar adds staged, evidence-backed Elastic analysis, GTI/VT reputation enrichment, field-coverage diagnostics, a 24-hour finding history, versioned detection coverage, structured exceptions, analyst dispositions, local investigation cases, and browser/Discord/Telegram alert delivery. A zero-finding result is accompanied by coverage health so it is not presented as proof that all activity was clean.
