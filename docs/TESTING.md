# Testing

Run:

```bash
npm test
```

Current coverage focuses on:

- IOC refanging and classification.
- Message schema validation.
- Origin validation.
- Kibana route building.
- Fleet allowlist sanitization and secret stripping.
- Health-state evaluation.
- Search query generation.
- Threat Radar scoring, private/public traffic boundaries, and retained history.
- Identity baseline learning and corroborated credential-attack detection.
- Structured exception field matching and expiry.
- Analyst feedback suppression and expiry.
- Case-record validation and evidence preservation.

The extension and web test commands use a config-free Vitest launcher. This avoids an esbuild configuration-loading failure on Windows workspaces whose path contains `+`.

Before reloading the unpacked extension, run:

```powershell
npm.cmd run build
```

The generated `apps/extension/dist/manifest.json` must show the same bridge version displayed by the web sidebar.

Manual E2E checks require an authenticated Chrome session against the internal Kibana instance and the unpacked extension installed.
