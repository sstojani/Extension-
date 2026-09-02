# Deployment

## Extension

1. Build with `npm run build -w apps/extension`.
2. Load `apps/extension/dist` as an unpacked extension for development.
3. For production, deploy through an organization-managed Chrome extension process so the extension ID remains stable.
4. Restrict `externally_connectable.matches` to the approved SOC Watch origin.

## Web

1. Build with `npm run build -w apps/web`.
2. Host on the approved internal origin, for example `https://socwatch.internal`.
3. Set `VITE_SOC_WATCH_EXTENSION_ID` to the stable production extension ID.

Do not add external telemetry or send Kibana data outside the analyst's browser unless a future architecture is explicitly approved.
