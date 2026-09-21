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

### Tailscale without Nginx

The repository includes a dependency-free static production server and a hardened
`systemd` unit. The example unit expects the repository at `/opt/soc-watch` and a
system account named `socwatch`.

```bash
sudo useradd --system --home /opt/soc-watch --shell /usr/sbin/nologin socwatch
sudo chown -R socwatch:socwatch /opt/soc-watch
sudo cp /opt/soc-watch/deploy/soc-watch-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-watch-web
curl --fail http://127.0.0.1:8080/
```

Expose the loopback-only service to tailnet members:

```bash
sudo systemctl enable --now tailscaled
sudo tailscale serve --bg http://127.0.0.1:8080
tailscale serve status
```

Only use Funnel when the console is intentionally public:

```bash
sudo tailscale funnel --bg http://127.0.0.1:8080
tailscale funnel status
```

The exact generated `https://...ts.net` origin must be present in the extension's
`content_scripts.matches` and `externally_connectable.matches` before the extension
is built. After future deployments, rebuild and restart the service:

```bash
git pull --ff-only origin master
npm ci
npm run build
sudo systemctl restart soc-watch-web
```

Do not add external telemetry or send Kibana data outside the analyst's browser unless a future architecture is explicitly approved.
