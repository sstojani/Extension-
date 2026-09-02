# Troubleshooting

## Extension Popup Shows Bridge Connected But Kibana Failed

The extension service worker is running, but Chrome could not complete the Kibana request.

Check:

- Open `https://10.10.254.202:8888` in the same Chrome profile.
- Allow Chrome site access for `https://10.10.254.202/*`. Chrome displays the host without the `:8888` port, but it still covers the Kibana URL on port `8888`.
- If Kibana is actually served through `http://10.10.254.202:8888`, change the popup Kibana URL field to `http://10.10.254.202:8888` and press `Connect`.
- Accept the internal certificate warning if Chrome shows one.
- Log in to Kibana normally.
- Return to the SOC Watch Bridge popup and press `Connect`.
- Confirm the extension is loaded from `apps/extension/dist`, not `apps/extension`.

The popup maps network failures to `KIBANA_UNREACHABLE`, authentication failures to `KIBANA_AUTH_REQUIRED`, and permission failures to `KIBANA_FORBIDDEN`.
