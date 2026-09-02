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

Manual E2E checks require an authenticated Chrome session against the internal Kibana instance and the unpacked extension installed.
