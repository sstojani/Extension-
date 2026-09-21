# Protocol

Every request has:

```ts
{
  version: 1,
  requestId: string,
  action: BridgeAction,
  params: unknown
}
```

Every response echoes `version` and `requestId`, and returns either `success: true` with `data` or `success: false` with a structured error.

## Implemented Actions

Connection and configuration:

- `bridge.ping`
- `kibana.status`
- `config.get`
- `config.save`

Elastic and Fleet inventory:

- `dataViews.list`
- `dataViews.get`
- `fleet.summary`
- `fleet.list`
- `fleet.get`
- `fleet.incomingData`

Threat intelligence and analysis:

- `ioc.search`
- `threatIntel.dailyHunt`
- `threatRadar.analyze`
- `threatRadar.agent.configure`
- `threatRadar.agent.run`

Alerting and analyst workflow:

- `alerts.get`
- `alerts.configure`
- `alerts.rule.add`
- `alerts.rule.remove`
- `alerts.history.clear`
- `alerts.test`
- `threatRadar.feedback.list`
- `threatRadar.feedback.save`
- `cases.list`
- `cases.create`
- `cases.update`
- `cases.note`

The protocol also reserves bulk IOC, logs, infrastructure, and watchlist action names for future bridge implementations. Calling a reserved action that is not dispatched by the installed bridge returns `INVALID_REQUEST`; clients must not infer support from the action name alone.

## Operational Semantics

- Threat Radar responses include a scan ID, scan mode, detection-pack version, stage coverage, field coverage, and data-health status.
- Automatic scan failures retain the last successful report and add a failed scan-ledger record instead of replacing findings with an empty result.
- Analyst feedback and structured exceptions suppress presentation or notification behavior only. They never mutate source events in Elastic.
- Cases contain frozen evidence snapshots and are stored in the local browser-extension profile. They are not a shared SOC case-management backend.
- Alert delivery supports browser notifications and explicitly configured Discord or Telegram destinations. `alerts.test` verifies the configured delivery paths without creating a detection finding.
