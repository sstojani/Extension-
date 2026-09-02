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

## Actions

- `bridge.ping`
- `kibana.status`
- `dataViews.list`
- `dataViews.get`
- `fleet.summary`
- `fleet.list`
- `fleet.get`
- `fleet.incomingData`
- `ioc.search`
- `ioc.bulkSearch`
- `logs.search`
- `logs.lastSeen`
- `logs.volume`
- `infrastructure.list`
- `infrastructure.get`
- `infrastructure.health`
- `watchlist.list`
- `watchlist.add`
- `watchlist.remove`
- `watchlist.check`

The first implementation supports bridge, Kibana status, Fleet, data views, and IOC search actions. Unsupported future actions return `INVALID_REQUEST`.
