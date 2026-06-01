# Telemetry Events

Transport-level telemetry can be attached to `receiveEnvelope` via `telemetry` callback.

## Event phases

- `decoded`
- `rejected_clock_skew`
- `rejected_validation`
- `rejected_replay`
- `rejected_missing_signature`
- `rejected_missing_material`
- `rejected_bad_signature`
- `accepted`

## Usage

```ts
import { receiveEnvelope } from './src/protocolTransport'

await receiveEnvelope(rawEnvelope, {
  nowMs: Date.now(),
  replayCache,
  secretResolver: async () => sharedSecret,
  telemetry: async (event) => {
    console.log(event.phase, event.sender, event.messageId, event.reason)
  },
})
```

## Gateway audit events

`createAipMcpGatewayRuntime` supports `onAuditEvent` for request/policy traces.

Phases:

- `request_received`
- `policy`
- `verification_failed`
- `request_success`
- `request_error`
