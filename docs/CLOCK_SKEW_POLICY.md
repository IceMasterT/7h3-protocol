# Clock Skew Policy

GLUV transport enforces a configurable future timestamp tolerance.

## Default

- `maxClockSkewMs`: `30000` (30s)

Messages with `header.timestampMs > nowMs + maxClockSkewMs` are rejected with:

- `Message timestamp exceeds allowed clock skew`

## Usage

```ts
import { receiveEnvelope } from './src/gluv/protocolTransport'

const result = await receiveEnvelope(rawEnvelope, {
  nowMs: Date.now(),
  maxClockSkewMs: 10_000,
  replayCache,
  secretResolver: async () => sharedSecret,
})
```

## Operational guidance

- Keep NTP enabled for all nodes.
- Use tighter skew windows for low-latency trusted clusters.
- Use slightly wider windows for geo-distributed deployments.
