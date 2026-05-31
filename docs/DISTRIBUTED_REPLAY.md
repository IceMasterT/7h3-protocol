# Distributed Replay Defense

7h3 Protocol AIP supports replay checks through pluggable cache interfaces.

## Interfaces

- `InMemoryReplayCache`: single-process replay protection.
- `DistributedReplayCache`: wraps a shared store for multi-node deployments.

Source: `src/gluv/protocolReplay.ts`

## Shared store contract

Implement `DistributedReplayStore.reserve(key, expiresAtMs, nowMs)` with atomic reserve semantics:

- Return `true` when key is newly reserved.
- Return `false` when key is already reserved and still valid.

`key` format is `sender|messageId|nonce`.

## Redis-style example (pseudo-code)

```ts
const replayCache = new DistributedReplayCache({
  reserve: async (key, expiresAtMs, nowMs) => {
    const ttlMs = Math.max(1, expiresAtMs - nowMs)
    const result = await redis.set(`aip:replay:${key}`, '1', {
      NX: true,
      PX: ttlMs,
    })
    return result === 'OK'
  },
})

await receiveEnvelope(rawEnvelope, {
  replayCache,
  secretResolver: async () => sharedSecret,
})
```

## Operational guidance

- Use distributed replay cache for any horizontally scaled gateway.
- Keep clocks synchronized (NTP) to minimize TTL-skew edge cases.
- Monitor replay reject rates as a security telemetry signal.
