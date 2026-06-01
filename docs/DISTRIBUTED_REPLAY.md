# Distributed Replay Defense

7h3 Protocol AIP protects against replay through pluggable cache interfaces.

## Interfaces

- `InMemoryReplayCache`: single-process replay protection.
- `DistributedReplayCache`: wraps a shared `DistributedReplayStore` for multi-node deployments.
- `createRedisReplayStore`: a production `DistributedReplayStore` backed by Redis-style `SET NX PX`.

Source: `src/protocolReplay.ts`, `src/replayStores.ts`.

## Client-agnostic by design

The library ships **no Redis dependency**. You inject any client matching the
small `RedisLikeClient` surface (`set` with `nx`/`pxMs`, optional `get`/`del`,
optional `pipeline`). `ioredis`, `node-redis`, Upstash, or a cluster proxy all
adapt in a few lines. An `InMemoryRedisLikeClient` reference implementation is
provided for tests and local development.

## Usage

```ts
import { DistributedReplayCache, createRedisReplayStore, receiveEnvelope } from '@7h3/protocol'
import Redis from 'ioredis'

const redis = new Redis(process.env.REDIS_URL)

const replayCache = new DistributedReplayCache(
  createRedisReplayStore(
    // adapt ioredis' set(key, val, 'PX', ms, 'NX') to the RedisLikeClient shape:
    {
      set: async (key, value, opts = {}) => {
        const args = []
        if (opts.pxMs !== undefined) args.push('PX', opts.pxMs)
        if (opts.nx) args.push('NX')
        return (await redis.set(key, value, ...args)) === 'OK' ? 'OK' : null
      },
    },
    {
      keyPrefix: 'aip:replay:',
      errorBehavior: 'fallback', // degrade to local store on a Redis outage
      onDegraded: (err) => metrics.increment('aip.replay.degraded'),
    },
  ),
)

await receiveEnvelope(rawEnvelope, { replayCache, secretResolver: async () => sharedSecret })
```

## Shared store contract

`DistributedReplayStore.reserve(key, expiresAtMs, nowMs)` must be atomic:

- Return `true` when the key is newly reserved.
- Return `false` when the key is already reserved and still valid.

`key` format is `sender|messageId|nonce`. The optional `reserveMany(entries, nowMs)`
performs a batched reserve (one round-trip via a client pipeline) and is used
automatically by `DistributedReplayCache.consumeMany` when present.

## Behavior on Redis outage (`errorBehavior`)

| Value | On client error | Use when |
|---|---|---|
| `fallback` (default) | Degrade to a local in-memory store — traffic flows, single-node replay protection stays in force, and TTL still bounds replays | Default; balances safety and uptime |
| `reject` | Fail closed — deny the message | Strictest security posture |
| `allow` | Fail open — accept the message | Uptime outweighs the narrow replay risk |

Every degraded decision fires `onDegraded` so the condition is observable — degradation is never silent.

## Operational guidance

- Use a distributed replay cache for any horizontally scaled gateway.
- Keep clocks synchronized (NTP) to minimize TTL-skew edge cases.
- Monitor replay reject rate and `onDegraded` rate as security/health signals.
