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

## High-availability topologies

### Redis Sentinel

ioredis connects to Sentinel transparently. The adapter wrapper is identical to standalone Redis:

```ts
import Redis from 'ioredis'

const redis = new Redis({
  sentinels: [
    { host: 'sentinel-1', port: 26379 },
    { host: 'sentinel-2', port: 26379 },
    { host: 'sentinel-3', port: 26379 },
  ],
  name: 'mymaster',
})

const aipRedis = {
  set: async (key: string, value: string, opts: { nx?: boolean; pxMs?: number } = {}) => {
    const args: (string | number)[] = []
    if (opts.pxMs !== undefined) args.push('PX', opts.pxMs)
    if (opts.nx) args.push('NX')
    return (await redis.set(key, value, ...(args as [string, number, string]))) === 'OK'
      ? ('OK' as const)
      : null
  },
}

const replayCache = new DistributedReplayCache(
  createRedisReplayStore(aipRedis, { errorBehavior: 'fallback' }),
)
```

Sentinel handles leader election automatically. During failover (typically < 30 s), `errorBehavior` controls whether requests are rejected or degrade to local replay protection.

### Redis Cluster

AIP replay keys (`aip:replay:{sender}:{messageId}:{nonce}`) and revocation keys (`aip:revoked:{keyId}`) are independent — no cross-slot transactions required. Cluster mode works without modification. Adapt a Cluster client the same way as standalone.

```ts
const cluster = new Redis.Cluster([
  { host: 'node-1', port: 7000 },
  { host: 'node-2', port: 7001 },
  { host: 'node-3', port: 7002 },
])
// adapter wrapper identical to standalone
```

### Upstash (serverless / edge)

Upstash's `@upstash/redis` client's `set` method matches `RedisLikeClient` directly:

```ts
import { Redis } from '@upstash/redis'

const redis = new Redis({ url: process.env.UPSTASH_URL!, token: process.env.UPSTASH_TOKEN! })

const aipRedis = {
  set: async (key: string, value: string, opts: { nx?: boolean; pxMs?: number } = {}) =>
    redis.set(key, value, { nx: opts.nx, px: opts.pxMs }),
}
```

## Operational guidance

- Use a distributed replay cache for any horizontally scaled gateway.
- Keep clocks synchronized (NTP / PTP) — AIP TTL checks require clocks within the configured skew window (default ±30 s) across all nodes and Sentinel/Cluster members.
- Monitor replay reject rate and `onDegraded` rate as security / health signals.
- During Redis failover, `errorBehavior: 'fallback'` keeps traffic flowing under single-node replay protection. `errorBehavior: 'reject'` is safer but means failover = downtime for inbound envelopes. Choose the posture that matches your threat model.
- The replay store is the only component AIP requires Redis for. The revocation store (`createRedisRevocationStore`) uses the same `RedisLikeClient` interface and the same HA patterns apply.
