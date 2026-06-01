# Fleet-Wide Key Revocation

`RollingKeyring` (`src/keyRotation.ts`) enforces revocation and `notBefore`/
`notAfter` expiry **in-process**. For horizontally scaled deployments, a shared
`RevocationStore` makes a revocation effective across every node: revoke a
`(sender, keyId)` on one gateway and all gateways that consult the same store
reject it.

Source: `src/revocation.ts`.

## Interfaces

- `RevocationStore` — `isRevoked(sender, keyId, nowMs?)` and `revoke(sender, keyId, { untilMs? })`.
- `InMemoryRevocationStore` — single-process implementation (tests, local dev, single node).
- `createRedisRevocationStore` — Redis-backed shared store with cached reads.
- `withRevocationCheck(resolver, store)` — wraps a signature resolver so a revoked key resolves to **no material**, which makes verification fail and the envelope is rejected.

## Usage

```ts
import {
  RollingKeyring,
  createKeyringSignatureResolver,
  createRedisRevocationStore,
  withRevocationCheck,
  receiveEnvelope,
} from '@7h3/protocol'

const keyring = new RollingKeyring(records)
const revocations = createRedisRevocationStore(redisLikeClient, {
  keyPrefix: 'aip:revoked:',
  errorBehavior: 'reject', // fail closed (default)
  cacheTtlMs: 5000,
  onDegraded: (err, ctx) => metrics.increment('aip.revocation.degraded'),
})

const signatureResolver = withRevocationCheck(
  createKeyringSignatureResolver(keyring),
  revocations,
)

await receiveEnvelope(rawEnvelope, { signatureResolver })

// Operationally, on a suspected compromise:
await revocations.revoke('agent.worker', 'agent.worker-k1')           // permanent
await revocations.revoke('agent.worker', 'agent.worker-k2', { untilMs: Date.now() + 86_400_000 }) // 24h
```

## Behavior on Redis outage (`errorBehavior`)

| Value | On client error | Rationale |
|---|---|---|
| `reject` (default) | Treat the key as **revoked** (fail closed) | A revoked key is a compromised key — never accept on uncertainty |
| `allow` | Treat the key as **not revoked** | Favor availability where the risk is acceptable |

Reads are served from a short-lived local cache (`cacheTtlMs`), so:

- the verify hot path does not hit Redis on every message (scalability), and
- known revocations keep enforcing through a brief Redis outage (a stale cached
  `revoked: true` is still honored).

Every degraded decision fires `onDegraded` — degradation is never silent.

## Operational guidance

- Wire `withRevocationCheck` into every verifying node's `signatureResolver`.
- Treat the `onDegraded` rate as a security signal; sustained degradation means
  revocations may not be propagating.
- Keep `cacheTtlMs` short enough that a revocation propagates within your SLA.
