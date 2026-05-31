# AIP Migration Guide

## Import path migration (JS/TS)

Use the stable package subpath export:

```ts
import { createAipAgentAdapter, receiveEnvelope } from '@7h3/protocol'
```

Avoid repo-relative imports in consumer apps.

## Signature profile migration

### HS256 to ED25519

1. Generate/provision ED25519 key pairs.
2. Keep HS256 verification active during overlap window.
3. Start signing outbound envelopes with ED25519.
4. Monitor verify failures by algorithm.
5. Revoke/decommission HS256 keys after migration window.

## Replay cache migration

### Single-node to distributed

1. Replace `InMemoryReplayCache` with `DistributedReplayCache`.
2. Implement atomic reserve in shared store (for example Redis `SET NX PX`).
3. Roll out gradually and monitor replay reject metrics.

## Clock skew migration

1. Start with default `maxClockSkewMs` (30s).
2. Tighten to lower values in synchronized environments.
3. Monitor `rejected_clock_skew` telemetry for false-positive tuning.

## Rollback guidance

- Keep prior verification profiles and key material during rollout.
- Do not remove old verifiers until telemetry confirms stable traffic.
