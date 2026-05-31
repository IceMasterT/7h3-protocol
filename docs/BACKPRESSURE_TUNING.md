# Backpressure and Saturation Tuning

This guide documents practical tuning for GLUV transport behavior under contention.

## Baseline methodology

Run these commands before tuning changes:

```bash
npm run bench:openloop:quick
npm run bench:openloop:adaptive:quick
npm run bench:e2e:quick
```

Focus on:

- `dropPct` under target load
- `p99Ms` tail latency
- `stageQueueMsPerOp` and `stageTransportMsPerOp`

## Tuning priorities

1. Prefer `ws` / `ws-batch` for high concurrency when tail latency dominates.
2. Prefer `ws-binary-batch` when p99 latency is more important than single-message peak throughput.
3. Reduce per-request payload size first; large payloads amplify queue and transport tails.
4. Set `batchConcurrency` on receive paths when verification work starts starving the event loop.
5. Use adaptive gate thresholds to cap unstable targets in CI.
6. Keep replay and signature verification enabled; tune concurrency and batching instead.

## Batch receive guidance

- Start with `batchConcurrency = 8` for service-side receive loops.
- Lower it when p99 grows faster than throughput.
- Raise it only when `stageVerifyMsPerOp` dominates and drop rate remains stable.
- Keep replay caches shared across the whole session so duplicate messages inside one batch are rejected.

## Binary WebSocket guidance

Use the open-loop benchmark modes below before changing runtime defaults:

```bash
npm run bench:openloop:adaptive:quick -- --modes ws,ws-batch,ws-binary,ws-binary-batch --payloads 256 --concurrency 10
```

Current policy: binary WebSocket modes are opt-in until full-profile benchmarks prove a stable throughput gain. Compact WebSocket remains the compatibility default.

## CI gate defaults

Use:

```bash
npm run bench:openloop:adaptive:ci
```

This gate enforces sustained operation bounds through adaptive search with p99 and drop-rate constraints.

## Regression check

Compare candidate against baseline:

```bash
npm run bench:diff -- --baseline <path/to/baseline.json> --candidate <path/to/candidate.json>
```

Block merges/releases when tail latency or drop-rate regresses beyond accepted limits.
