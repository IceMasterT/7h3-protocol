# 7h3 Protocol AIP Benchmark Claim Matrix (v1.0)

Use this matrix when making public performance claims.

## Standard environment

- OS: Linux (x86_64)
- Node: 22.x
- CPU: publish model and core count in benchmark report
- Memory: publish total RAM in benchmark report
- Command profile: `quick` for PR signal, `full` for release evidence

## Required benchmark suites

- `npm run bench:protocol`
- `npm run bench:e2e:quick`
- `npm run bench:e2e:full`
- `npm run bench:openloop:quick`
- `npm run bench:openloop:full`
- `npm run bench:openloop:adaptive:ci`
- `npm run bench:signatures:quick`
- `npm run bench:signatures:full`

## Mandatory dimensions

- Payload sizes: `256`, `1024`, `4096`, `16384` bytes
- Concurrency: `1`, `10`, `100`, `1000`
- Transport modes: `inproc`, `http`, `ws`, `agent-loop` where applicable
- Signature profiles: `HS256`, `ED25519`

## Required metrics

- Throughput: ops/s
- Latency: p50, p95, p99
- Drop rate percentage (open-loop)
- Stage timings where available (build/canonicalize/mac/queue/transport/verify/decode)

## Evidence requirements

- Store JSON outputs under `bench-results/` (ignored by git, attached in CI/release notes)
- Include baseline and candidate runs for release branch
- Include `bench:diff` summary for release signoff
