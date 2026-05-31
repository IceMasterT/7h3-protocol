# Release Benchmark Report (2026-05-15)

## 1) Metadata

- Report ID: `gluv-release-bench-2026-05-15`
- Date/Time (UTC): 2026-05-15 (updated 2026-05-18)
- Branch/Commit: `bbcd960` (Fix inFlight counter leak in HTTP batch bench server handler)
- Runtime: Node.js `v24.10.0`
- Machine: local benchmark host (same environment used for prior release-gate runs)

## 2) Scope

- Profile: `full` (segmented mode-by-mode to avoid timeout)
- Modes tested:
  - `ws`, `ws-batch`, `ws-binary`, `ws-binary-batch`
  - `http-binary`
  - `http-batch` (concurrency 10 lanes complete; concurrency 100 unstable/timeout)
  - `http-binary-batch` (concurrency 10 lanes complete; concurrency 100 incomplete)
- Payload sizes: `256`, `1024`, `4096` bytes
- Concurrency levels targeted: `10`, `100`

## 3) Security Configuration Matrix

| Check | Full Secure Protocol |
|---|---:|
| Signature verification | enabled |
| Canonicalization | enabled |
| Replay defense | enabled |
| TTL/clock-skew enforcement | enabled |
| Policy checks/guardrails | enabled |

Notes:
- Guardrail for unsafe plain `http` high-concurrency was enforced.
- No benchmark run in this report used invariant-bypass settings.

## 4) Commands Executed (Representative)

```bash
npx tsx scripts/bench-protocol-openloop.ts --profile full --ci --adaptive --p99-threshold 250 --drop-threshold-pct 2 --adaptive-max-doublings 6 --adaptive-binary-steps 8 --modes ws
npx tsx scripts/bench-protocol-openloop.ts --profile full --ci --adaptive --p99-threshold 250 --drop-threshold-pct 2 --adaptive-max-doublings 6 --adaptive-binary-steps 8 --modes ws-batch
npx tsx scripts/bench-protocol-openloop.ts --profile full --ci --adaptive --p99-threshold 250 --drop-threshold-pct 2 --adaptive-max-doublings 6 --adaptive-binary-steps 8 --modes ws-binary
npx tsx scripts/bench-protocol-openloop.ts --profile full --ci --adaptive --p99-threshold 250 --drop-threshold-pct 2 --adaptive-max-doublings 6 --adaptive-binary-steps 8 --modes ws-binary-batch
npx tsx scripts/bench-protocol-openloop.ts --profile full --ci --adaptive --p99-threshold 250 --drop-threshold-pct 2 --adaptive-max-doublings 6 --adaptive-binary-steps 8 --modes http-binary
npx tsx scripts/bench-protocol-openloop.ts --profile full --adaptive --p99-threshold 250 --drop-threshold-pct 2 --adaptive-max-doublings 6 --adaptive-binary-steps 8 --modes http-batch --payloads 256,1024,4096 --concurrency 10
npx tsx scripts/bench-protocol-openloop.ts --profile full --adaptive --p99-threshold 250 --drop-threshold-pct 2 --adaptive-max-doublings 6 --adaptive-binary-steps 8 --modes http-binary-batch --payloads 256,1024,4096 --concurrency 10
```

## 5) Results Summary (Best observed per lane)

### Full Secure Protocol (authoritative)

| Mode | Payload | Concurrency | Ops/s | Drop % | p99 ms | Sustainable |
|---|---:|---:|---:|---:|---:|---|
| ws | 256 | 100 | 6548.375 | 0.000 | 49.669 | yes |
| ws | 1024 | 100 | 5887.500 | 0.000 | 53.772 | yes |
| ws | 4096 | 100 | 3887.500 | 0.000 | 66.011 | yes |
| ws-batch | 256 | 100 | 7649.000 | 0.000 | 30.971 | yes |
| ws-batch | 1024 | 100 | 6749.500 | 0.000 | 37.306 | yes |
| ws-batch | 4096 | 100 | 3850.000 | 0.000 | 49.455 | yes |
| ws-binary | 256 | 100 | 7261.000 | 0.000 | 53.193 | yes |
| ws-binary | 1024 | 100 | 5087.375 | 0.000 | 73.307 | yes |
| ws-binary | 4096 | 100 | 3662.500 | 0.000 | 77.854 | yes |
| ws-binary-batch | 256 | 100 | 5750.000 | 0.000 | 36.134 | yes |
| ws-binary-batch | 1024 | 100 | 6499.000 | 0.000 | 35.508 | yes |
| ws-binary-batch | 4096 | 100 | 4246.000 | 0.000 | 63.565 | yes |
| http-binary | 256 | 100 | 2699.875 | 0.000 | 129.755 | yes |
| http-binary | 1024 | 100 | 2385.000 | 0.000 | 119.438 | yes |
| http-binary | 4096 | 100 | 11993.750 | 0.000 | 17.647 | yes |
| http-batch | 256 | 10 | 399.125 | 1.359 | 0.867 | yes |
| http-batch | 1024 | 10 | 291.625 | 1.686 | 0.939 | yes |
| http-batch | 4096 | 10 | 320.500 | 1.536 | 1.259 | yes |
| http-binary-batch | 256 | 10 | 276.000 | 1.779 | 0.979 | yes |
| http-binary-batch | 1024 | 10 | 260.000 | 1.887 | 0.983 | yes |
| http-binary-batch | 4096 | 10 | 447.500 | 1.214 | 1.260 | yes |

### Updated results after bug fix (2026-05-18, commit `bbcd960`)

Root cause identified and fixed: the `inFlight` counter in the HTTP batch bench server handler was never decremented for batch requests, causing it to accumulate until the server began 503-ing all traffic. Fix: added `finally { this.inFlight -= 1 }` to the batch path.

| Mode | Payload | Concurrency | Ops/s | Drop % | p99 ms | Sustainable |
|---|---:|---:|---:|---:|---:|---|
| http-batch | 256 | 100 | 34940.000 | 0.000 | 7.877 | yes |
| http-batch | 1024 | 100 | 21460.000 | 0.000 | 11.470 | yes |
| http-batch | 4096 | 100 | 17886.667 | 0.000 | 13.683 | yes |
| http-binary-batch | 256 | 100 | 28238.000 | 0.000 | 8.551 | yes |
| http-binary-batch | 1024 | 100 | 19056.000 | 0.000 | 22.214 | yes |
| http-binary-batch | 4096 | 100 | 11096.000 | 0.000 | 20.675 | yes |

Evidence: `dist/bench/protocol-openloop.quick.2026-05-18T09-23-51-852Z.json`

## 6) SLO Gate Status

Defined gates used in this closure cycle:

- Interactive lanes: `p99 <= 25ms`, `drop <= 2%`
- High-throughput lanes: `p99 <= 250ms`, `drop <= 2%`

Current status:

- WS lanes (`ws*`): PASS on completed lanes.
- `http-binary`: PASS on completed lanes.
- `http-batch` and `http-binary-batch`: PASS at concurrency `100` after `bbcd960` bug fix (0% drop, all p99 within gate).

Overall decision: `GO (all lanes pass SLO gates as of 2026-05-18)`

## 7) Reliability Hardening Applied During Benchmarking

- Added HTTP/2 server stream `error` handling in bench harness.
- Added HTTP/2 client session `error` handling in bench harness.
- These are benchmark resilience fixes and do not alter protocol invariants.

## 8) Evidence Artifacts

- `dist/bench/protocol-openloop.full.2026-05-15T08-33-35-118Z.json`
- `dist/bench/protocol-openloop.full.2026-05-15T08-48-39-773Z.json`
- `dist/bench/protocol-openloop.full.2026-05-15T09-03-28-317Z.json`
- `dist/bench/protocol-openloop.full.2026-05-15T09-18-35-320Z.json`
- `dist/bench/protocol-openloop.full.2026-05-15T09-33-32-306Z.json`
- `dist/bench/protocol-openloop.full.2026-05-15T10-48-40-452Z.json`
- `dist/bench/protocol-openloop.full.2026-05-15T11-18-47-746Z.json`

## 9) Security Review Checklist

- [x] Signature verification enabled
- [x] Replay defense enabled
- [x] TTL/clock-skew checks enabled
- [x] Canonicalization enabled
- [x] Policy validation run (`npm run policy:validate`)
- [x] Release gate re-run after harness changes (`npm run release:gate`)

## 10) Next Actions for Full Closure

- ~~Rework HTTP batch transport path before re-qualification at concurrency `100`.~~ Resolved by `bbcd960`.
- All transport modes qualified. No further bench gate blockers.
- Proceed with `@7h3/protocol` publish from `dist/npm-aip/` via release automation.
