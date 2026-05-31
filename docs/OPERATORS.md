# GLUV Operators Guide

This guide is for SRE, platform, and performance teams operating GLUV-backed workloads in production.

---

## 1) Operational objectives

Primary objectives:

1. Maintain low drop-rate under declared load profiles
2. Maintain p99 latency SLO
3. Preserve signature/replay guarantees under stress
4. Detect and stop regressions before release

---

## 2) SLO model

Define SLOs per traffic class (example baseline):

- **Availability:** protocol receive path success ≥ 99.9%
- **Drop rate:** `dropPct <= 0.1%` (or 0% for critical lanes)
- **Latency:** p99 <= 20ms (adjust by payload and transport class)
- **Integrity:** 100% signature verification and replay checks on ingress

Important: “no drop” means **within declared operating envelope**. Any system can be overloaded if offered load exceeds capacity.

---

## 3) Transport selection matrix

Use this default selection policy:

| Workload | Recommended Mode | Why |
|---|---|---|
| High-throughput lane | `http-binary-batch` or `ws-binary-batch` | best throughput and lowest overhead |
| Balanced latency/compatibility | `ws-batch` | low framing overhead and stable p99 |
| Low/medium compatibility lane | `http` | simplest interoperability |
| Stress testing only | `http` + `--allow-unsafe-http` | intentional overload characterization |

Guardrail behavior in benchmark harness blocks unsafe plain HTTP at high concurrency unless explicitly overridden.

---

## 4) Benchmark discipline

### Sustainable benchmarks (default)

Use adaptive benchmark commands for release confidence:

```bash
npm run bench:openloop:quick
npm run bench:openloop:full
```

These discover sustainable operating rates using threshold gates.

### Stress benchmarks (explicit overload)

Use only for capacity ceiling exploration:

```bash
npm run bench:openloop:stress:quick
npm run bench:openloop:stress:full
```

Do not use stress runs alone as production readiness criteria.

---

## 5) Core runbook commands

### Quality and release gates

```bash
npm run lint
npm run test
npm run build
npm run release:gate
```

### Conformance gates

```bash
npm run conformance:python
npm run conformance:rust
npm run conformance:binary
```

### Benchmark analysis

```bash
npm run bench:diff -- --baseline <baseline.json> --candidate <candidate.json>
npm run release:dashboard
```

---

## 6) Incident runbook

### Symptom: high drop rate

1. Confirm mode and benchmark class (adaptive vs stress)
2. Check if plain HTTP is being used at high concurrency
3. Switch to binary batch mode for hot lanes
4. Inspect overload/retry behavior and queue pressure
5. Reduce offered rate or widen worker capacity

### Symptom: p99 latency spike

1. Compare payload size distribution against baseline
2. Check in-flight cap / batch-size adaptation behavior
3. Verify no regression in signature profile or canonicalization path
4. Re-run adaptive benchmark for sustainable envelope

### Symptom: signature failures

1. Validate key resolver outputs and key IDs
2. Verify canonicalization parity across runtime boundaries
3. Check clock skew / TTL policy window

### Symptom: replay rejections

1. Verify message uniqueness (`messageId`, `nonce`)
2. Validate replay cache window sizing
3. Confirm producer retry semantics are idempotent

---

## 7) Tuning matrix (starting points)

| Setting | Low Traffic | Medium Traffic | High Traffic |
|---|---:|---:|---:|
| Batch size | 4–8 | 8–32 | 32–64 |
| In-flight cap | 16–64 | 64–256 | 256–1024 |
| Retry backoff | 1–2ms | 2–8ms | 4–16ms |
| Preferred mode | `http`/`ws` | `ws-batch` | `http-binary-batch` / `ws-binary-batch` |

Treat this as a starting policy; tune from measured p99/drop under adaptive runs.

---

## 8) Security and reliability invariants

Never disable these in production:

- signature verification
- canonicalization checks
- replay defense
- TTL and clock-skew enforcement

Any performance optimization must preserve these invariants.

---

## 9) Release acceptance checklist

Release candidate is acceptable when:

1. `release:gate` passes
2. conformance suites pass (TS/Python/Rust/binary)
3. adaptive benchmarks satisfy target SLO thresholds
4. no critical regression in benchmark diff vs baseline
5. rollback plan and threshold alerts are prepared

---

## 10) Recommended rollout strategy

1. Canary 5%
2. Observe drop/p99/signature/replay counters
3. Expand 25% → 50% → 100%
4. Auto-rollback if drop or p99 breaches thresholds for sustained window

---

## 11) Documentation map

- Protocol technical guide: `README.md`
- Executive brief: `README_EXECUTIVE.md`
- Performance policy: `PERF_REGRESSION_POLICY.md`
- Backpressure notes: `BACKPRESSURE_TUNING.md`
- Release hardening: `RELEASE_GATE.md`
