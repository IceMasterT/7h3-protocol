# GLUV AI Decision Card (Runtime)

Use this as a fast, deterministic runtime checklist for agent systems using GLUV.

---

## 1) Pick transport mode

### If throughput is high or concurrency >= 100
- Use: `http-binary-batch` or `ws-binary-batch`
- Avoid: plain `http`

### If moderate throughput with low complexity
- Use: `ws-batch`

### If low traffic / compatibility-first
- Use: `http`

---

## 2) Pick batch size

- Low traffic: `4–8`
- Medium traffic: `8–32`
- High traffic: `32–64`

Rule: if p99 rises sharply, reduce batch size first.

---

## 3) Pick in-flight cap

- Low traffic: `16–64`
- Medium traffic: `64–256`
- High traffic: `256–1024`

Rule: if queueing grows and drop rises, lower cap and rely on backpressure.

---

## 4) Retry/backoff policy

- Retry only on retriable overload/transient failures (e.g., 503)
- Use jittered backoff:
  - low: `1–2ms`
  - medium: `2–8ms`
  - high: `4–16ms`
- Keep retries bounded (e.g., max 3 attempts)

Never retry indefinitely.

---

## 5) Safety invariants (never disable)

- Signature verification
- Canonicalization
- Replay defense
- TTL / clock-skew checks

If any are disabled, system is out of compliant mode.

---

## 6) Benchmark discipline

Use **adaptive** for production readiness:

```bash
npm run bench:openloop:quick
npm run bench:openloop:full
```

Use **stress** only for capacity ceiling exploration:

```bash
npm run bench:openloop:stress:quick
npm run bench:openloop:stress:full
```

Do not use stress numbers as SLO pass/fail.

---

## 7) Fast decision tree

1. Concurrency >= 100?
   - Yes → choose `*-binary-batch`
   - No → go to 2
2. Need lowest latency and moderate throughput?
   - Yes → `ws-batch`
   - No → `http`
3. Drop > threshold?
   - Lower in-flight cap
   - Reduce batch size
   - Increase backoff
   - Switch to binary batch mode

---

## 8) SLO gate template

- `dropPct <= 0.1%` (or stricter by lane)
- `p99 <= target_ms`
- signatures/replay checks: 100% enforced
- sustained for target duration under declared load profile

If not met: do not promote release.

---

## 9) Operator handoff note

When filing an incident/perf ticket include:

- mode (`http`, `ws-batch`, `http-binary-batch`, etc.)
- payload size(s)
- concurrency
- adaptive or stress run
- p50/p95/p99
- dropPct
- retry counts and overload signals
