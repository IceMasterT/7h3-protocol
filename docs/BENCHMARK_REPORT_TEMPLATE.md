# Benchmark Report Template (Release-Grade)

Use this template for every candidate release benchmark report.

---

## 1) Metadata

- Report ID:
- Date/Time (UTC):
- Author:
- Branch/Commit:
- Environment:
  - CPU:
  - Memory:
  - OS/Kernel:
  - Node/npm versions:
  - Network locality (loopback/LAN/WAN):

---

## 2) Benchmark Scope

- Profile: `quick` / `full`
- Modes tested:
- Payload sizes:
- Concurrency levels:
- Adaptive thresholds:
  - p99 threshold:
  - drop threshold:

---

## 3) Security Configuration Matrix (Required)

Mark each row as enabled/disabled and include exact settings.

| Check | Transport-only Baseline | Full Secure Protocol |
|---|---:|---:|
| Signature verification |  |  |
| Canonicalization |  |  |
| Replay defense |  |  |
| TTL/clock-skew enforcement |  |  |
| Policy checks/guardrails |  |  |

> Rule: Any public “protocol performance” claim must reference **Full Secure Protocol** results.

---

## 4) Commands Executed

Include exact commands and flags.

```bash
# adaptive sustainable runs
npm run bench:openloop:quick
npm run bench:openloop:full

# explicit stress runs
npm run bench:openloop:stress:quick
npm run bench:openloop:stress:full

# optional focused modes
npx tsx scripts/bench-protocol-openloop.ts --profile quick --adaptive --modes http-binary-batch,ws-binary-batch --payload-sizes 256,1024
```

---

## 5) Results Summary (Required)

### A) Full Secure Protocol (authoritative)

| Mode | Payload | Concurrency | Ops/s | Drop % | p99 ms | Sustainable |
|---|---:|---:|---:|---:|---:|---|
|  |  |  |  |  |  |  |

### B) Transport-only Baseline (optional reference)

| Mode | Payload | Concurrency | Ops/s | Drop % | p99 ms | Sustainable |
|---|---:|---:|---:|---:|---:|---|
|  |  |  |  |  |  |  |

---

## 6) SLO Gates (Pass/Fail)

Define and evaluate lane-specific gates.

| Lane | Gate | Result | Pass/Fail |
|---|---|---|---|
| Interactive (<=100 concurrency) | p99 <= 25ms, drop <= 0.1% |  |  |
| High-throughput (1000 concurrency) | p99 <= 100ms, drop <= 0.5% |  |  |
| Security invariants | all enforced |  |  |

Overall decision:

- [ ] PASS
- [ ] FAIL

---

## 7) Pressure Signals and Interpretation

Document pressure points and likely causes.

- Queueing/scheduling pressure observed at:
- Session/stream pressure observed at:
- Retry/backoff behavior:
- Mode-level instability (if any):

Interpretation:

- Is degradation expected under stress, or present in adaptive sustainable lane?
- Are drops due to overload policy or protocol correctness issues?

---

## 8) Remediation / Tuning Actions

List actions taken or recommended.

- [ ] Lower inflight cap
- [ ] Reduce batch size
- [ ] Increase retry backoff
- [ ] Move lane to `*-binary-batch`
- [ ] Tighten queue bounds/backpressure
- [ ] Adjust priority lanes

---

## 9) Claim Language (Publish-safe)

Use this format:

> "In full secure mode (signature + canonicalization + replay + TTL + policy enabled), mode X achieved Y ops/s at payload Z and concurrency C with drop D% and p99 P ms under adaptive sustainable thresholds."

Avoid:

- mixing stress outputs into production SLO claims,
- reporting transport-only baseline as secure protocol performance.

---

## 10) Evidence Attachments

- Raw JSON output paths:
- Markdown output paths:
- `bench:diff` output:
- `release:dashboard` output:
- Relevant logs (if anomalies):

---

## 11) Security Review Checklist

- [ ] Signature verification enabled
- [ ] Replay defense enabled
- [ ] TTL/clock-skew checks enabled
- [ ] No bypass flags used in production benchmark lane
- [ ] Policy file validated (`npm run policy:validate`)

---

## 12) Release Recommendation

- Recommendation: `GO` / `NO-GO`
- Conditions for GO:
- Conditions requiring re-test:
- Risk notes:
