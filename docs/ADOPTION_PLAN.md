# AIP Adoption Plan (Secure + Extremely Fast)

This plan turns `aip/0.1` into a production-ready protocol for agentic AI systems, memory services, and multi-agent networks.

## North-Star Targets

- Default secure mode: signed envelopes, replay protection, strict TTL validation.
- Transport speed: make `ws` the low-latency default and batch modes first-class for high-throughput workloads.
- Interop: at least 3 language SDKs passing shared conformance vectors.
- Operational maturity: CI performance gates on p99 latency, drop rate, and sustainable throughput.

## Protocol Productization (Weeks 1-2)

- Freeze protocol semantics from executable sources in `src/protocol.ts`, `src/protocolTransport.ts`, and `src/protocolReplay.ts`.
- Publish `AIP RFC v0.1` with normative language (`MUST`, `SHOULD`, `MAY`) covering:
  - canonicalization rules (field order + optional fields)
  - signature requirements and key identifiers
  - replay cache keying and eviction expectations
  - error/diagnostic semantics and transport-level failure mapping
- Include wire profiles:
  - `json` profile (interop first)
  - `compact` profile (performance first)

## Security Hardening Track (Weeks 2-6)

- Keep HS256 as baseline; add algorithm registry and pluggable signer/verifier interface for Ed25519 profile.
- Define key rotation contract:
  - key IDs
  - overlap windows
  - rotation cadence and emergency revocation behavior
- Add hard limits and abuse controls:
  - max payload size
  - max batch size
  - per-sender rate limits
  - replay cache saturation behavior (fail-open/closed policy by profile)
- Produce a threat model doc with explicit mitigations for replay flooding, clock skew abuse, and queue amplification.

## Performance Engineering Track (Weeks 2-8)

- Keep microbench (`npm run bench:protocol`) for function-level regressions.
- Keep closed-loop E2E (`npm run bench:e2e:quick|full`) for latency/throughput under bounded concurrency.
- Keep open-loop saturation (`npm run bench:openloop:quick|full`) for contention behavior and drop dynamics.
- Use adaptive CI gate (`npm run bench:openloop:adaptive:ci`) as merge guard.
- Adopt hard SLO gates per CI scenario:
  - p99 <= 250ms
  - dropPct <= 2%
  - minimum sustainable ops/s threshold by mode/payload/concurrency tuple

## SDK and Ecosystem Expansion (Weeks 3-10)

- Build official SDKs:
  - TypeScript (reference)
  - Python (agent framework ecosystem)
  - Go or Rust (infra/perf services)
- Publish cross-language conformance vectors:
  - canonical payload fixtures
  - signature fixtures
  - replay and TTL edge-case fixtures
- Ship adapter packages:
  - WebSocket session adapter
  - HTTP batch adapter
  - memory gateway adapter (AIP intents for memory read/write/search)

## AI Memory System Integration (Weeks 4-10)

- Add intent extensions for memory operations:
  - `MEM_GET`, `MEM_PUT`, `MEM_APPEND`, `MEM_SEARCH`, `MEM_COMPACT`
- Add capability namespace conventions:
  - `mem.read`, `mem.write`, `mem.search`, `mem.admin`
- Standardize idempotency and causality metadata:
  - correlation IDs
  - idempotency keys
  - causal parent references for chain-of-thought-safe state updates

## Agent Runtime Integration (Weeks 5-12)

- Add a reference agent mesh demo:
  - planner agent
  - tool-executor agent
  - memory agent
  - policy/guardrail agent
- Ensure all inter-agent traffic is AIP signed and replay-protected.
- Instrument end-to-end agent loop latency:
  - input -> planning -> tool call -> memory update -> response
- Provide runbooks for degraded modes (queue pressure, key mismatch, stale clock).

## CI, Governance, and Releases

- CI stages:
  - correctness: `npm run lint && npm run test && npm run build`
  - perf gate: `npm run bench:openloop:adaptive:ci`
  - regression diff: `npm run bench:diff -- --baseline <baseline> --candidate <candidate>`
- Release cadence:
  - protocol patch versions for non-breaking behavior
  - minor versions for additive intents/capabilities
  - major versions for breaking canonicalization/wire/security semantics
- Governance:
  - RFC process for protocol changes
  - mandatory conformance vector updates for all normative changes

## 30/60/90 Day Execution

- Day 0-30:
  - publish RFC v0.1
  - lock CI adaptive gate
  - ship SDK hardening notes and conformance vectors
- Day 31-60:
  - Python SDK beta
  - memory intent extension draft
  - key rotation + revocation reference implementation
- Day 61-90:
  - production profile v1 (`ws` + compact + adaptive perf SLOs)
  - at least one multi-agent + memory reference deployment
  - external adopter kit (quickstart + compatibility checklist)

## Success Criteria

- Security: no unsigned traffic in secure profiles; replay checks enforced in all reference transports.
- Performance: CI gate remains green with stable p99 and sustainable throughput across selected scenarios.
- Adoption: 3+ SDKs passing conformance tests and at least one external integration using AIP as primary inter-agent protocol.
