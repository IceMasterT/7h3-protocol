# AGENTS

## Commands (source of truth: package.json)
- Install deps: `npm install`
- Dev server: `npm run dev`
- Lint: `npm run lint`
- Full tests: `npm run test`
- AI agent protocol quickstart demo: `npm run aip:quickstart`
- Framework bridge quickstart demo: `npm run aip:framework:quickstart`
- JSON-RPC gateway over AIP internals: `npm run aip:mcp:gateway`
- Protocol microbench: `npm run bench:protocol`
- E2E protocol quick benchmark: `npm run bench:e2e:quick`
- E2E protocol full benchmark: `npm run bench:e2e:full`
- Open-loop contention quick benchmark: `npm run bench:openloop:quick`
- Open-loop contention full benchmark: `npm run bench:openloop:full`
- Adaptive saturation benchmark gate: `npm run bench:openloop:adaptive:quick`
- CI-friendly adaptive benchmark gate: `npm run bench:openloop:adaptive:ci`
- Signature profile quick benchmark (`HS256` vs `ED25519`): `npm run bench:signatures:quick`
- Signature profile full benchmark (`HS256` vs `ED25519`): `npm run bench:signatures:full`
- Wire codec quick benchmark (`compact-json` vs `binary`): `npm run bench:wire:quick`
- Wire codec full benchmark (`compact-json` vs `binary`): `npm run bench:wire:full`
- Build release dashboard summary from latest bench runs: `npm run release:dashboard`
- Compare two benchmark json runs: `npm run bench:diff -- --baseline <path> --candidate <path>`
- CI uploads benchmark artifacts from `dist/bench/`, `dist/release-dashboard/`, `dist/npm-aip/`, and `bench-results/` for trend tracking and release evidence.
- Python conformance suite: `npm run conformance:python`
- Rust conformance suite: `npm run conformance:rust`
- Single test file: `npm run test -- src/language.test.ts`
- Single test name: `npm run test -- -t "signs and verifies with HMAC"`
- Build + typecheck: `npm run build` (runs `tsc -b && vite build`)
- Build library exports only: `npm run build:aip`
- Prepare publishable package output (`@7h3/protocol`): `npm run package:aip`

## Verification order
- Use `npm run lint && npm run test && npm run build` before finishing.
- `build` writes `dist/`; treat it as generated output, not hand-edited source.

## Real entrypoints and module boundaries
- `src/main.tsx` mounts the app; `src/App.tsx` is the single UI workbench.
- `src/language.ts` is the core implementation (tokenize/compile/run/assemble/disassemble + stdlib preload + demos).
- Protocol stack is split by responsibility:
  - `src/protocol.ts`: envelope model, canonicalization, validation, HMAC sign/verify
  - `src/protocolTransport.ts`: decode/encode (JSON + compact wire), inbound verification, replay checks, batch/session helpers
  - `src/protocolAgent.ts`: session abstraction and auto-response loop
  - `src/agentAdapter.ts`: drop-in raw-message adapter for AI framework integration
  - `src/frameworkAdapters.ts`: framework bridge helpers (LangChain/LlamaIndex message mapping + JSON-RPC MCP-style bridge)
  - `src/mcpGateway.ts`: line-based JSON-RPC gateway runtime over signed AIP internals
  - `src/index.ts`: public protocol/adapter export surface for external integrations
  - `src/protocolDemo.ts`: deterministic demo transcript used by UI/tests
- Benchmark harnesses:
  - `scripts/bench-protocol-e2e.ts` (closed-loop inproc/http/ws + agent-loop latency/throughput matrix, stage-level timing for build/canonicalize/mac/queue/transport/verify/decode)
  - `scripts/bench-protocol-openloop.ts` (open-loop contention with http/ws + batch modes; supports adaptive search for max sustainable ops/s at p99/drop thresholds and `--ci` scenario preset)
  - `scripts/bench-diff.ts` (baseline vs candidate regression check for ops/s and p99)
- Shared cross-language vectors live in `conformance/aip_v0_1.json`; TypeScript and Python conformance tests should stay aligned to this fixture.
- Shared cross-language vectors live in `conformance/aip_v0_1.json`; TypeScript, Python, and Rust conformance tests should stay aligned to this fixture.
- Tests live in `src/*.test.ts` plus CLI process tests in `scripts/*.test.ts` (no custom Vitest config/setup file).

## Non-obvious behavior to preserve
- GLUV source accepts only four Unicode symbols (`╬ ┼ ╫ ╪`) plus whitespace.
- `CALL` is encoded with two immediates: target index and arity (`arg2`).
- If any `func` declarations exist, assembler enters function mode:
  - requires `main` with arity `0`
  - injects bootstrap instructions `CALL main` then `HALT`
  - shifts jump/call targets by `+2`
- `use <library>` directives are expanded before parsing; available libs are hardcoded in `STANDARD_LIBRARIES` inside `src/language.ts`.
- Protocol verification defaults to signed envelopes (`requireSignature: true`) and needs a `secretResolver` for inbound signature checks.
- For non-HS256 signatures (for example `ED25519`), use `signatureResolver` in transport/session options to provide algorithm-specific verification material.
- Use `DistributedReplayCache` from `src/protocolReplay.ts` for multi-node replay defense (shared store reserve semantics).
- Configure `maxClockSkewMs` in receive/session options when deployments need stricter/flexible time-skew tolerance.
- Use `telemetry` (`receiveEnvelope`) and `onAuditEvent` (`createAipMcpGatewayRuntime`) to emit rejection and policy traces.
- Stable JS consumer import path is `@7h3/protocol` (from `package.json` `exports`).
- HMAC helpers depend on Web Crypto (`crypto.subtle`); runtimes without it will throw.
- Protocol canonicalization is explicit and order-sensitive (`body` then `header`, each field in fixed key order); changing field order will break signature compatibility.
- HMAC key import is cached (bounded map) in `src/protocol.ts`; preserve cache behavior for high-throughput signing/verification.
- Compact wire format uses short keys in transport (`v, mid, ts, ttl, s, r, n, i, c, cap, cid, sig`) and must map losslessly to canonical envelope fields before verification; compact signatures can include `sig.a` for algorithm (`HS256` default if omitted).

## Instruction files present
- No repo-local agent instruction files were found besides this `AGENTS.md`.
