# AGENTS

## Commands (source of truth: package.json)
- Install deps (root + optional SDKs): `npm run install:all`
- Lint: `npm run lint`
- Full tests: `npm run test`
- CLI help / keygen (builds first): `npm run cli:help` / `npm run cli:keygen`
- AI agent protocol quickstart demo: `npm run aip:quickstart`
- Framework bridge quickstart demo: `npm run aip:framework:quickstart`
- JSON-RPC gateway over protocol internals: `npm run aip:mcp:gateway`
- MCP wrap demo: `npm run aip:mcp:wrap`
- Protocol microbench: `npm run bench:protocol`
- E2E protocol quick/full benchmark: `npm run bench:e2e:quick` / `npm run bench:e2e:full`
- Open-loop adaptive-search benchmark: `npm run bench:openloop:quick` / `npm run bench:openloop:full`
- Open-loop fixed-load stress benchmark: `npm run bench:openloop:stress:quick` / `npm run bench:openloop:stress:full`
- Signature profile benchmark (`HMAC-SHA256` vs `Ed25519`): `npm run bench:signatures:quick` / `npm run bench:signatures:full`
- Wire codec benchmark (JSON vs CBOR/binary): `npm run bench:wire:quick` / `npm run bench:wire:full`
- Replay cache benchmark: `npm run bench:replay:quick` / `npm run bench:replay:full`
- Build release dashboard summary from latest bench runs: `npm run release:dashboard`
- Compare two benchmark json runs: `npm run bench:diff -- --baseline <path> --candidate <path>`
- Release gate / runtime policy validation / canary plan: `npm run release:gate`, `npm run policy:validate`, `npm run canary:plan`
- Python conformance suite: `npm run conformance:python`
- Rust conformance suite: `npm run conformance:rust`
- Binary conformance vectors (re)build: `npm run conformance:binary`
- TS/Rust fuzz harnesses: `npm run fuzz:ts`, `npm run fuzz:ts:decode`, `npm run fuzz:ts:verify`, `npm run fuzz:rust:decode`, `npm run fuzz:rust:canonicalize`
- Single test file: `npm run test -- src/gateway.test.ts`
- Single test name: `npm run test -- -t "signs and verifies with HMAC"`
- Build library output: `npm run build:protocol` (runs `tsc -p tsconfig.lib.json && vite build`)
- Compile the CLI binary: `npm run build:cli`
- Prepare publishable package output (`@7h3/protocol`): `npm run package:protocol`
- Smoke-test the packed npm artifact (subpath imports + CLI bin): `npm run package:protocol:smoke`

`npm run install:all` covers `sdk/pq` and `sdk/threshold`. `cloudflare/` and
`mcp-server/` are separate npm packages too — `npm ci` inside each before
running their tests. See `docs/CLEAN_CLONE_RUNBOOK.md`.

## Verification order
- Use `npm run lint && npm run test && npm run build:protocol` before finishing.
- `npm run build:protocol` writes `dist/`; treat it as generated output, not hand-edited source.

## Real entrypoints and module boundaries
- `src/index.ts` is the public export surface (`@7h3/protocol`); every subpath
  export in `package.json` (`@7h3/protocol/gateway`, `/http`, ...) resolves to
  the same bundled `dist/protocol/index.js` and is just a narrower type view.
- `src/protocol.ts`: envelope model, canonicalization, Ed25519/HMAC sign/verify, keygen.
- `src/protocolTransport.ts`: decode/encode (JSON + compact wire), inbound verification, batch/session helpers.
- `src/protocolReplay.ts` / `src/replayStores.ts`: replay/nonce dedup caches and store interfaces (in-memory, Redis, KV, Durable Object).
- `src/protocolAgent.ts`: session abstraction and auto-response loop.
- `src/agentAdapter.ts`: drop-in raw-message adapter for AI framework integration.
- `src/frameworkAdapters.ts`: framework bridge helpers (LangChain/LlamaIndex message mapping + JSON-RPC MCP-style bridge).
- `src/mcpGateway.ts`: line-based JSON-RPC gateway runtime over signed protocol internals (`createAipMcpGatewayRuntime`).
- `src/mcpWrapper.ts` / `src/mcpTransports.ts`: MCP server wrapping/transport helpers.
- `src/gateway.ts`: verifying HTTP reverse-proxy gateway (`createGateway`); `defaultPolicy` controls unmatched-route behavior — see "Non-obvious behavior" below.
- `src/keyRegistry.ts`, `src/keyInfra.ts`, `src/keyRotation.ts`: key material lookup, `.well-known` key serving, rotation.
- `src/rateLimiter.ts`, `src/routePolicy.ts`: per-route rate limiting and policy matching used by the gateway.
- `bin/7h3.ts`: the `7h3` CLI (keygen/sign/verify/inspect/gateway/keys serve/add scaffolds); imports the package's own public subpaths (`@7h3/protocol/gateway`, etc.), not relative `src/` paths, so it works both under `tsx` and compiled to `bin/7h3.js`.
- Benchmark harnesses:
  - `scripts/bench-protocol-e2e.ts` (closed-loop inproc/http/ws + agent-loop latency/throughput matrix, stage-level timing for build/canonicalize/mac/queue/transport/verify/decode)
  - `scripts/bench-protocol-openloop.ts` (open-loop contention with http/ws + batch modes; supports adaptive search for max sustainable ops/s at p99/drop thresholds)
  - `scripts/bench-diff.ts` (baseline vs candidate regression check for ops/s and p99)
- Shared cross-language vectors live in `conformance/7h3_v0_1.json` (and `conformance/7h3_v0_1_binary.json` for the binary wire format); TypeScript, Python, and Rust conformance tests should stay aligned to these fixtures.
- Tests live in `src/*.test.ts` plus CLI/script process tests in `scripts/*.test.ts` (no custom Vitest config/setup file).

## Non-obvious behavior to preserve
- Protocol verification defaults to signed envelopes (`requireSignature: true`) and needs a `secretResolver` for inbound signature checks.
- For non-HMAC signatures (e.g. `Ed25519`), use `signatureResolver` in transport/session options to provide algorithm-specific verification material.
- Use `DistributedReplayCache` from `src/protocolReplay.ts` for multi-node replay defense (shared store reserve semantics).
- `createGateway()`'s `defaultPolicy` defaults to `'allow'` for unmatched routes when unset — production configs should always set `defaultPolicy: 'deny'` explicitly (see `docs/GATEWAY.md`).
- A gateway without a configured `replayStore` verifies signatures/TTL but does not dedupe nonce reuse; production and horizontally-scaled deployments need a shared store (Redis/KV/Durable Object).
- Configure `maxClockSkewMs` in receive/session options when deployments need stricter/flexible time-skew tolerance.
- Use `telemetry` (`receiveEnvelope`) and `onAuditEvent` (`createAipMcpGatewayRuntime`) to emit rejection and policy traces.
- Stable JS consumer import path is `@7h3/protocol` (from `package.json` `exports`); every documented subpath maps to the same bundle.
- HMAC helpers depend on Web Crypto (`crypto.subtle`); runtimes without it will throw.
- Protocol canonicalization is explicit and order-sensitive (`body` then `header`, each field in fixed key order); changing field order will break signature compatibility.
- HMAC key import is cached (bounded map) in `src/protocol.ts`; preserve cache behavior for high-throughput signing/verification.
- Compact wire format uses short keys in transport (`v, mid, ts, ttl, s, r, n, i, c, cap, cid, sig`) and must map losslessly to canonical envelope fields before verification; compact signatures can include `sig.a` for algorithm (`HS256` default if omitted).

## Instruction files present
- No repo-local agent instruction files were found besides this `AGENTS.md`.
