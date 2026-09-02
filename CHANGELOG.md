# Changelog

All notable changes to `@7h3/protocol` are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## v0.6.7 — `@7h3/protocol` 0.6.2

Findings from a fourth adversarial pass, this time over security controls that
had only ever been read, never attacked.

### Security

- **Revoking a keyId left Ed25519 fully valid.** `RevocationRegistry`'s two
  credential paths disagreed: `getSharedSecret` receives both a keyId and a
  sender and checked both, while `getPublicKey` receives only a sender and
  checked only that. So `revoke('k1')` blocked the HMAC credential and silently
  did nothing for Ed25519 — a revoked, compromised key kept authenticating.

  A registry lookup is keyed by sender and structurally cannot see
  `signature.keyId`, so this could not be fixed in place. Added
  `isEnvelopeRevoked(envelope)`, which checks both the sender and the keyId the
  envelope was signed under, and documented which identifier `revoke()` affects
  — and that `RevocationStore` is the right tool for fleet-wide
  `(sender, keyId)` revocation.

- **Rate-limiter eviction was a rate-limit reset.** The key map is LRU-bounded,
  and evicting a key sitting at its quota restores its full allowance, so
  pushing enough distinct keys through the store cleared a victim's limit.
  Verified: a victim blocked after three requests was allowed again after a
  500-key flood.

  Eviction now runs in order — fully-expired windows first (they hold no live
  state), then keys under quota (losing their state grants nothing), and keys at
  or over quota only as a last resort. The bound is still real and documented:
  with more concurrently-active keys than `maxKeys`, something live must go.

### Verified clean under attack

The stream binding rejected all seven attacks — dropped chunk, reordered
chunks, tampered chunk content, removed final frame, cross-stream splice, and
verification under a foreign key. Signed responses rejected tampered bodies,
missing headers and foreign keys. The gateway rejected all nine, including a
capability token attempting to bypass `allowedSenders`, and a post-dated
envelope. Webhooks rejected all nine malformed and replayed cases. Cloudflare's
middleware fails closed on any `DEFAULT_POLICY` other than exactly `'allow'`,
the KV key registry percent-encodes both identifiers, and the KV replay race
window is documented with a pointer to the Durable Object store. `mcpWrapper`
pins `requireSignature: true` after the option spread, so it cannot be
overridden.

## v0.6.6 — queue payload integrity (TypeScript, Python, Rust)

### Security

- **The queue binding accepted an unsigned payload.** `signQueueMessage` writes
  the payload twice: into `envelope.body.content`, which the signature covers,
  and into a sibling `payload` field, which it does not. `verifyQueueMessage`
  verified the envelope and then returned the **sibling** field.

  An attacker could therefore take any validly signed queue message, replace
  `payload` with anything at all, and the signature would still verify while the
  consumer acted on attacker-controlled data. Demonstrated end to end: a message
  signed as `{"job":"reindex","amount":10}` was accepted returning
  `{"job":"DROP TABLE users","amount":1000000000}`.

  A complete integrity bypass on a transport whose entire purpose is integrity.
  Present in TypeScript, Python and Rust — every SDK that ships a queue binding.
  Go has none and is unaffected. The returned payload is now required to
  serialize exactly to the signed content, using the same serialization the
  signing side uses, so honest messages are unaffected.

  `consumeWebhook` was audited for the same shape and is safe: it parses the
  verified payload itself rather than a sibling field.

### Added

- Regression tests in all three SDKs covering a swapped payload, a removed
  payload, a subtly altered numeric field, string-payload round-trips, and
  `verifyQueueBatch` inheriting the check.

## v0.6.5 — `@7h3/protocol-threshold` 0.6.1

### Security

- **`splitPrivateKey` silently corrupted any key that was not a 32-byte BLS
  scalar.** Shares carry a 32-byte field element, but nothing checked the input.
  Splitting a 48-byte Ed25519 PKCS8 key produced shares that "reconstructed"
  into a *different* 32-byte key, with **no error thrown**. A 32-byte value at
  or above the BLS field order was likewise reduced by `fieldMod` and
  reconstructed to a different value.

  For a key-recovery primitive this is the worst possible failure mode: it only
  surfaces when the backup is finally needed. Both cases now throw, naming the
  likely mistake.

  Found by exercising the published tarballs rather than the working tree.

### Added

- `scripts/verify-published-packages.mjs` — installs every 7h3 package fresh
  from the registry and asserts 47 properties against the real artifacts:
  signing and tamper detection, every validation rule, CBOR depth and prototype
  pollution limits, delegation containment, the full WebMCP authorization model
  (grants, spend ceilings, replay, receipt tampering and deletion, manifest
  verification, tool-surface poisoning), and cross-SDK interop in both
  directions. A green unit suite says the source is correct; this says the
  artifact a user installs is.

Only `@7h3/protocol-threshold` changes version, to 0.6.1.

## v0.6.4 — `@7h3/protocol-mcp` 0.6.2

### Fixed

- **`@7h3/protocol-mcp@0.6.1` could not start.** Running it failed immediately
  with `ERR_MODULE_NOT_FOUND: Cannot find module '.../dist/scaffold'`. The
  regression was introduced in this release series by splitting `scaffold.ts`
  and `version.ts` out of `index.ts`: `tsc` does not rewrite specifiers when
  emitting ESM, so `from './scaffold'` stays extensionless and Node's resolver
  rejects it. The package was a single file before that split, which is why it
  had never been exposed. 0.5.6 is unaffected.

  Every unit test still passed, because they import the modules directly rather
  than launching the built server.

### Added

- `npm run smoke` in `mcp-server` — packs the tarball, installs it, **launches
  the built server and drives a real MCP session over stdio**: `initialize`,
  `tools/list`, then a `tools/call` of `7h3_generate_keypair`, asserting the
  server identifies itself, lists the expected tools, and returns a keypair.
  Importing the entry point would not have caught this; only starting the
  binary does. Verified to fail with `server exited early (code 1)` against the
  broken build. Wired into CI and the publish job.

Only `@7h3/protocol-mcp` changes version, to 0.6.2.

## v0.6.3 — `@7h3/protocol-browser` 0.6.1

`@7h3/protocol-browser` had been stuck at 0.4.0 with no build tooling and no
publish job. It is a self-contained reimplementation of the wire format — it
shares no code with `src/` — and it had drifted badly.

### Security

- **The browser SDK performed no validation at all.** It exposed only
  `isEnvelopeExpired`, and accepted every malformed envelope the other SDKs
  reject: a `ttlMs` of a year, a `timestampMs` a year in the future, `NaN` or
  `Infinity` in either field, an empty nonce, and a foreign wire version.
  Publishing it version-matched with the hardened SDKs would have shipped a
  package with none of the hardening.

  It now exports `validateEnvelope` enforcing exactly the same rules, with
  identical diagnostic messages, plus `MAX_TTL_MS` and `MAX_CLOCK_SKEW_MS`.

- **`isEnvelopeExpired` failed open on non-finite input.** `NaN + NaN < now` is
  false, so an envelope with a `NaN` timestamp or TTL was reported as *not*
  expired. It now fails closed.

### Added

- Build tooling: the package had no `tsconfig.json` and no build script, yet
  `package.json` pointed at `index.js` and `index.d.ts` that did not exist in
  the repository. It now builds to `dist/`, matching the other SDKs.
- `npm run smoke` — packs, installs and imports the tarball under plain Node,
  asserting sign/verify, tamper detection, and each validation rule. Wired into
  CI and the publish job.
- `src/browserParity.test.ts` — since this SDK shares no code with the core,
  only a test keeps them in step. It compares canonical bytes, round-trips
  signatures core↔browser in both directions, and asserts both SDKs emit
  identical diagnostics for twelve malformed envelopes.
- `publish-browser` job, and a package `README.md` (which `files` already
  referenced but did not exist).

### Fixed

- `docs/install/browser.md` documented the core's flattened
  `createEnvelope({ sender, intent, content })`. This SDK takes a nested
  `body`. The smoke test caught it.

Only `@7h3/protocol-browser` changes version, to 0.6.1.

## v0.6.2 — `@7h3/protocol-webmcp` 0.6.1

### Fixed

- **`@7h3/protocol-webmcp@0.6.0` was published broken.** Importing it threw
  `ERR_MODULE_NOT_FOUND: Cannot find module '.../dist/guard'`. TypeScript does
  not rewrite module specifiers when emitting ESM, so a source import of
  `'./guard'` stays `'./guard'` in the output, and Node's ESM resolver requires
  the explicit `.js`. All relative specifiers now carry it.

  The unit suite could not have caught this: vitest resolves extensionless
  imports happily, so all 61 tests passed against a build that no consumer
  could import. Only the bundled core, `-pq` and `-threshold` escaped it — they
  are single-file packages with no relative imports.

### Added

- `npm run smoke` in `sdk/webmcp` — packs the real tarball, installs it into a
  scratch project, and imports it under plain Node, exercising a refusal, an
  allowed call, a bound spend cap, receipt-chain verification and manifest
  verification. Verified to fail with the exact `ERR_MODULE_NOT_FOUND` against
  the broken build and pass against the fix. Wired into both CI and the publish
  job, so this class of defect cannot reach a registry again.

### Changed

- npm publish steps now treat npm's own "cannot publish over the previously
  published versions" as success. A newly created package's document can lag
  the publish endpoint, so the pre-existing "check if already published" step
  reported *not published* for `@7h3/protocol-webmcp@0.6.0` moments after it
  was published, and the job failed re-publishing it. The intent of that check
  is idempotency, not novelty.

Only `@7h3/protocol-webmcp` changes version, to 0.6.1. Everything else stays as
published.

## v0.6.1 — `@7h3/protocol-mcp` only

### Fixed

- `@7h3/protocol-mcp` failed to build during the v0.6.0 publish:
  `src/scaffold.test.ts(2,38): error TS2307: Cannot find module 'vitest'`. The
  package's `tsconfig.json` compiled all of `src`, which now includes a test
  file, but its tests run under the repo-root vitest and `vitest` is not a
  dependency here. It typechecked locally only because Node resolution walks up
  into the root `node_modules`; the publish job installs the package in
  isolation, where there is nothing to walk up to. Test files are now excluded
  from the build, verified against an isolated `npm ci` that mirrors CI.

Only `@7h3/protocol-mcp` changes version. Every other package remains at 0.6.0,
which is already published; the workflow's idempotency checks skip them.

## v0.6.0

Security release. Every SDK tightens envelope acceptance, and a new package
brings the protocol to WebMCP. **Wire format is unchanged (`7h3/0.1`)** — only
what each SDK is willing to accept has changed, so peers interoperate exactly
as before.

### Added

- **`@7h3/protocol-webmcp`** — signed, capability-scoped, receipted WebMCP
  (`document.modelContext`) tools. Three primitives: manifests signed by the
  origin at deploy time so an injected lookalike tool is detectable; scoped,
  expiring, revocable grants with spend ceilings bound *inside* the signed
  token; and a hash-chained receipt log recording every call, allowed and
  refused. Grants are held page-side by default, so the token never passes
  through the agent.
- `webmcp` scaffold target in both `7h3 add` and the MCP server's
  `7h3_scaffold`.
- `docs/install/` — a guide per install surface, including WebMCP and ChatGPT.
- `MAX_CLOCK_SKEW_MS` (TypeScript, Python, Rust, Go) and `MAX_CBOR_DEPTH`
  (TypeScript).

### Changed

- **`README.md` rewritten to match the shipped API surface.** Many examples were
  aspirational and had never matched the real code: `createEnvelope` shown with
  three positional arguments (the real signature takes a single options object),
  `verifyEnvelopeEd25519` / `verifyEnvelopeHmac` documented as returning
  `{ ok, error }` (they return a plain boolean), and `createWsBinding`,
  `grpcSigningInterceptor` / `grpcVerifyingInterceptor`, `createKeyRotator`, and
  a Python/Rust `generate_keypair()` that exist in no SDK. Replaced with the real
  `wrapWebSocket`, `signGrpcCall` / `withGrpcVerification`, `KeyRotationManager`,
  and verified per-SDK keygen patterns. Also corrected `RoutePolicy.pathGlob` to
  `path`, the reversed argument order on `matchPolicy` / `isAllowedSender`, and
  the `SlidingWindowRateLimiter`, `createCachingKeyRegistry`, and
  `createAuditLog` shapes.
- The README's CLI and Gateway sections assumed a `--config <yaml>` flag that was
  never implemented — rewritten against the real flag-based CLI. The Docker
  section claimed a published `ghcr.io` image that no CI job produces — rewritten
  to build locally from the repo `Dockerfile`.
- `docs/assets/banner-github.png` regenerated at its real 1280x400 size (478
  tests, 5 transport bindings, v0.5.6).

### Security

- **`MAX_TTL_MS` bounded nothing.** `validateEnvelope` never rejected a
  post-dated timestamp, and `verifyHttpEnvelope` calls only `validateEnvelope` —
  the clock-skew check lived solely in `protocolTransport`. On the primary HTTP
  path a sender could set `timestampMs` a year ahead with a legal 24h `ttlMs`
  and keep an envelope valid, and replayable, for a year. Now bounded at 30s
  across all four SDKs.
- **Python accepted `null` and non-string identity fields.** Presence checks
  used `str(value).strip()`, which renders `None` as `"None"`, `False` as
  `"False"` and `0` as `"0"` — all non-empty. `"nonce": null` passed validation
  with no replay nonce at all; `"sender": null` passed with no identity.
- **Python raised instead of rejecting on malformed numbers.** `"ttlMs": "abc"`,
  `NaN`, `Infinity` or `null` threw out of `validate_envelope` — an unhandled
  exception in a request handler, on input straight off the wire.
- **Rust never checked for a missing nonce**, so it accepted an envelope with no
  replay-protection primitive. TypeScript, Python and Go all rejected it.
- **Unsound delegation scope containment.** `pathGlobIsSubset` returned true as
  soon as a parent segment was `**`, even with no child segments left — but
  `a/**` matches `a/x` and never bare `a`, so a child of `a` reached a path its
  parent could not.
- **CBOR had no nesting bound.** `0x81` is "array of 1", so 50 KB of repeated
  `0x81` nested 50 000 deep and overflowed the decoder's stack — reachable
  through the HTTP CBOR binding. Bounded at 64 per RFC 8949 §10.
- **`verifyHttpEnvelope` threw on attacker-chosen input.** Both signature
  branches dereferenced `opts.keyRegistry` unguarded, so an HMAC envelope sent
  to a registry-less server raised a `TypeError` inside the handler instead of
  returning a clean refusal. Now fails closed.

### Fixed

- `bin/gateway-cli.test.ts` spawns `bin/7h3.ts` as a separate process, so it
  resolves `@7h3/protocol` from disk and needs `dist/` — but `ci.yml` ran tests
  before the build. CI had been red since 2026-08-08; a `pretest` hook fixes it
  everywhere, so `npm test` now works on a fresh clone.
- The open-loop benchmark crashed the whole run at high concurrency: a client
  destroying a stream first makes `respond()` throw `ERR_HTTP2_INVALID_STREAM`
  *synchronously*, so the stream `error` listener never saw it and the throw
  inside a `catch` escaped unhandled. `npm run release:gate` could not complete.
- `@7h3/protocol-mcp` hardcoded `@7h3/protocol-mcp@0.5.0` in six places while
  shipping 0.5.6, so every generated install config pinned a stale release. Now
  derived from `package.json`.
- Peer ranges widened from `^0.5.0` to `>=0.5.0 <1.0.0`. Under 0.x semver
  `^0.5.0` means `<0.6.0`, so this release would otherwise have broken every
  satellite package's peer resolution.

### Note for upgraders

Validation is strictly tighter. An envelope that previously passed will now be
rejected if it is post-dated by more than 30s, carries a non-string or missing
nonce or sender, or carries a non-finite `ttlMs`/`timestampMs`. All of those
were already invalid in principle; they are now enforced consistently in every
SDK. Wire format unchanged: `7h3/0.1`.

## v0.5.6 — 2026-08-08

### Fixed

- CLI build regression that broke v0.5.5's npm publish. `bin/7h3.ts` passed an
  `InMemoryRedisLikeClient` straight to `RedisReplayStore`, which takes an
  options object (`{ client, redisUrl, keyPrefix }`) — and the two interfaces
  were never compatible in the first place. Replaced with a small
  `InMemoryCliReplayStore` implementing the gateway's `ReplayStore` interface
  directly; a single-process CLI store needs no Redis abstraction. Only
  `tsc -p tsconfig.bin.json` (what `package:protocol` and `publish.yml` run)
  catches this class of error — the root `tsc --noEmit` does not compile
  `bin/7h3.ts`'s dynamic imports against built `dist/` output.

### Release note

crates.io and PyPI published `v0.5.5` successfully — neither artifact includes
`bin/7h3.ts` — and only the npm publish failed. Rather than force-move an
already-pushed tag, all six targets were bumped to `v0.5.6`.

Wire format unchanged: `7h3/0.1`.

## v0.5.5 — 2026-08-08

### Security

- **Gateway capability-token auth bypassed `allowedSenders` and rate limiting.**
  The capability path returned `ok: true` immediately; both checks now run on
  every auth path through a shared post-auth check.
- **Path-traversal bypass in the gateway.** Request paths are now normalized once
  and the normalized path is used for both policy matching and upstream
  forwarding. `x-7h3-verified` is no longer set on requests that skipped
  verification.
- **Capability delegation chains accepted escalation** — broader scope, longer
  TTL, and `maxDelegations: 0` all passed verification. Also fixed a
  glob-containment bug that treated `**` as narrower than `*`.
- **Non-finite `timestampMs` / `ttlMs` defeated TTL expiry, clock-skew, and replay
  checks** in `protocol.ts`, `protocolTransport.ts`, and `protocolReplay.ts`.
- **CBOR map decoding allowed `__proto__` prototype pollution**; envelope field
  decoding now validates types instead of blindly casting.
- **`mcpWrapper`'s `requireSignature` could be silently overridden to `false`**
  through option spread order.
- **Key revocation only blocked Ed25519**, not the same key's HMAC shared-secret
  path; unrecognized sender IDs no longer fall back to the current key.
- **Webhook and WebSocket bindings had no replay protection** — a captured valid
  message could be replayed indefinitely inside its TTL window. Both now accept
  an optional `replayCache` (`InMemoryWebhookReplayCache` included).
- **`SlidingWindowRateLimiter` grew without bound** while tracking unique senders;
  its key map is now LRU-evicted.
- **The CLI refuses to start an unverified passthrough gateway** without
  `--allow-unverified`. Added `--private-key-file` and env-var alternatives to
  `--private-key` so keys stop leaking through shell history and process
  listings; all HTTP servers gained error handlers.
- **Code-generation injection in `mcp-server`**: user-supplied `sender`,
  `upstream`, `serverAgentId`, and `clientAgentId` are now escaped before being
  interpolated into the templates emitted by `7h3_scaffold` and
  `7h3_wrap_mcp_server`.
- Cloudflare hardening: `wrangler.toml` was missing KV bindings for the staging
  and production environments (Wrangler does not inherit them); KV registry keys
  now percent-encode sender and keyId to prevent delimiter collisions between
  senders; Durable Object cleanup alarms use each entry's real TTL/window instead
  of a hardcoded 5-minute sweep; `DEFAULT_POLICY` now fails closed on any value
  other than exactly `'allow'`.

### Fixed

- Dependency advisories closed across every workspace: `cryptography`
  49.0.0 → 50.0.0 (GHSA-g6cj-pr64-35w5 — a PKCS#7 Bleichenbacher oracle;
  CI/test-only for the Python SDK, which has no runtime dependencies and never
  touches PKCS#7), `nanoid` (GHSA-2v37-7h3g-55p8) in root, `mcp-server`,
  `sdk/pq`, `sdk/threshold`, and `cloudflare`, and an `undici` 7.29.0 override in
  `cloudflare/` closing three advisories pulled in through
  `wrangler` → `miniflare`.

Wire format unchanged: `7h3/0.1`.

## v0.5.4 — 2026-08-03

### Changed

- **License changed from MIT to Apache-2.0.** 7h3 Protocol is a wire protocol
  meant to be implemented independently. Apache-2.0 §3 supplies the express,
  irrevocable patent grant and the patent-retaliation clause that MIT lacks, and
  it is the license foundations hosting protocol work expect. Relicensing is
  clean now: copyright is held solely by IceMasterT, the only non-maintainer
  commits are mechanical dependabot bumps, and no CLA or DCO is in effect.
- All eight publishable artifacts now declare Apache-2.0 and carry the license
  text at their own package root: `@7h3/protocol`, `@7h3/protocol-mcp`,
  `@7h3/protocol-pq`, `@7h3/protocol-threshold`, `@7h3/protocol-browser`,
  `protocol-7h3` (crates.io), `7h3-protocol` (PyPI), and the Go module.
- `cloudflare/package.json` declared no license at all; now `Apache-2.0`.

### Security

- **Critical: gateway rate limiting was backed by in-process state** that reset on
  restart — now backed by persistent state.
- Queue bindings gained TTL and replay protection.
- HMAC shared-secret lookup is now bound to the claimed sender.
- Rust private keys are zeroized on drop and redacted from `Debug` output.
- `/metrics` is gated by default, and `ttlMs` is capped at 24 h across all SDKs.
- `@7h3/protocol-pq` no longer derives `keyId` from private key material.

### Fixed

- `scripts/prepare-aip-package.ts` hardcoded `license: 'MIT'` independently of
  `package.json` and never copied a license file into `dist/npm-protocol`. Every
  published `@7h3/protocol` tarball to date has shipped with **no license text**,
  including v0.5.3, despite the repo carrying a `LICENSE` since v0.5.2. The
  script now declares Apache-2.0 and copies `LICENSE` and `NOTICE` into the
  tarball.
- `sdk/rust/Cargo.toml` `include` paths resolve against the package root
  (`sdk/rust/`), so the repo-root `LICENSE` could never reach crates.io. Every
  published `protocol-7h3` crate has shipped with no license text. `include` now
  lists `LICENSE` and `NOTICE`.
- `mcp-server/package.json` `files` allowlist omitted `NOTICE`. npm force-includes
  `LICENSE` but not `NOTICE`, so the attribution notice would not have shipped.
- **`@7h3/protocol/<subpath>` imports were broken in the shipped package** —
  `gateway`, `http`, `key-registry`, and the rest resolved to per-module `dist`
  files that vite's single-bundle lib build never produced. This was live, not
  just a publish-artifact bug: `cloudflare/src/worker.ts` and `middleware.ts`
  import `createGateway` from `@7h3/protocol/gateway`, and that import threw
  `ERR_MODULE_NOT_FOUND`. Every subpath's `import` condition now points at
  `dist/protocol/index.js` (types stay per-module).
- **`@7h3/protocol-pq@0.5.0` was live and broken on npm.** Its `main`/`types`/
  `exports` pointed at `./index.js`, but a `rootDir` reaching across the monorepo
  produced deeply nested paths like `dist/7h3-protocol/sdk/pq/src/index.js` that
  never matched, so importing it gave `ERR_MODULE_NOT_FOUND`. `sdk/pq/src/index.ts`
  now imports from the public `@7h3/protocol` package it already declares as a
  peer dependency, with a self-contained `rootDir: ./src`. Added
  `prepublishOnly` build steps to `sdk/pq` and `sdk/threshold` so a
  "published without a fresh build" bug cannot recur.
- `release-gate.ts` referenced a nonexistent `bench:openloop:adaptive:ci` script,
  and `policy:validate` had no default path — `npm run release:gate` now runs.
- The `Dockerfile` swallowed `build:protocol` failures with `|| true`; the build
  must now succeed, since the runtime stage ships `bin/7h3.js` and runs it with
  plain `node` instead of tsx-executing TypeScript source.
- Documentation drift from the pre-rename repo: wrong clone URL, nonexistent npm
  scripts, and references to UI files that do not exist here in
  `docs/CLEAN_CLONE_RUNBOOK.md` and `docs/AGENTS.md`; `aip_*` tool names in
  `mcp-server/README.md`; the `aip/0.1` wire version in `CONTRIBUTING.md`;
  `AIP_*` env var names in `docs/MCP_WRAPPER.md`; and six operational docs still
  worded for "GLUV".

### Added

- `NOTICE` — attribution notice required to propagate under Apache-2.0 §4(d),
  recording copyright in IceMasterT.
- `## License` section in `README.md`. There was previously only a badge.
- `createProductionGateway()` — throws unless `defaultPolicy` is explicitly
  `'deny'` and a `replayStore` is set, instead of silently allowing unmatched
  routes through unverified or losing replay protection across instances.
  `createGateway()` now warns once when a signature-requiring policy has no
  `replayStore`.
- `scripts/smoke-test-package.ts` — packs the real npm artifact and imports every
  documented subpath plus the CLI bin through `node_modules`.
- `npm run install:all` — restores `sdk/pq` and `sdk/threshold` alongside the root
  install. Previously undocumented, so a fresh clone's root test run failed on
  missing `@noble/*` deps.
- Compiled CLI: `bin/7h3.ts` is built to `bin/7h3.js` and shipped in the publish
  artifact, with internal dynamic imports rewritten to the package's own public
  subpaths so it works compiled, not just under tsx.
- Release pipeline: PyPI trusted publishing, crates.io publishing via OIDC
  trusted publishing (no long-lived `CARGO_REGISTRY_TOKEN`), and `publish-pq` /
  `publish-threshold` / `mcp-server` jobs, all gated on `publish-protocol`. Every
  publish job is idempotent and skips work already published.

### Downstream note

Releases up to and including `v0.5.3` were published under MIT. That grant is
irrevocable and is not being withdrawn; anyone who obtained those versions keeps
their MIT rights to them permanently. Apache-2.0 applies from `v0.5.4` onward.

Apache-2.0 is incompatible with GPLv2-only code (GPLv3 is unaffected). Projects
vendoring a 7h3 Protocol SDK into a GPLv2-only codebase should pin `v0.5.3`.

Wire format unchanged: `7h3/0.1`.

## v0.5.3

### Changed

- Internal type-quality sweep: eliminated every `any` from production `src/`
  (typed `WebSocketLike` listeners, structural `BufferCtorLike`, `unknown`
  casts), zeroed out ESLint (62 → 0) and `tsc --noEmit` (40 → 0). No behavior
  change; all 395 tests pass.
- Supply-chain hardening: all GitHub Actions pinned to commit SHAs, gitleaks
  secret-scan workflow, `tsc` + fuzz-smoke CI gates, CODEOWNERS,
  CODE_OF_CONDUCT, branch protection on `main`.
- Spec: RFC §5.1 now makes nonce entropy normative (CSPRNG, ≥96 bits;
  timestamp / `Math.random()` nonces forbidden).

## v0.5.2

### Security

- **Rust: constant-time HMAC verification** — `verify_canonical_payload_hmac` previously
  compared base64 strings with `==`, leaking matching-prefix length as a timing oracle.
  Now decodes the signature and uses `hmac::Mac::verify_slice` (constant-time). Brings
  Rust in line with TypeScript (`subtle.verify`) and Python (`hmac.compare_digest`).
- **Cryptographically secure nonces** — TypeScript `createEnvelope` used `Math.random()`
  for nonce/messageId defaults; the Rust envelope helper used a timestamp-only nonce
  (`n-<ms>`, zero entropy, collides within the same millisecond). Both now use CSPRNG
  output: new exported `randomHex()` (Web Crypto) in TS and `random_nonce()`
  (`getrandom`) in Rust. Capability token, key rotation, and audit log IDs also moved
  off `Math.random()`.

### Fixed

- CI/publish workflows referenced nonexistent scripts (`build:aip`/`package:aip`) and
  the old `dist/npm-aip` output path — corrected to `build:protocol`/`package:protocol`
  and `dist/npm-protocol`.
- `SECURITY.md`/`GOVERNANCE.md` still cited the pre-rebrand wire version `aip/0.1` and
  the removed `src/aip/` path — corrected to `7h3/0.1` and current paths.
- Repository URLs pointed at the old `7h3-protocol-aip` repo name across package
  manifests and docs; Cargo `documentation` link fixed to `docs.rs/protocol-7h3`.

### Added

- `LICENSE` file (MIT) — previously declared in manifests but missing from the repo.

### Removed

- Stale compiled `src/protocol.js` (drift risk next to `protocol.ts`).
- `bench-results/` JSON artifacts untracked and gitignored.

Wire format unchanged: `7h3/0.1` envelopes signed by v0.5.1 verify under v0.5.2 and
vice versa.

## v0.5.0

### New features

**Feature 1 — Distributed Redis replay cache**
- RedisReplayStore: atomic SET NX PX prevents cross-instance replay attacks
- ClusterRedisReplayStore: queries all Redis Cluster nodes
- InMemoryReplayStore improvements
- Go SDK: InMemoryReplayStore + RedisReplayStore (inject-your-client)
- Python SDK: RedisReplayStore using redis-py

**Feature 2 — End-to-end encryption (X25519 + ChaCha20-Poly1305)**
- sealEnvelope / openEnvelope: encrypt body before signing, verify before decrypting
- generateX25519KeyPair: ephemeral key pairs for forward secrecy
- Zero new dependencies: Node.js built-in crypto.ecdh + crypto.createCipheriv('chacha20-poly1305')
- Python SDK: X25519 + ChaCha20-Poly1305 via cryptography package
- Go SDK: crypto/ecdh + golang.org/x/crypto/chacha20poly1305

**Feature 3 — Capability tokens and delegation chains**
- issueCapabilityToken: scoped, time-bounded, cryptographically signed credentials
- delegateCapabilityToken: sub-delegate with equal or narrower scope
- verifyCapabilityChain: verify full A→B→C delegation chain
- Gateway integration: x-7h3-capability header accepted alongside signatures
- tokenMatchesScope: glob path matching

**Feature 4 — Streaming message signing**
- SignedStreamWriter / SignedStreamReader: per-chunk HMAC + final Ed25519
- signStream / verifyStream: convenience wrappers for arrays
- WebSocket integration: createSignedWebSocketStream / receiveSignedWebSocketStream
- Tampering detected mid-stream on the failing chunk

**Feature 5 — Prometheus metrics + OpenTelemetry**
- Protocol7h3Metrics: counters and histograms for all verification events
- renderPrometheusText: zero-dep Prometheus exposition format
- createMetricsMiddleware: serve /metrics endpoint
- CLI: 7h3 gateway --metrics-port N
- setOtelProvider / withVerificationSpan: optional OTel tracing

**Feature 6 — Post-quantum signatures (ML-DSA) — @7h3/protocol-pq**
- generatePqKeyPair: ML-DSA-65 and ML-DSA-87 keypairs
- signEnvelopePq / verifyEnvelopePq: same envelope format, alg: 'ML-DSA-65'
- Python SDK: Dilithium2/3/5 via dilithium-py
- Separate package to keep @7h3/protocol at zero runtime deps

**Feature 7 — CBOR binary wire format**
- encodeCbor / decodeCbor: zero-dep deterministic CBOR (RFC 8949)
- encodeEnvelopeCbor / decodeEnvelopeCbor: compact numeric-key encoding (~40% smaller)
- HTTP binding: Content-Type: application/7h3-cbor support
- Go SDK: EncodeEnvelopeCBOR / DecodeEnvelopeCBOR

**Feature 8 — M-of-N threshold signatures (BLS12-381) — @7h3/protocol-threshold**
- generateBlsKeyPair: BLS12-381 keypairs
- signEnvelopeBls: partial signature from one participant
- aggregateSignatures: combine M-of-N partial sigs into one
- verifyThresholdEnvelope: single verify call on aggregated sig
- splitPrivateKey / reconstructPrivateKey: Shamir Secret Sharing over BLS scalar field
- Separate package (@7h3/protocol-threshold) using @noble/curves

---

## [0.1.2] — 2026-06-05

### Added
- `SECURITY.md` — coordinated vulnerability disclosure process, 48h acknowledgement / 14-day critical patch SLA, Hall of Thanks
- `CONTRIBUTING.md` — test commands, wire-freeze policy, conformance fixture update requirement, PR workflow
- `GOVERNANCE.md` — LF Minimum Viable Governance style: single-maintainer stage, decision process, co-maintainership path
- `.github/dependabot.yml` — weekly npm and GitHub Actions dependency updates; non-security updates grouped to reduce noise
- `.github/workflows/scorecard.yml` — OpenSSF Scorecard workflow (activates when Actions billing is restored)
- `.github/workflows/publish.yml` — provenance-enabled npm publish workflow for both `@7h3/protocol` and `@7h3/protocol-mcp` (activates when Actions billing is restored)
- `src/protocolFuzz.advanced.test.ts` — 8 property-based fuzz tests via fast-check: wire decoder resilience (never throws on arbitrary input), canonicalization determinism (field-order invariant), replay cache uniqueness properties

### Changed
- README: added Ed25519 production recommendation with code snippet; added Security section linking to SECURITY.md
- `docs/MCP_WRAPPER.md`: added HMAC vs Ed25519 comparison table and Ed25519 `wrapMcpServer` example
- `mcp-server`: updated `aip_wrap_mcp_server` tool description to guide toward Ed25519 for production; HMAC boilerplate now includes a production upgrade comment

### Fixed
- README: corrected overstated fuzz status (now accurately notes property-based tests exist; formal fuzzing campaign still not done)

---

## [0.1.1] — 2026-06-05

### Fixed
- Published package was missing 21 individual `.d.ts` module files — only `index.d.ts` was included, causing TS2305 errors in any consumer using NodeNext or bundler moduleResolution. All 22 declaration files now ship with the package.
- `scripts/prepare-aip-package.ts`: copy all `.d.ts` files from `dist/aip/` instead of only `index.d.ts`

### Added
- `@7h3/protocol-mcp@0.1.0` — MCP server installable into Claude Code (`claude mcp add aip -- npx @7h3/protocol-mcp`). Five tools: `aip_generate_secret`, `aip_generate_keypair`, `aip_wrap_mcp_server`, `aip_sign`, `aip_verify`

---

## [0.1.0] — 2026-06-01

### Added

**Core protocol (`aip/0.1`)**
- `createEnvelope` / `signEnvelopeHmac` / `signEnvelopeEd25519` — envelope construction and signing over a deterministic canonical form (fixed key order).
- `verifyEnvelopeHmac` / `verifyEnvelopeEd25519` — tamper-evident verification via real WebCrypto (no hand-rolled crypto).
- `validateEnvelope` — structural + TTL + clock-skew validation with typed diagnostics.
- `receiveEnvelope` — full receive pipeline: validate → verify → replay-check, composable via `ReceiveEnvelopeOptions`.
- Wire formats: `json`, `compact` (minified), `binary` (MessagePack); encode/decode via `encodeEnvelope` / `decodeEnvelope`.
- Polyglot parity: shared conformance fixture set (`conformance/aip_v0_1.json`) proves byte-identical signatures across TypeScript, Python (`aip7h3`), and Rust (`aip7h3`).

**Replay protection**
- `InMemoryReplayCache` — single-process `(sender, messageId, nonce)` uniqueness window with TTL.
- `DistributedReplayCache` — wraps any `DistributedReplayStore`; routes batch ops through `reserveMany` when available.
- `createRedisReplayStore` — atomic `SET NX PX` reserve over a client-agnostic `RedisLikeClient` interface; batch pipeline via `reserveMany`; `errorBehavior: 'fallback' | 'reject' | 'allow'` with graceful degradation to local store and `onDegraded` hook.
- `InMemoryRedisLikeClient` — reference implementation for tests (no Redis dep required).

**Fleet-wide key revocation**
- `InMemoryRevocationStore` — single-process; supports time-bounded `untilMs`.
- `createRedisRevocationStore` — cached reads (`cacheTtlMs` default 5 s), **fail-closed default** (`errorBehavior: 'reject'`), serves stale cache during Redis outage.
- `withRevocationCheck` — wraps any `SignatureResolver`; revoked key returns `undefined` → verification fails.

**MCP hardening wrapper**
- `wrapMcpServer` — sign + replay-protect an existing MCP handler with zero handler changes; enforces recipient binding (cross-server relay defense).
- `wrapMcpClient` / `createMcpClientCodec` — sign outbound requests; enforce sender binding (response-spoof defense) and correlation binding (response-substitution defense); replay protection on by default.
- Demo: `npm run aip:mcp:wrap` — proves tampered and replayed requests rejected.

**Transport adapters**
- `serveMcpOverStdio` / `createStdioMcpClient` — newline-delimited; in-order sequential chain prevents response interleaving.
- `createHttpMcpHandler` / `createHttpMcpClient` — `node:http` handler + `fetch` client; supports `binary` wire format.
- No new runtime dependencies (uses `node:readline`, `node:http`, `node:stream`, global `fetch`).

**Key management & policy**
- Key rotation support (`keyRotation`), runtime policy (`runtimePolicy`, `policyEnforcer`), telemetry feedback hooks.
- Framework adapters (`frameworkAdapters`), agent adapter (`agentAdapter`), MCP gateway (`mcpGateway`).

### Documentation
- `docs/THREAT_MODEL.md` — full threat coverage matrix.
- `docs/DISTRIBUTED_REPLAY.md` — Redis store setup, `errorBehavior` table, operational guidance.
- `docs/KEY_REVOCATION.md` — revocation store setup, cache TTL tuning.
- `docs/MCP_WRAPPER.md` — threat coverage table, server + client usage, transport examples.

### Test coverage
- 123 tests / 22 test files — all green.
- Live-Redis integration test (`redisIntegration.test.ts`) — auto-skips if no server present.
- Python conformance: `conformance:python`.
- Rust: `conformance:rust` (7 tests).

---

[0.1.0]: https://github.com/IceMasterT/7h3-protocol/releases/tag/v0.1.0
