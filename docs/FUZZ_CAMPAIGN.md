# Fuzz Campaign

AIP employs two complementary fuzzing strategies: mutation-based harnesses for TypeScript and coverage-guided libFuzzer targets for Rust.

---

## TypeScript — mutation-based harnesses

**Location:** `fuzz/ts/`

**Run:**
```bash
npm run fuzz:ts          # both harnesses, default rounds
FUZZ_ROUNDS=200000 npm run fuzz:ts   # heavier run
npm run fuzz:ts:decode   # decoder only
npm run fuzz:ts:verify   # verifier only
```

### Harness: `harness-decode.ts`

**Target:** `decodeEnvelope`  
**Invariant:** Must never throw on any input — garbage returns `{ok: false}`, not a crash.

**Strategy:**
1. Seed corpus: conformance vectors (JSON full form + compact form) + known-bad inputs (`{}`, `[]`, `null`, `"string"`, `{`, etc.)
2. Each round: pick a mutator, apply it to the current input
3. Reset to a fresh corpus item every 500 rounds

**Mutators:**
- Bit flip at a random byte position
- Random byte insertion
- Random byte deletion
- Truncation to a random prefix length
- JSON field mutation (null, type change)
- Token substitution (e.g. `"aip/0.1"` → `"aip/0.2"`)

**Initial run result (2026-06-05):**
```
[harness-decode] rounds=50000 ok=98 ok:false=49902 crashes=0
```
No crashes. Decoder tolerates all 50,000 mutated inputs.

---

### Harness: `harness-verify.ts`

**Target:** `verifyEnvelopeHmac`  
**Invariants:**
1. Must never throw on a tampered envelope.
2. Any tampered envelope must verify as `false` (no false positives).

**Strategy:**
1. Sign a fresh baseline envelope
2. Each round: deep-clone and randomly mutate one field in `header` or `body`
3. Guard: if mutation produced no net change, force `body.content` to a sentinel value
4. Every 200 rounds: test with a fully broken envelope (`{}` headers/body)

**Mutation operators:**
- String fields: bit flip a random byte, UTF-8 round-tripped (invalid sequences → replacement char)
- Numeric fields: add a non-zero delta (−500 to −1 or +1 to +500)
- Optional fields: set to `null`

**Initial run result (2026-06-05):**
```
[harness-verify] rounds=20000 tamper-false-positives=0 crashes=0
```
No crashes, no false positives. No tampered envelope verified as valid.

---

## Rust — cargo-fuzz (libFuzzer)

**Location:** `sdk/rust/fuzz/`

**Prerequisites:**
```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

**Run:**
```bash
npm run fuzz:rust:decode         # 60-second decode fuzzing session
npm run fuzz:rust:canonicalize   # 60-second canonicalize fuzzing session

# Or run directly:
cargo +nightly fuzz run fuzz_decode --manifest-path sdk/rust/fuzz/Cargo.toml
cargo +nightly fuzz run fuzz_canonicalize --manifest-path sdk/rust/fuzz/Cargo.toml
```

### Target: `fuzz_decode`

**Target:** `aip7h3::decode_envelope`  
**Invariant:** Must never panic on any UTF-8-valid input — errors are `Err(...)`, not panics.

Input: arbitrary byte sequences converted to UTF-8 via `std::str::from_utf8`.

### Target: `fuzz_canonicalize`

**Target:** `aip7h3::canonicalize_envelope`  
**Invariant:** Calling it twice on the same envelope returns the same string (idempotence / purity).

Input: fuzz bytes carved into envelope fields (`messageId`, `content`) to exercise the canonicalization path under arbitrary field content.

---

## Coverage gaps and known limitations

| Gap | Notes |
|---|---|
| TypeScript fuzzing is mutation-based, not coverage-guided | Coverage-guided fuzzing (e.g. jazzer.js) requires Java; out of scope for CI. The mutation harnesses provide meaningful parser boundary coverage without the dependency. |
| Binary decoder (`decodeEnvelope` with `Uint8Array`) | The existing property-based tests (fast-check) cover this path (`src/protocolFuzz.advanced.test.ts`). A dedicated fuzz harness is a future addition. |
| Ed25519 verification paths | These depend on WebCrypto internals; crash surface is on the envelope parsing/canonicalization layer (covered). |
| No crash corpus retained | Extend the harnesses with a `fuzz/corpus/` directory to persist and replay interesting inputs. |
| Python | No standalone fuzz harness — Python correctness is covered by conformance vectors and the property-based TS tests. |

---

## Pre-release fuzz policy

Per `docs/RELEASE_GATE.md`, at minimum the TypeScript harnesses run at default round counts as part of every release gate check. Rust fuzzing is optional for patch releases and required for minor/major bumps.
