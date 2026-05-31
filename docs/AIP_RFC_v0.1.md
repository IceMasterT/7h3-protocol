# AIP RFC v0.1 (Draft)

This document defines the normative behavior for the GLUV AI communication protocol (`aip/0.1`).

## 1. Scope

- AIP defines signed, replay-resistant envelopes for agent-to-agent communication.
- This RFC covers envelope structure, canonicalization, signing, validation, and transport expectations.

## 2. Envelope Model

An envelope has:

- `header`
  - `version` (MUST be `"aip/0.1"`)
  - `messageId` (MUST be non-empty)
  - `timestampMs` (Unix epoch milliseconds)
  - `ttlMs` (MUST be > 0)
  - `sender` (MUST be non-empty)
  - `recipient` (OPTIONAL)
  - `nonce` (MUST be non-empty)
- `body`
  - `intent` (MUST be one of `PING`, `PONG`, `CAPS`, `TASK`, `RESULT`, `ERROR`)
  - `content` (MAY be empty but SHOULD be meaningful)
  - `capability` (OPTIONAL)
  - `correlationId` (OPTIONAL)
- `signature` (OPTIONAL at format level, REQUIRED in secure profile)
  - `alg` (`HS256` in v0.1)
  - `keyId`
  - `value` (base64url)

## 3. Canonicalization (Normative)

The canonical payload used for signing and verification MUST be a deterministic JSON string with fixed key ordering.

- Top-level order MUST be: `body`, then `header`.
- `body` key order MUST be:
  - `capability` (if present)
  - `content`
  - `correlationId` (if present)
  - `intent`
- `header` key order MUST be:
  - `messageId`
  - `nonce`
  - `recipient` (if present)
  - `sender`
  - `timestampMs`
  - `ttlMs`
  - `version`

Receivers MUST verify signatures against this exact canonicalization behavior.

## 4. Signature and Integrity

- Secure profile senders MUST sign envelopes.
- Secure profile receivers MUST reject missing signatures.
- `HS256` signatures MUST be computed over canonical payload bytes (UTF-8).
- `keyId` SHOULD identify the active secret material.

## 5. Freshness and Replay

- Receivers MUST enforce freshness: reject when `timestampMs + ttlMs < nowMs`.
- Replay cache key MUST be `(sender, messageId, nonce)`.
- Re-seeing an unexpired replay key MUST be rejected.

## 6. Transport Expectations

- JSON and compact wire forms are allowed; both MUST map losslessly to the same envelope model before validation.
- Compact wire fields:
  - `v, mid, ts, ttl, s, r, n, i, c, cap, cid, sig`
- Validation and signature verification MUST occur after decoding to canonical envelope fields.

## 7. Error Semantics

Receivers SHOULD produce explicit diagnostics for:

- invalid JSON / unrecognized shape
- unsupported version
- missing required fields
- TTL expiry
- missing or invalid signature
- replay detection

## 8. Security Profile Recommendations

- Production deployments SHOULD require signatures (`requireSignature: true`).
- Secrets SHOULD rotate; overlapping accept windows SHOULD be supported by `secretResolver`.
- Deployments SHOULD apply payload size limits and rate limits per sender.

## 9. Conformance

Implementations are conformant to v0.1 if they:

- produce/accept normative envelope model
- match canonicalization behavior exactly
- pass signature verification and replay/freshness requirements
- interoperate across wire forms without semantic loss
