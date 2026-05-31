# 7h3 Protocol AIP Threat Model (v1.0 draft)

## Scope

This model covers `aip/0.1` envelope transport and verification paths in:

- `src/gluv/protocol.ts`
- `src/gluv/protocolTransport.ts`
- `src/gluv/mcpGateway.ts`
- `sdk/rust/src/lib.rs`

## Assets

- Message integrity and authenticity
- Agent identity binding (`sender`, `keyId`, signature material)
- Freshness (TTL + replay resistance)
- Gateway policy decisions (allowlist/auth/rate-limit)

## Assumptions

- Clocks are roughly synchronized within deployment skew limits.
- Secret/private-key material is provisioned securely outside protocol logic.
- Transport channel can be observed/modified by adversaries; protocol must detect tamper.

## Threats and controls

## Tampering

- Threat: attacker modifies envelope body/header in transit.
- Controls:
  - canonical payload signing (`HS256` / `ED25519`)
  - signature verification before acceptance
  - canonical key order fixed to prevent ambiguous signing forms

## Replay

- Threat: attacker replays previously valid signed envelopes.
- Controls:
  - TTL checks (`timestampMs + ttlMs`)
  - replay cache consumption (`messageId` + `sender` + `nonce` semantics)

## Sender impersonation

- Threat: attacker signs as trusted sender with incorrect key material.
- Controls:
  - verifier resolves material by `(keyId, sender)` context
  - `signatureResolver`/`secretResolver` mapping policy in transport layer

## Algorithm confusion / downgrade

- Threat: attacker swaps `alg` or relies on omitted compact alg fields.
- Controls:
  - explicit algorithm field in canonical signature object
  - compact wire supports `sig.a`; default compatibility path only for legacy HS256
  - verifier rejects material when resolved algorithm does not match envelope signature

## Gateway abuse

- Threat: unauthorized or abusive JSON-RPC method calls.
- Controls:
  - method allowlist
  - authorization policy hook
  - rate-limit policy hook with context-aware keys

## Remaining risks (open)

- In-memory replay cache is not sufficient for distributed multi-node deployments.
- No built-in key revocation or expiry enforcement layer yet.
- No formal fuzz campaign yet for parser/canonicalization boundaries.

## v1.0 required mitigations

- Keep signature verification enabled by default in production paths.
- Deploy a shared replay store for horizontally scaled gateways.
- Enforce key lifecycle policy (rotation, expiry, revocation) in control plane.
