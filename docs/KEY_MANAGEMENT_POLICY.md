# 7h3 Protocol AIP Key Management Policy (v1.0 draft)

## Supported signature profiles

- `HS256` (shared secret)
- `ED25519` (asymmetric keypair)

## Key ID rules

- Every signing key must have a unique `keyId`.
- Verifiers must resolve verification material by both `keyId` and `sender`.
- Reusing the same `keyId` for different senders is prohibited.

## Rotation policy

- Rotation interval target:
  - `HS256`: every 30 days
  - `ED25519`: every 90 days
- Rotation process:
  1. Provision new key as active for signing.
  2. Keep previous key in verify-only mode during overlap window.
  3. End overlap and revoke old key.

## Revocation policy

- Immediate revocation triggers:
  - suspected credential leak
  - host compromise
  - failed integrity investigation
- Revoked keys must fail verification in resolver control plane within SLA.
- For multi-node deployments, back revocation with a shared `RevocationStore`
  (`createRedisRevocationStore`) and wrap the verification resolver with
  `withRevocationCheck` so a revoke on one node is enforced fleet-wide. The
  store fails **closed** by default: if the revocation list is unreachable, the
  key is treated as revoked. See `KEY_REVOCATION.md`.

## Storage requirements

- Do not commit secrets/private keys to source control.
- Store key material in managed secrets/KMS.
- Restrict read access to signing services and verification control plane.

## Runtime policy

- Production endpoints require signatures by default.
- `HS256` is recommended for tightly controlled private clusters.
- `ED25519` is recommended for cross-domain or multi-tenant federation.
- Use `RollingKeyring` (`src/keyRotation.ts`) for overlap windows, verify-only periods, and revocation enforcement.

## Audit requirements

- Log key activation, rotation, revocation, and failed verification events.
- Retain audit logs for incident response and compliance windows.
