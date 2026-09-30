# Workload attestation and the key transparency log

Two pieces that answer "should I trust this key?" more strongly than "it is in the
registry".

Status: TypeScript reference implementation (`@7h3/protocol`).

## Workload attestation

A message signature proves someone holding a private key sent it. It does not prove
**what is running** with that key: the approved container image, the reviewed
configuration, the pinned tool list. An attestation closes that gap. A party you
trust (a CI system, a deployment pipeline, a verifier service) signs a statement:
"agent A, using public key K, was measured as `{ image: …, config: … }`". You approve
the digests you are willing to trust; a statement for any other build is refused.

```ts
import { issueAttestation, verifyAttestation, createAttestedKeyRegistry, toolPinsDigest } from '@7h3/protocol'

// Issued by the attester (for example at the end of a deployment):
const statement = await issueAttestation({
  attesterPrivateKey, attester: 'ci',
  subject: { agent: 'agent.worker', publicKey: agentPublicKey },
  measurements: { image: imageDigest, toolPins: await toolPinsDigest(approvedPins) },
  claims: { env: 'prod' }, lifetimeMs: 60 * 60_000,
})

// Verified by a relying party:
const result = await verifyAttestation(statement, {
  attesterKeys, allowedAttesters: ['ci'],
  agent: 'agent.worker', agentPublicKey,
  requiredMeasurements: { image: [approvedImageDigest] },
})

// Or make it structural: an agent without a valid attestation simply has no key.
const keyRegistry = createAttestedKeyRegistry({ base: registry, attesterKeys, allowedAttesters: ['ci'],
  requiredMeasurements: { image: [approvedImageDigest] }, getAttestation })
```

What is enforced:

- **The attester must be one you allow, with a key you registered.** Both lists are
  required and non-empty; `requiredMeasurements` must name at least one measurement with
  at least one approved digest. A verifier that would pass any authentic statement throws
  instead of running.
- **The statement binds to one agent and one key.** A statement for key K1 is refused when
  the agent's messages use K2, so an attested identity cannot be moved onto an
  un-attested key.
- **Measurements are lower-case hex SHA-256 or SHA-512 digests**, compared exactly.
  Conventional names: `image`, `config`, `policy`, `toolPins`, `sbom`, `model`.
  `toolPinsDigest` measures an approved MCP tool pin set, so "this agent is running with
  exactly these tools" is something you can attest and verify.
- **Statements are short-lived** (at most 24 hours, one hour by default), can be limited by
  `maxAgeMs`, and can be revoked with `isRevoked`.
- **`createAttestedKeyRegistry` fails closed**: any error fetching or verifying the
  statement yields no key. Positive results are cached, never beyond the statement's expiry
  and never across a change of key; negative results are not cached, so a fixed deployment
  recovers immediately. A revoked statement can remain accepted for up to `cacheMs`.

### What it does not do

7h3 verifies statements signed by an attester you trust. **It does not verify hardware
attestation evidence** (SGX, SEV-SNP, TDX, TPM quotes). If you use those, a verifier
service checks the evidence and signs a statement, and 7h3 consumes that. An attestation
is exactly as trustworthy as its attester: a compromised attester can vouch for anything.

## Key transparency log

A key registry is a table of "identity → public key". Whoever runs it can silently swap a
key, and nobody would know. The key log makes changes visible: every registration,
rotation and revocation is an entry; entries are hash-chained and signed by the operator;
the operator signs checkpoints of the form (`size`, `headHash`).

```ts
const log = new KeyLog({ operator: 'keys.example.org', operatorPrivateKey })
await log.register('agent.a', 'a-1', publicKey)
await log.rotate('agent.a', 'a-2', newPublicKey)
await log.revoke('agent.a', 'a-2', 'compromised')
const checkpoint = await log.checkpoint()      // publish; clients keep it

// Relying party:
const keyRegistry = createKeyLogRegistry({
  entries: fetchEntries, operatorPublicKey,
  trustedCheckpoint: () => myStoredCheckpoint,  // optional but what makes a rewrite detectable
})
```

Verification enforces the meaning of entries, not only the chain: entries are sequential
and chained; every entry carries the operator's signature; time never goes backwards and is
not in the future; a subject never has two active keys; only a registered subject with an
active key can rotate; only an existing key can be revoked, once; key ids are not reused; a
public key belongs to one subject, once, and **a revoked key can never be registered again,
by anyone**. The writer refuses any entry that verification would reject, so the log it
produces always verifies.

Checkpoints catch what the chain alone cannot:

- **Rewritten history.** An operator can re-sign a whole altered log and it will verify
  internally, but it will not extend a checkpoint a client saved earlier
  (`logExtendsCheckpoint`). A log cut shorter than a checkpoint fails the same way.
- **Equivocation.** Two genuine checkpoints of the same size with different heads prove the
  operator showed two different logs (`checkpointsConflict`). The pair is transferable
  evidence.
- **Monitoring.** `keyChangesFor(entries, subject, fromIndex)` lists what changed for an
  identity you care about.

`createKeyLogRegistry` returns no keys at all for a log that fails verification, or that no
longer extends your trusted checkpoint, or that cannot be fetched.

### What it does not do

It is a hash chain with a single signing operator plus signed checkpoints. It is
**tamper-evident, not tamper-proof**: it cannot stop a malicious operator from publishing a
bad key; it makes that visible to anyone who is watching, and it makes a rewrite of history
detectable to anyone who kept a checkpoint. It is not a Merkle-tree transparency log: there
are no O(log n) inclusion or consistency proofs, so verification is linear in the log size.
Split-view attacks are only detectable if parties compare checkpoints; something has to
exchange them.
