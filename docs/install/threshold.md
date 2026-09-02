# Install: Threshold signatures

BLS12-381 M-of-N signing, for when no single party should be able to sign
alone.

```bash
npm install @7h3/protocol-threshold @7h3/protocol
```

`@7h3/protocol` is a peer dependency.

## M-of-N signing

Signers are identified by name throughout, and the `{ m, n }` config travels
with every call.

```ts
import {
  generateBlsKeyPair,
  signEnvelopeBls,
  aggregateSignatures,
  verifyThresholdEnvelope,
} from '@7h3/protocol-threshold'
import { createEnvelope } from '@7h3/protocol'

const signers = {
  alice: generateBlsKeyPair(),
  bob: generateBlsKeyPair(),
  carol: generateBlsKeyPair(),
}
const publicKeys = Object.fromEntries(
  Object.entries(signers).map(([id, k]) => [id, k.publicKey]),
)

const config = { m: 2, n: 3 }   // 2 of 3
const envelope = createEnvelope({
  sender: 'quorum@example.com',
  intent: 'TASK',
  content: 'release funds',
})

// Each signer signs independently — no shared secret, no coordinator.
const partials = await Promise.all([
  signEnvelopeBls(envelope, signers.alice.privateKey, 'alice'),
  signEnvelopeBls(envelope, signers.bob.privateKey, 'bob'),
])

const aggregated = await aggregateSignatures(partials, publicKeys, envelope, config)
await verifyThresholdEnvelope(aggregated, publicKeys, config)   // → true
```

Note `verifyThresholdEnvelope` takes the **aggregated** envelope, not the
original one.

## Shamir key splitting

For splitting one existing key across holders, rather than aggregating
independent signers:

```ts
import { splitPrivateKey, reconstructPrivateKey } from '@7h3/protocol-threshold'

const shares = splitPrivateKey(privateKey, 3, 5)        // m = 3, n = 5
const restored = reconstructPrivateKey(shares.slice(0, 3), 3)
```

Both take `m` and `n` positionally — `m` first.

## Which one to use

- **Aggregation** (`signEnvelopeBls` + `aggregateSignatures`) — each party keeps
  its own key and the key is never reassembled anywhere. Prefer this.
- **Shamir** (`splitPrivateKey`) — reconstructs the original private key in
  memory at the moment of use. Only appropriate where a single key must exist,
  such as recovering a legacy identity.

## Wire compatibility

The wire version is unchanged — `7h3/0.1`. Only the signature algorithm
identifier differs.
