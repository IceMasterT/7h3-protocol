# Install: Post-quantum signatures

ML-DSA (NIST FIPS 204) signatures, for when Ed25519's long-term security
matters more than signature size.

```bash
npm install @7h3/protocol-pq @7h3/protocol
```

`@7h3/protocol` is a peer dependency.

## Use

```ts
import {
  generatePqKeyPair,
  signEnvelopePq,
  verifyEnvelopePq,
} from '@7h3/protocol-pq'
import { createEnvelope } from '@7h3/protocol'

const { publicKey, privateKey } = generatePqKeyPair()   // ML-DSA-65 by default

const envelope = createEnvelope({ sender: 'agent@example.com', intent: 'TASK', content: 'hello' })
const signed = await signEnvelopePq(envelope, privateKey)

await verifyEnvelopePq(signed, publicKey)   // → true
```

The third argument to `signEnvelopePq` is the **algorithm**, not a key id:

```ts
const kp = generatePqKeyPair('ML-DSA-87')
const signed = await signEnvelopePq(envelope, kp.privateKey, 'ML-DSA-87')
```

Or use the pinned helpers directly:

```ts
import { signEnvelopeMlDsa65, verifyEnvelopeMlDsa65,
         signEnvelopeMlDsa87, verifyEnvelopeMlDsa87 } from '@7h3/protocol-pq'
```

## Trade-offs

ML-DSA signatures are **substantially larger** than Ed25519 — kilobytes rather
than 64 bytes. That matters for header-carried envelopes and for anything
bandwidth-sensitive. Use it where post-quantum resistance is a stated
requirement, not by default.

## Python

```bash
pip install 7h3-protocol
```

```python
from protocol_7h3.pq import ...   # requires dilithium-py
```

ML-DSA-44 is available in the **Python** SDK only; TypeScript exposes ML-DSA-65
and ML-DSA-87.

## Wire compatibility

The wire version is unchanged — `7h3/0.1`. Only the signature algorithm
identifier differs, so a peer that does not implement ML-DSA will reject the
signature rather than misinterpret the envelope.
