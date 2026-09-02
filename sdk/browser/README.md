# @7h3/protocol-browser

**7h3 Protocol — Browser/Edge SDK.** Pure Web Crypto, zero dependencies,
`sideEffects: false`.

```bash
npm install @7h3/protocol-browser
```

A self-contained implementation of the `7h3/0.1` wire format for environments
where you want the smallest possible surface: sign, verify, validate, and
attach an envelope to a `fetch`. If you need gateways, capability tokens,
replay stores or encryption, use [`@7h3/protocol`](https://www.npmjs.com/package/@7h3/protocol)
— it is also pure Web Crypto and runs in the browser unchanged.

## Use

```ts
import {
  generateKeypair,
  createEnvelope,
  signEnvelope,
  verifyEnvelope,
  validateEnvelope,
} from '@7h3/protocol-browser'

const { publicKey, privateKey } = await generateKeypair()

const envelope = createEnvelope({
  sender: 'browser@example.com',
  body: { intent: 'TASK', content: 'hello' },
  ttlMs: 60_000,
})

const signed = await signEnvelope(envelope, privateKey, 'k1')
await verifyEnvelope(signed, publicKey)   // → true
```

> `createEnvelope` takes a **nested `body`** here, unlike the core's flattened
> `{ intent, content }`. The wire format is identical either way.

## Validation

```ts
validateEnvelope(signed)
// → [] when valid, otherwise [{ level: 'error', message: '…' }]
```

Enforces the same rules as the TypeScript, Python, Rust and Go SDKs: the wire
version, presence of `messageId` / `sender` / `nonce`, finite `timestampMs` and
`ttlMs`, the 24h `MAX_TTL_MS` ceiling, the 30s `MAX_CLOCK_SKEW_MS`
future-timestamp ceiling, and expiry.

`isEnvelopeExpired` **fails closed**: a non-finite timestamp or TTL counts as
expired, because `NaN + NaN < now` is false and naive arithmetic would wave such
an envelope through.

## Signing a request

```ts
import { signRequest, ENVELOPE_HEADER } from '@7h3/protocol-browser'

const request = await signRequest(new Request(url, { method: 'POST' }), {
  sender: 'browser@example.com',
  privateKey,
  keyId: 'k1',
})
```

## Cross-SDK guarantee

An envelope signed here verifies under every other 7h3 SDK and vice versa. That
is not an aspiration — `src/browserParity.test.ts` compares canonical bytes,
round-trips signatures in both directions, and asserts that both SDKs emit
identical validation diagnostics for every malformed envelope.

## Requirements

A **secure context** — `crypto.subtle` is unavailable over plain HTTP
(`localhost` counts). Ed25519 in Web Crypto needs a current browser.

**Do not ship a private key to the browser.** A page-generated key is fine for
signing that visitor's own session artifacts; anything representing your
origin's identity must be signed server-side.

## Building agent tools?

Use [`@7h3/protocol-webmcp`](https://www.npmjs.com/package/@7h3/protocol-webmcp)
— capability scoping, replay protection and signed receipts for WebMCP tools.

## License

Apache-2.0
