# Install: Browser

```bash
npm install @7h3/protocol-browser
```

Pure Web Crypto, zero dependencies, `sideEffects: false` so it tree-shakes.

## Use

> **This SDK's API differs from the core's.** It is a self-contained
> implementation, so the names are shorter and `createEnvelope` takes a nested
> `body` rather than flattened `intent`/`content`. The wire format is identical:
> an envelope signed here verifies in every other SDK, and vice versa — enforced
> by a parity test that compares canonical bytes and every validation
> diagnostic.

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
  body: { intent: 'TASK', content: 'hello' },   // nested, unlike the core
  ttlMs: 60_000,
})

const signed = await signEnvelope(envelope, privateKey, 'k1')
await verifyEnvelope(signed, publicKey)   // → true (a plain boolean)
```

## Validation

```ts
const diagnostics = validateEnvelope(signed)
// → [{ level: 'error', message: 'ttlMs exceeds maximum allowed 86400000 ms' }]
```

Enforces exactly what the other SDKs enforce: the wire version, presence of
`messageId` / `sender` / `nonce`, finite `timestampMs` / `ttlMs`, the 24h
`MAX_TTL_MS` ceiling, the 30s `MAX_CLOCK_SKEW_MS` future-timestamp ceiling, and
expiry. `isEnvelopeExpired` fails closed on a non-finite timestamp or TTL.

## Requirements

- **Secure context.** `crypto.subtle` is unavailable over plain HTTP.
  `localhost` counts as secure.
- Ed25519 in Web Crypto requires a current browser. Where it is missing, use
  HMAC (`signEnvelopeHmac`) instead.

## Key handling

**Do not ship a private key to the browser.** A page-generated key is fine for
signing that visitor's own session artifacts, but anything representing your
*origin's* identity must be signed server-side or at deploy time.

That split is exactly what [the WebMCP guide](./webmcp.md) implements: a
per-session key in the page for grants and receipts, and a separate origin
identity key — which the browser never sees — for the signed tool manifest.

## Building agent tools?

If you are giving a browser agent access to your page, use
**[@7h3/protocol-webmcp](./webmcp.md)** instead. It adds capability scoping,
replay protection and signed receipts on top of this.
