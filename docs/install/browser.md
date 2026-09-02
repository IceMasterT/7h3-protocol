# Install: Browser

```bash
npm install @7h3/protocol-browser
```

Pure Web Crypto, zero dependencies, `sideEffects: false` so it tree-shakes.

> **Note:** the npm release currently lags this repository (published `0.4.0`,
> repo `0.5.0`). For the newest surface, use `@7h3/protocol` directly — it is
> also pure Web Crypto and runs unchanged in the browser.

## Use

```ts
import {
  createEnvelope,
  signEnvelopeEd25519,
  verifyEnvelopeEd25519,
  generateEd25519KeypairBase64Url,
} from '@7h3/protocol-browser'

const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
const envelope = createEnvelope({ sender: 'browser@example.com', intent: 'TASK', content: 'hello' })
const signed = await signEnvelopeEd25519(envelope, privateKey, 'k1')
await verifyEnvelopeEd25519(signed, publicKey)   // → true
```

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
