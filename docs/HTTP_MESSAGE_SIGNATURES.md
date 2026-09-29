# HTTP Message Signatures (RFC 9421) and Web Bot Auth

7h3's native format is the signed envelope. RFC 9421 is the standards-track way to
sign an HTTP request or response, and it is what **Web Bot Auth** builds on. This
module lets a 7h3 gateway authenticate clients that know nothing about 7h3, and
lets 7h3 agents call servers that only speak the standard.

Status: TypeScript reference implementation (`@7h3/protocol`). Not yet in the
Python, Rust or Go SDKs.

## What is implemented

- **RFC 9421**: derived components `@method`, `@target-uri`, `@authority`,
  `@scheme`, `@request-target`, `@path`, `@query`, `@query-param;name=…`,
  `@status`; header fields, including dictionary members (`;key="…"`); the `req`
  parameter for responses; algorithms `ed25519` and `hmac-sha256`; parameters
  `created`, `expires`, `nonce`, `alg`, `keyid`, `tag`.
- **RFC 9530 Content-Digest** (`sha-256`, `sha-512`).
- **Web Bot Auth**: JWK-thumbprint key ids (RFC 7638), `Signature-Agent`, JWKS key
  directory fetching.
- **Gateway**: `require: 'http-signature'` routes.

Rejected rather than ignored: the `sf`, `bs` and `tr` component parameters, and the
RSA-PSS, RSA-v1.5 and ECDSA algorithms. A verifier that silently skipped an
unsupported parameter would report "verified" for something other than what was
signed.

## Conformance

The implementation is checked against the RFC's own published values: it
reproduces the Ed25519 (B.2.6) and HMAC-SHA256 (B.2.5) signatures byte for byte,
verifies them as received, and produces the exact signature bases printed in
B.2.1, B.2.2 and Figure 1. It also reproduces the Web Bot Auth draft's Ed25519
vector A.2.1 and its JWK thumbprint for the RFC test key.

**Known discrepancy in the draft.** The signature the Web Bot Auth draft lists for
its vector A.2.2 (dictionary-form `Signature-Agent`) is not a signature over the
base the draft prints. It only verifies over a base in which the member value has
lost its quotes. RFC 9421 §2.1.2 requires strict serialization, which keeps the
quotes, and this implementation follows the RFC. A signer that reproduces that
listed vector will be rejected. The test in `src/webBotAuth.test.ts` records this.

## Signing and verifying

```ts
import { signMessage, verifyMessage, createContentDigest } from '@7h3/protocol'

const signed = await signMessage(
  { method: 'POST', url: 'https://api.example.com/pay', headers: { 'content-digest': await createContentDigest(body) } },
  {
    components: ['@method', '@authority', '@path', 'content-digest'],
    key: { alg: 'ed25519', privateKey },
    keyId: 'agent-key', tag: 'my-app', nonce: true,
  },
)
// add signed.headers['signature-input'] and signed.headers.signature to the request

const result = await verifyMessage(message, {
  resolveKey: (keyId) => keyId === 'agent-key' ? { alg: 'ed25519', publicKey } : null,
  requiredComponents: ['@method', '@authority', '@path'],
  tag: 'my-app', body, requireBodyBinding: true, nonceStore,
})
if (!result.ok) reject(result.reason)
```

### Verification is policy-driven

The verifier says what a signature must cover; a signature that is cryptographically
valid but covers too little is refused.

| Check | Failure |
|---|---|
| `requiredComponents` all covered (required and non-empty) | `insufficient-coverage` |
| `requireBodyBinding` and a body is present: `content-digest` covered and matching | `body-not-bound`, `digest-mismatch` |
| `created` present, not in the future, not older than `maxAgeMs` (default 5 min) | `missing-created`, `not-yet-valid`, `too-old` |
| `expires` not passed (`requireExpires` to insist on one) | `expired`, `missing-expires` |
| `tag` matches | `tag-mismatch` |
| Nonce single use through a `ReplayStore` | `missing-nonce`, `replayed` |
| Algorithm comes from the key you resolve, never from the message | `algorithm-mismatch` |

Only the **first** matching signature is verified. Trying several and accepting any
would let an attacker append a signature they can forge next to one they cannot; pass
`label` to choose explicitly. A rejected signature does not consume its nonce.

## Web Bot Auth

```ts
import { signWebBotAuthRequest, verifyWebBotAuthRequest, spkiToEd25519Jwk } from '@7h3/protocol'

// Client
const { headers } = await signWebBotAuthRequest(
  { method: 'GET', url: 'https://example.com/page', headers: {} },
  { privateKey, publicKey, agentUrl: 'https://bot.example.org' },
)

// Server
const r = await verifyWebBotAuthRequest(message, {
  resolveKeys: async (agentUrl) => (agentUrl === 'https://bot.example.org' ? await fetchKeyDirectory(agentUrl) : null),
  nonceStore,
})
```

- The signer covers `@authority`, `@method`, `@path` (and `@query`) by default. The
  draft's minimal profile signs only `@authority`, which proves who is calling but
  not what they are calling; such a signature can be replayed against any path or
  method on the host within its lifetime. Use `identityOnly: true` to produce the
  minimal profile, and add `requiredComponents` on the verifier to refuse it.
- **The verifier never fetches a `Signature-Agent` URL by itself.** Doing so for an
  unauthenticated caller is an SSRF vector, so you supply `resolveKeys` and apply
  your own allow-list and cache there. `fetchKeyDirectory` is a guarded helper for
  it: https only, fixed well-known path, no redirects, bounded time and size, JSON
  media type required, only well-formed public Ed25519 keys kept.
- A `Signature-Agent` header that the signature does not cover is refused
  (`bad-signature-agent`); an unsigned header is attacker-controlled.
- Web Bot Auth signatures must carry `expires`, and `maxAgeMs` defaults to 60 seconds.

## At the gateway

```ts
createGateway({
  upstream, keyRegistry, replayStore, defaultPolicy: 'deny',
  httpSignature: {
    tag: 'web-bot-auth', requireExpires: true,
    // The identity a key stands for becomes the authenticated sender.
    resolveKey: async (keyId) => lookup(keyId), // { key, sender } | null
  },
  policies: [{ path: '/crawl/**', require: 'http-signature', allowedSenders: ['bot.example'] }],
})
```

The signed target URI is rebuilt from the `Host` header (or `x-forwarded-host` only
if `trustForwardedHost` is set, which is safe only behind a proxy you control) and
the path exactly as received, so a request signed for one host or path cannot be
replayed to another. Required components default to `@method`, `@authority`, `@path`,
plus `@query` when the request has a query string. Body binding is on by default.
The resolved sender then goes through `allowedSenders`, rate limits and, if the route
sets one, step-up approval ([`APPROVAL_AND_PROVENANCE.md`](./APPROVAL_AND_PROVENANCE.md)).
Failures return `401 http-signature:<reason>`.

A derived `@query-param` name is the already percent-encoded name exactly as it
appears in the component identifier (RFC 9421 §2.2.8). Values are form-decoded and
re-encoded with the WHATWG form-urlencoded set, with space as `%20` as the RFC's
examples require.
