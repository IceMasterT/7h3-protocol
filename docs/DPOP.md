# DPoP: sender-constrained tokens (RFC 9449)

A bearer token works for whoever holds it, so a stolen token is as good as the real
one. A DPoP-bound token is tied to a key the client holds. Each request carries a
short-lived proof signed with that key, naming the exact method and URL and hashing
the access token. A thief with only the token cannot produce proofs.

For agents this matters because an agent's OAuth token then stops being a transferable
secret: a token leaked from a log, a prompt or a tool result is unusable without the
agent's private key.

Status: TypeScript reference implementation (`@7h3/protocol`).

## What is implemented

- Proof creation and verification with `ES256` (P-256) and `EdDSA` (Ed25519). `none`,
  HMAC and all other algorithms are refused.
- Every check in RFC 9449 §4.3, including the ones that are easy to get wrong:
  - the proof's own `jwk` must not carry private or symmetric members, and its key
    type must agree with the declared `alg`;
  - a proof with `crit` headers is refused, as is more than one `DPoP` header;
  - `htm` and `htu` must match the request actually received, with query and fragment
    ignored and scheme, host and default port normalized;
  - freshness window on `iat` (default 60 s, 30 s skew), and single-use `jti`;
  - with a token: `ath` must equal the token's SHA-256, **and** the proof key's
    thumbprint must equal the token's `cnf.jkt`. Passing `accessToken` without
    `expectedJkt` throws: a valid proof made with a different key than the token is
    bound to is exactly what DPoP exists to reject.
- Server-provided nonces (`DpopNonceIssuer`): stateless HMAC nonces that bound how
  long a pre-minted proof stays usable.
- Gateway routes with `require: 'dpop'`.

Checked against the RFC 9449 example: the key thumbprint (`0ZcOCORZ…`) and the `ath`
value are reproduced, and the RFC's own example proof (Figure 13) verifies as received.

## Client

```ts
import { generateDpopKeyPair, createDpopProof, dpopAuthorization } from '@7h3/protocol'

const key = await generateDpopKeyPair('ES256') // or 'EdDSA'. Keep key.privateJwk secret.

const proof = await createDpopProof({ key, method: 'GET', url: 'https://api.example.com/data', accessToken })
fetch(url, { headers: { authorization: dpopAuthorization(accessToken), dpop: proof } })
// A `use_dpop_nonce` challenge returns a DPoP-Nonce header: retry with createDpopProof({ ..., nonce }).
```

## Resource server / gateway

```ts
createGateway({
  upstream, keyRegistry, replayStore,
  dpop: {
    // Map a token to who it was issued to and the key it is bound to (cnf.jkt).
    resolveToken: async (token) => introspect(token), // { sender, jkt } | null
    nonce: { issuer: new DpopNonceIssuer(secret) },   // optional but recommended
  },
  policies: [{ path: '/api/**', require: 'dpop' }],
})
```

The gateway rebuilds the request URL from the `Host` header (or `x-forwarded-host` only
if `trustForwardedHost` is set, which is safe only behind a proxy you control). A token
with no key binding (`jkt` empty) is refused on a DPoP route: it would otherwise
silently downgrade the route to bearer authentication. Failures return
`401 dpop:<reason>` with `WWW-Authenticate: DPoP error="…"`, and a fresh `DPoP-Nonce`
when a nonce is what was missing or wrong. The resolved identity feeds
`allowedSenders`, rate limits and step-up approval.

The gateway removes the `DPoP` header before forwarding: the proof is single-use and the
upstream authenticates the gateway, not the client's key.

## Not covered

Issuing tokens (the authorization-server side: `dpop_jkt`, binding a refresh token) is
outside this library. `resolveToken` is where a deployment applies its own token format
and introspection.
