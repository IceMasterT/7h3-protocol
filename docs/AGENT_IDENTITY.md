# Agent identity: Agent Cards, did:key, SPIFFE

7h3 messages prove that the holder of a private key signed them. This module covers
the other half of the question: which identity does that key belong to, in a form
other ecosystems already use.

Status: TypeScript reference implementation (`@7h3/protocol`).

**Trust caveat that applies to everything below.** A signature proves possession of a
key. It proves who the operator is only relative to the keys you have chosen to trust
(`resolveKey`, a trust-domain allow-list, a pinned issuer). Nothing here decides that
for you.

## Signed Agent Cards (A2A-compatible)

A2A §8.4 lets an Agent Card carry JWS signatures over the RFC 8785 (JCS) canonical
card. `signAgentCard` and `verifyAgentCard` implement that format, with `EdDSA`
(Ed25519) and `ES256` (P-256):

```ts
import { signAgentCard, verifyAgentCard } from '@7h3/protocol'

const signed = await signAgentCard(card, { privateJwk, keyId: 'key-1', jku: 'https://example.com/jwks.json' })

const result = await verifyAgentCard(fetchedCard, {
  resolveKey: (kid, jku) => trustedKeys.get(kid) ?? null, // a public JWK, or null
  expectedOrigin: 'https://agent.example.com',            // where the card was fetched from
})
```

What the verifier enforces:

- **A card with no usable signature is never trusted** (`no-signature`).
- **Any change to the card invalidates it**: skills, security schemes, endpoints, anything.
- **The algorithm comes from your key**, not the header. `none`, HMAC and RSA are
  refused, as is a header that says `ES256` for an Ed25519 key, and any `crit` header.
- **`expectedOrigin` stops card lifting.** A validly signed card copied onto an
  attacker's host is refused unless it declares an endpoint on the origin it was
  fetched from. Set it whenever you know where the card came from.
- **`jku` is a hint and is never fetched by the verifier.** Fetching an
  attacker-supplied URL is an SSRF vector; any fetching happens inside your
  `resolveKey`, behind your allow-list.
- **Rotation**: extra signatures are kept and at least one valid signature suffices;
  signatures by unknown or revoked keys are skipped. `requireAll` insists on all.

`signAgentCard` signs the card object exactly as given. A2A's field-presence rules
(omit unset optional fields and default values before canonicalizing) depend on the
card schema version and are the caller's to apply.

`canonicalizeJcs` is RFC 8785 canonical JSON. It reproduces the RFC's §3.2.2 sample,
the UTF-16 property sorting example, and all 22 number serialization samples of
Appendix B.

## did:key

`did:key` identifiers for Ed25519 keys are self-certifying: the identifier *is* the
key, so no registry or network lookup is needed.

```ts
didKeyFromEd25519(spki)            // did:key:z6Mk…
ed25519FromDidKey(did)             // SPKI base64url, or null
didKeyDocument(did)                // the DID document it expands to
ed25519PublicToX25519(spki)        // the equivalent key-agreement key
createDidKeyRegistry()             // a KeyRegistry for did:key senders
```

The parser is strict: other methods, other key types (X25519, secp256k1), non-base58
characters, wrong lengths, paths, queries and mismatched key-reference fragments are
all refused. It is checked against the did:key specification's example: the DID
round-trips, and the X25519 `keyAgreement` key derived from it equals the one the
specification's own DID document lists.

**Using `did:key` as a sender id authenticates the key, not the party.** Anyone can
mint one. Pair it with `allowedSenders`, an approver list or an attestation before it
is granted anything.

## SPIFFE IDs

`parseSpiffeId` accepts only well-formed IDs (lower-case trust domain, valid path
segments, no userinfo, port, query, fragment, or `.`/`..` segments, at most 2048
characters). `isSpiffeIdAllowed` applies a trust-domain and path-prefix policy; a
prefix `/ns/prod` allows `/ns/prod/agent-1` but not `/ns/production`.

## Hardening of the HTTP key registry

`createHttpKeyRegistry` derives the host it fetches keys from out of the sender id of a
message that has not been verified yet, so that host is attacker-controlled. It now:

- refuses anything that is not a plausible public DNS name: IP addresses (including
  numeric and hex forms), `localhost`, `.local`, `.internal`, `.lan`, `.home.arpa`,
  ports, paths, credentials and brackets;
- refuses redirects and bounds the size of the key document;
- bounds its cache;
- takes an `allowedDomains` list. **Set it in production**: a public-looking name can
  still resolve to a private address, and without a list any domain can introduce
  itself as a sender.
