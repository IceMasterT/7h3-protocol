/**
 * Web Bot Auth: authenticating an automated HTTP client with RFC 9421 signatures.
 *
 * The client signs each request with an Ed25519 key it publishes in a JWKS
 * key directory. The signature identifies the key by its JWK thumbprint
 * (RFC 7638) and — optionally — names the directory in a `Signature-Agent`
 * header. A server that recognizes the agent can then allow, rate-limit or block
 * it by cryptographic identity instead of by guessable User-Agent or IP range.
 *
 * Follows the IETF Web Bot Auth architecture draft
 * (draft-meunier-web-bot-auth-architecture); it is a draft, so the tag and
 * header names may still change.
 *
 * This module does NOT fetch key directories on its own. Resolving a
 * `Signature-Agent` URL sent by an unauthenticated caller is a server-side
 * request forgery vector, so the verifier takes a `resolveKeys` callback in which
 * the deployment applies its allow-list and caching. {@link fetchKeyDirectory} is
 * provided as a guarded building block for that callback.
 */

import {
  getDictionaryMember,
  parseSignatures,
  type HttpMessage,
  type HttpSignatureFailure,
  type VerifyMessageOptions,
  createContentDigest,
  signMessage,
  verifyMessage,
} from './httpMessageSignatures'
import type { ReplayStore } from './replayStores'

export const WEB_BOT_AUTH_TAG = 'web-bot-auth'
export const SIGNATURE_AGENT_HEADER = 'signature-agent'
export const KEY_DIRECTORY_PATH = '/.well-known/http-message-signatures-directory'
export const KEY_DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json'

const encoder = new TextEncoder()

export interface Ed25519Jwk {
  kty: 'OKP'
  crv: 'Ed25519'
  /** base64url raw 32-byte public key. */
  x: string
  kid?: string
  use?: string
}

// ---------------------------------------------------------------------------
// Key conversion and thumbprints
// ---------------------------------------------------------------------------

/** ASN.1 prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): the key is the last 32 bytes. */
const SPKI_ED25519_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])

function b64uToBytes(s: string): Uint8Array {
  const std = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(std + '='.repeat((4 - (std.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

function bytesToB64u(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Convert a 7h3-style SPKI base64url Ed25519 public key to a JWK. */
export function spkiToEd25519Jwk(spkiBase64Url: string): Ed25519Jwk {
  const der = b64uToBytes(spkiBase64Url)
  const ok = der.length === SPKI_ED25519_PREFIX.length + 32 && SPKI_ED25519_PREFIX.every((b, i) => der[i] === b)
  if (!ok) throw new Error('spkiToEd25519Jwk: not an Ed25519 SubjectPublicKeyInfo')
  return { kty: 'OKP', crv: 'Ed25519', x: bytesToB64u(der.slice(SPKI_ED25519_PREFIX.length)) }
}

/** Convert an Ed25519 JWK to the SPKI base64url form used across 7h3. */
export function ed25519JwkToSpki(jwk: Ed25519Jwk): string {
  if (!isEd25519Jwk(jwk)) throw new Error('ed25519JwkToSpki: not an Ed25519 OKP JWK')
  const raw = b64uToBytes(jwk.x)
  if (raw.length !== 32) throw new Error('ed25519JwkToSpki: x must be 32 bytes')
  const der = new Uint8Array(SPKI_ED25519_PREFIX.length + 32)
  der.set(SPKI_ED25519_PREFIX)
  der.set(raw, SPKI_ED25519_PREFIX.length)
  return bytesToB64u(der)
}

export function isEd25519Jwk(value: unknown): value is Ed25519Jwk {
  if (typeof value !== 'object' || value === null) return false
  const j = value as Record<string, unknown>
  if (j.kty !== 'OKP' || j.crv !== 'Ed25519' || typeof j.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(j.x)) return false
  return j.d === undefined // a JWK carrying a private component is never a published key
}

/**
 * RFC 7638 JWK thumbprint (SHA-256, base64url) of an Ed25519 key: the digest of
 * the JSON object with only the required members in lexicographic order.
 */
export async function jwkThumbprint(jwk: Ed25519Jwk): Promise<string> {
  if (!isEd25519Jwk(jwk)) throw new Error('jwkThumbprint: not an Ed25519 OKP JWK')
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(canonical)))
  return bytesToB64u(digest)
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

export interface SignWebBotAuthOptions {
  /** PKCS8 base64url Ed25519 private key. */
  privateKey: string
  /** SPKI base64url Ed25519 public key (used to derive the thumbprint key id). */
  publicKey: string
  /** URL of the client's key directory; sent as `Signature-Agent` and covered by the signature. */
  agentUrl?: string
  /**
   * How `Signature-Agent` is encoded. `'dictionary'` (default) follows the current
   * draft: `Signature-Agent: agent="https://…"`, covered as `"signature-agent";key="agent"`.
   * `'string'` is the legacy plain sf-string form some verifiers still expect.
   */
  agentForm?: 'dictionary' | 'string'
  /** Dictionary member name for `Signature-Agent` (default `agent`). */
  agentLabel?: string
  /** Signature lifetime in seconds (default 60). Web Bot Auth requires `expires`. */
  lifetimeSeconds?: number
  /** Also sign the request body via `Content-Digest`. */
  body?: string | Uint8Array
  /**
   * Sign only `@authority` (and `signature-agent`), as the draft's minimal profile
   * does. Such a signature proves WHO is calling but not WHAT they are calling: it
   * can be replayed against any path or method on the host within its lifetime.
   * By default this signer also covers `@method`, `@path` (and `@query` when the
   * URL has one), which verifiers that only require `@authority` accept unchanged.
   */
  identityOnly?: boolean
  label?: string
  now?: number
}

export interface SignedWebBotAuthRequest {
  /** Headers to add to the request. */
  headers: Record<string, string>
  keyId: string
}

export async function signWebBotAuthRequest(message: HttpMessage, opts: SignWebBotAuthOptions): Promise<SignedWebBotAuthRequest> {
  const jwk = spkiToEd25519Jwk(opts.publicKey)
  const keyId = await jwkThumbprint(jwk)
  const lifetime = opts.lifetimeSeconds ?? 60
  if (!Number.isInteger(lifetime) || lifetime <= 0 || lifetime > 3600) throw new Error('signWebBotAuthRequest: lifetimeSeconds must be 1..3600')
  const created = Math.floor((opts.now ?? Date.now()) / 1000)

  const extra: Record<string, string> = {}
  const components = ['@authority']
  if (!opts.identityOnly) {
    components.push('@method', '@path')
    if (message.url !== undefined && message.url.includes('?')) components.push('@query')
  }
  if (opts.agentUrl !== undefined) {
    if (!/^https:\/\/[^\s"\\]+$/.test(opts.agentUrl)) throw new Error('signWebBotAuthRequest: agentUrl must be an https URL')
    if (opts.agentForm === 'string') {
      extra[SIGNATURE_AGENT_HEADER] = `"${opts.agentUrl}"`
      components.push(SIGNATURE_AGENT_HEADER)
    } else {
      const label = opts.agentLabel ?? 'agent'
      if (!/^[a-z*][a-z0-9_.*-]*$/.test(label)) throw new Error('signWebBotAuthRequest: invalid agentLabel')
      extra[SIGNATURE_AGENT_HEADER] = `${label}="${opts.agentUrl}"`
      components.push(`${SIGNATURE_AGENT_HEADER};key="${label}"`)
    }
  }
  if (opts.body !== undefined && (typeof opts.body === 'string' ? opts.body.length > 0 : opts.body.length > 0)) {
    extra['content-digest'] = await createContentDigest(opts.body)
    components.push('content-digest')
  }

  const withExtra: HttpMessage = { ...message, headers: { ...message.headers, ...extra } }
  const signed = await signMessage(withExtra, {
    label: opts.label ?? 'sig1',
    components,
    key: { alg: 'ed25519', privateKey: opts.privateKey },
    keyId,
    created,
    expires: created + lifetime,
    nonce: true,
    tag: WEB_BOT_AUTH_TAG,
    includeAlg: true,
  })
  return { headers: { ...extra, ...signed.headers }, keyId }
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

export interface WebBotAuthVerifyOptions {
  /**
   * Return the published keys for an agent. `agentUrl` is the (already
   * signature-covered) `Signature-Agent` value, or `undefined` when the request
   * named no directory. Apply your allow-list here; return `null` to refuse.
   */
  resolveKeys: (agentUrl: string | undefined, keyId: string | undefined) => Promise<readonly Ed25519Jwk[] | null> | readonly Ed25519Jwk[] | null
  /** Single-use enforcement for the signature nonce. Strongly recommended. */
  nonceStore?: ReplayStore
  /** Extra components to require (e.g. `content-digest` on routes where the body matters). */
  requiredComponents?: string[]
  body?: string | Uint8Array
  requireBodyBinding?: boolean
  /** Maximum signature age in ms (default 60 seconds; Web Bot Auth signatures are meant to be short-lived). */
  maxAgeMs?: number
  now?: number
  label?: string
}

export type WebBotAuthResult =
  | { ok: true; keyId: string; agentUrl?: string; jwk: Ed25519Jwk }
  | { ok: false; reason: HttpSignatureFailure | 'bad-signature-agent' | 'unknown-key'; detail?: string }

function headerValue(headers: HttpMessage['headers'], name: string): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === name && v !== undefined) return Array.isArray(v) ? v.join(', ') : v
  }
  return undefined
}

/**
 * Read the agent URL out of `Signature-Agent`, given how the signature covered it.
 * Returns `undefined` when there is no header, `null` when it is present but
 * malformed or not covered in a form we understand.
 */
function agentFromHeader(raw: string | undefined, coveredComponent: string | undefined): string | undefined | null {
  if (raw === undefined) return undefined
  if (coveredComponent === undefined) return null
  const plainString = /^"([^"\\]+)"$/
  if (coveredComponent === '"signature-agent"') return plainString.exec(raw.trim())?.[1] ?? null // legacy sf-string
  const key = /^"signature-agent";key="([^"\\]+)"$/.exec(coveredComponent)?.[1]
  if (key === undefined) return null
  try {
    return plainString.exec(getDictionaryMember(raw, key))?.[1] ?? null
  } catch {
    return null
  }
}

export async function verifyWebBotAuthRequest(message: HttpMessage, opts: WebBotAuthVerifyOptions): Promise<WebBotAuthResult> {
  const rawAgent = headerValue(message.headers, SIGNATURE_AGENT_HEADER)
  // Which Signature-Agent component (if any) the signature covers, so the header is
  // only ever read the way the signer signed it. A header that is present but not
  // covered is untrusted input and is refused, never silently used or ignored.
  let coveredAgent: string | undefined
  try {
    const cand = parseSignatures(message.headers).find((x) => (opts.label === undefined || x.label === opts.label) && x.params.tag === WEB_BOT_AUTH_TAG)
    coveredAgent = cand?.components.find((c) => c === '"signature-agent"' || c.startsWith('"signature-agent";key='))
  } catch {
    // Malformed signature fields: verifyMessage below reports the precise reason.
  }
  const agentUrl = agentFromHeader(rawAgent, coveredAgent)
  if (agentUrl === null) return { ok: false, reason: 'bad-signature-agent' }

  const required = ['@authority', ...(coveredAgent !== undefined ? [coveredAgent] : []), ...(opts.requiredComponents ?? [])]
  let resolved: Ed25519Jwk | undefined
  let unknownKey = false

  const verifyOpts: VerifyMessageOptions = {
    label: opts.label,
    tag: WEB_BOT_AUTH_TAG,
    requiredComponents: required,
    requireBodyBinding: opts.requireBodyBinding,
    body: opts.body,
    maxAgeMs: opts.maxAgeMs ?? 60_000,
    nonceStore: opts.nonceStore,
    now: opts.now,
    requireCreated: true,
    // A signature that never expires is a bearer token; Web Bot Auth signatures must carry `expires`.
    requireExpires: true,
    resolveKey: async (keyId) => {
      if (keyId === undefined) return null
      const keys = await opts.resolveKeys(agentUrl ?? undefined, keyId)
      if (!keys) return null
      for (const jwk of keys) {
        if (isEd25519Jwk(jwk) && (await jwkThumbprint(jwk)) === keyId) {
          resolved = jwk
          return { alg: 'ed25519', publicKey: ed25519JwkToSpki(jwk) }
        }
      }
      unknownKey = true
      return null
    },
  }

  const result = await verifyMessage(message, verifyOpts)
  if (!result.ok) {
    if (result.reason === 'no-key' && unknownKey) return { ok: false, reason: 'unknown-key' }
    return { ok: false, reason: result.reason, detail: result.detail }
  }
  return { ok: true, keyId: result.keyId!, ...(agentUrl !== undefined ? { agentUrl } : {}), jwk: resolved! }
}

// ---------------------------------------------------------------------------
// Key directory fetching (guarded building block)
// ---------------------------------------------------------------------------

export interface FetchKeyDirectoryOptions {
  fetch?: typeof fetch
  timeoutMs?: number
  /** Maximum response size (default 64 KiB). */
  maxBytes?: number
  /** Maximum keys accepted (default 32). */
  maxKeys?: number
}

/**
 * Fetch and validate a key directory. Safeguards: https only; the well-known path
 * is fixed (the caller cannot be steered to an arbitrary path); no redirects;
 * bounded time and size; the JSON media type is required; only well-formed
 * Ed25519 public keys are kept (anything with a private `d` is dropped).
 *
 * This does not decide WHICH hosts may be contacted — see the module comment.
 * Only call it for agent URLs your own allow-list has already approved.
 */
export async function fetchKeyDirectory(agentUrl: string, opts: FetchKeyDirectoryOptions = {}): Promise<Ed25519Jwk[]> {
  let url: URL
  try {
    url = new URL(agentUrl)
  } catch {
    throw new Error('fetchKeyDirectory: invalid agent URL')
  }
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('fetchKeyDirectory: agent URL must be https without credentials')
  const target = `${url.origin}${KEY_DIRECTORY_PATH}`
  const doFetch = opts.fetch ?? fetch
  const maxBytes = opts.maxBytes ?? 64 * 1024
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 5000)
  try {
    const res = await doFetch(target, { redirect: 'error', signal: controller.signal, headers: { accept: KEY_DIRECTORY_MEDIA_TYPE } })
    if (!res.ok) throw new Error(`fetchKeyDirectory: HTTP ${res.status}`)
    const type = (res.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase()
    if (type !== KEY_DIRECTORY_MEDIA_TYPE && type !== 'application/json') throw new Error('fetchKeyDirectory: unexpected content-type')
    const declared = Number(res.headers.get('content-length') ?? '0')
    if (declared > maxBytes) throw new Error('fetchKeyDirectory: response too large')
    const text = await res.text()
    if (encoder.encode(text).length > maxBytes) throw new Error('fetchKeyDirectory: response too large')
    const parsed = JSON.parse(text) as { keys?: unknown }
    if (!parsed || !Array.isArray(parsed.keys)) throw new Error('fetchKeyDirectory: not a JWKS')
    return parsed.keys.filter(isEd25519Jwk).slice(0, opts.maxKeys ?? 32)
  } finally {
    clearTimeout(timer)
  }
}
