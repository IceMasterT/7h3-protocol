/**
 * HTTP Message Signatures (RFC 9421) with Content-Digest (RFC 9530).
 *
 * This is the standards-track way to sign an HTTP request or response. It is
 * what Web Bot Auth builds on (see `./webBotAuth`), and it lets 7h3 interoperate
 * with signers and verifiers that know nothing about the 7h3 envelope.
 *
 * Supported: request and response messages; derived components `@method`,
 * `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`,
 * `@query-param;name=…`, `@status`; plain header fields; the `req` parameter;
 * algorithms `ed25519` and `hmac-sha256`; signature parameters `created`,
 * `expires`, `nonce`, `alg`, `keyid`, `tag`.
 *
 * Dictionary members via `;key="…"` are supported (RFC 9421 §2.1.2).
 *
 * Deliberately not supported (rejected, never silently ignored): the `sf`,
 * `bs` and `tr` component parameters, and the RSA-PSS / RSA-v1.5 / ECDSA
 * algorithms. Rejecting is required by the RFC for unknown parameters, and it
 * keeps "verified" from meaning "verified something else".
 *
 * Verification is policy-driven: the verifier states which components MUST be
 * covered, how old a signature may be, which tag it expects, and (optionally)
 * consumes the nonce through a {@link ReplayStore}. A signature that covers too
 * little — for example only `@method` — is refused, not accepted as "valid".
 */

import { randomHex } from './protocol'
import type { ReplayStore } from './replayStores'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HttpMessage {
  /** Requests: the request method, e.g. `POST`. */
  method?: string
  /**
   * Requests: the absolute target URI as the recipient sees it,
   * e.g. `https://example.com/foo?param=Value&Pet=dog`.
   */
  url?: string
  /** Responses: the status code. */
  status?: number
  headers: Record<string, string | string[] | undefined>
}

export type SignatureAlgorithm = 'ed25519' | 'hmac-sha256'

export interface SignatureParams {
  created?: number
  expires?: number
  nonce?: string
  alg?: string
  keyid?: string
  tag?: string
}

export interface ParsedSignature {
  label: string
  /** Covered component identifiers, each serialized like `"@query-param";name="Pet"`. */
  components: string[]
  params: SignatureParams
  /** The exact `@signature-params` value as it appeared on the wire. */
  signatureParamsValue: string
  signature: Uint8Array
}

export class HttpSignatureError extends Error {
  constructor(
    public readonly code: string,
    message?: string,
  ) {
    super(message === undefined ? code : `${code}: ${message}`)
    this.name = 'HttpSignatureError'
  }
}

// ---------------------------------------------------------------------------
// Bytes / base64
// ---------------------------------------------------------------------------

const encoder = new TextEncoder()

function bytesToBase64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

function base64ToBytes(b64: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 === 1) return null
  try {
    const bin = atob(b64)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return null
  }
}

const toBase64Url = (b64: string): string => b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const fromBase64Url = (b64u: string): string => {
  const s = b64u.replace(/-/g, '+').replace(/_/g, '/')
  return s + '='.repeat((4 - (s.length % 4)) % 4)
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle
  if (!s) throw new Error('WebCrypto (crypto.subtle) is required')
  return s
}

const buf = (u: Uint8Array): ArrayBuffer => u.slice().buffer as ArrayBuffer

// ---------------------------------------------------------------------------
// Content-Digest (RFC 9530)
// ---------------------------------------------------------------------------

export type DigestAlgorithm = 'sha-256' | 'sha-512'
const DIGEST_HASH: Record<DigestAlgorithm, string> = { 'sha-256': 'SHA-256', 'sha-512': 'SHA-512' }

/** `Content-Digest` header value for a body, e.g. `sha-256=:base64:`. */
export async function createContentDigest(body: string | Uint8Array, alg: DigestAlgorithm = 'sha-256'): Promise<string> {
  const bytes = typeof body === 'string' ? encoder.encode(body) : body
  const digest = new Uint8Array(await subtle().digest(DIGEST_HASH[alg], buf(bytes)))
  return `${alg}=:${bytesToBase64(digest)}:`
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/**
 * Check a `Content-Digest` header against the body. Every recognized algorithm in
 * the header must match; unrecognized ones are ignored; a header with NO
 * recognized algorithm fails (it proves nothing about the body).
 */
export async function verifyContentDigest(headerValue: string, body: string | Uint8Array): Promise<boolean> {
  const bytes = typeof body === 'string' ? encoder.encode(body) : body
  let sawKnown = false
  for (const member of splitTopLevel(headerValue, ',')) {
    const m = /^\s*([a-z][a-z0-9.*_-]*)=:([A-Za-z0-9+/=]*):\s*$/.exec(member)
    if (!m) return false
    const alg = m[1] as DigestAlgorithm
    if (!(alg in DIGEST_HASH)) continue
    const claimed = base64ToBytes(m[2])
    if (!claimed) return false
    sawKnown = true
    const actual = new Uint8Array(await subtle().digest(DIGEST_HASH[alg], buf(bytes)))
    if (!constantTimeEqual(actual, claimed)) return false
  }
  return sawKnown
}

// ---------------------------------------------------------------------------
// Structured Fields (RFC 8941), the subset RFC 9421 needs
// ---------------------------------------------------------------------------

/** Split on a separator that is not inside a quoted string or an inner list. */
function splitTopLevel(input: string, sep: string): string[] {
  const out: string[] = []
  let depth = 0
  let inStr = false
  let start = 0
  for (let i = 0; i < input.length; i++) {
    const c = input[i]
    if (inStr) {
      if (c === '\\') i++
      else if (c === '"') inStr = false
      continue
    }
    if (c === '"') inStr = true
    else if (c === '(') depth++
    else if (c === ')') depth--
    else if (c === ':' && sep !== ':') {
      // byte sequence :....: — skip to closing colon
      const end = input.indexOf(':', i + 1)
      if (end === -1) return [input]
      i = end
    } else if (c === sep && depth === 0) {
      out.push(input.slice(start, i))
      start = i + 1
    }
  }
  out.push(input.slice(start))
  return out
}

type SfBareItem = string | number | boolean | { token: string } | Uint8Array
type SfParams = Array<[string, SfBareItem]>

class SfParser {
  private i = 0
  constructor(private readonly s: string) {}

  eof(): boolean {
    return this.i >= this.s.length
  }
  skipSp(): void {
    while (this.s[this.i] === ' ') this.i++
  }
  skipOws(): void {
    while (this.s[this.i] === ' ' || this.s[this.i] === '\t') this.i++
  }
  peek(): string | undefined {
    return this.s[this.i]
  }
  pos(): number {
    return this.i
  }
  slice(from: number): string {
    return this.s.slice(from, this.i)
  }
  expect(c: string): void {
    if (this.s[this.i] !== c) throw new HttpSignatureError('malformed-structured-field', `expected '${c}' at ${this.i}`)
    this.i++
  }

  key(): string {
    const m = /^[a-z*][a-z0-9_.*-]*/.exec(this.s.slice(this.i))
    if (!m) throw new HttpSignatureError('malformed-structured-field', 'bad key')
    this.i += m[0].length
    return m[0]
  }

  string(): string {
    this.expect('"')
    let out = ''
    for (;;) {
      const c = this.s[this.i++]
      if (c === undefined) throw new HttpSignatureError('malformed-structured-field', 'unterminated string')
      if (c === '\\') {
        const n = this.s[this.i++]
        if (n !== '"' && n !== '\\') throw new HttpSignatureError('malformed-structured-field', 'bad escape')
        out += n
      } else if (c === '"') return out
      else if (c.charCodeAt(0) < 0x20 || c.charCodeAt(0) > 0x7e) throw new HttpSignatureError('malformed-structured-field', 'non-ASCII in string')
      else out += c
    }
  }

  bareItem(): SfBareItem {
    const c = this.peek()
    if (c === '"') return this.string()
    if (c === ':') {
      this.i++
      const end = this.s.indexOf(':', this.i)
      if (end === -1) throw new HttpSignatureError('malformed-structured-field', 'unterminated byte sequence')
      const bytes = base64ToBytes(this.s.slice(this.i, end))
      if (!bytes) throw new HttpSignatureError('malformed-structured-field', 'bad base64')
      this.i = end + 1
      return bytes
    }
    if (c === '?') {
      this.i++
      const v = this.s[this.i++]
      if (v !== '0' && v !== '1') throw new HttpSignatureError('malformed-structured-field', 'bad boolean')
      return v === '1'
    }
    const num = /^-?[0-9]{1,15}(\.[0-9]{1,3})?/.exec(this.s.slice(this.i))
    if (num) {
      this.i += num[0].length
      if (num[0].includes('.')) throw new HttpSignatureError('malformed-structured-field', 'decimals unsupported')
      return Number(num[0])
    }
    const tok = /^[A-Za-z*][A-Za-z0-9:/!#$%&'*+.^_`|~-]*/.exec(this.s.slice(this.i))
    if (tok) {
      this.i += tok[0].length
      return { token: tok[0] }
    }
    throw new HttpSignatureError('malformed-structured-field', `bad item at ${this.i}`)
  }

  params(): SfParams {
    const out: SfParams = []
    while (this.peek() === ';') {
      this.i++
      this.skipSp()
      const k = this.key()
      let v: SfBareItem = true
      if (this.peek() === '=') {
        this.i++
        v = this.bareItem()
      }
      out.push([k, v])
    }
    return out
  }
}

const MAX_FIELD_BYTES = 8 * 1024
const MAX_MEMBERS = 16
const MAX_COMPONENTS = 32

/** Serialize an sf-string (RFC 8941 §4.1.6). */
function sfString(s: string): string {
  if (!/^[\x20-\x7e]*$/.test(s)) throw new HttpSignatureError('non-ascii-value', 'structured string must be printable ASCII')
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

/** Parse one component identifier (`"name";param…`) into its canonical serialization. */
export function normalizeComponentId(id: string): string {
  const trimmed = id.trim()
  // Shorthand without quotes: `@method`, `content-type`, `@query-param;name="Pet"`, `content-digest;req`
  const semi = trimmed.indexOf(';')
  const rawName = semi === -1 ? trimmed : trimmed.slice(0, semi)
  const rest = semi === -1 ? '' : trimmed.slice(semi)
  const quoted = rawName.startsWith('"') ? rawName : `"${rawName}"`
  const p = new SfParser(quoted + rest)
  const name = p.string()
  const params = p.params()
  if (!p.eof()) throw new HttpSignatureError('malformed-component', id)
  return serializeComponent(name, params)
}

function serializeComponent(name: string, params: SfParams): string {
  let out = sfString(name)
  for (const [k, v] of params) {
    out += `;${k}`
    if (v === true) continue
    if (typeof v === 'string') out += `=${sfString(v)}`
    else throw new HttpSignatureError('unsupported-component-parameter', k)
  }
  return out
}

function serializeSignatureParams(components: string[], p: SignatureParams): string {
  let out = `(${components.join(' ')})`
  // Order matches the RFC 9421 Appendix B and Web Bot Auth test vectors
  // (created;keyid;alg;expires;nonce;tag). Verifiers never depend on it: they re-use
  // the exact `Signature-Input` value they received.
  if (p.created !== undefined) out += `;created=${p.created}`
  if (p.keyid !== undefined) out += `;keyid=${sfString(p.keyid)}`
  if (p.alg !== undefined) out += `;alg=${sfString(p.alg)}`
  if (p.expires !== undefined) out += `;expires=${p.expires}`
  if (p.nonce !== undefined) out += `;nonce=${sfString(p.nonce)}`
  if (p.tag !== undefined) out += `;tag=${sfString(p.tag)}`
  return out
}

function parseSignatureInputMember(label: string, raw: string): Omit<ParsedSignature, 'signature'> {
  const p = new SfParser(raw)
  p.expect('(')
  const components: string[] = []
  p.skipSp()
  while (p.peek() !== ')') {
    if (p.eof()) throw new HttpSignatureError('malformed-structured-field', 'unterminated inner list')
    const name = p.string()
    const params = p.params()
    components.push(serializeComponent(name, params))
    if (components.length > MAX_COMPONENTS) throw new HttpSignatureError('too-many-components')
    if (p.peek() !== ' ' && p.peek() !== ')') throw new HttpSignatureError('malformed-structured-field', 'bad separator')
    p.skipSp()
  }
  p.expect(')')
  const params: SignatureParams = {}
  const seen = new Set<string>()
  for (const [k, v] of p.params()) {
    if (seen.has(k)) throw new HttpSignatureError('duplicate-parameter', k)
    seen.add(k)
    switch (k) {
      case 'created':
      case 'expires':
        if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) throw new HttpSignatureError('malformed-parameter', k)
        params[k] = v
        break
      case 'nonce':
      case 'alg':
      case 'keyid':
      case 'tag':
        if (typeof v !== 'string') throw new HttpSignatureError('malformed-parameter', k)
        params[k] = v
        break
      default:
        // Unknown metadata parameters stay covered by the signature (they are part of
        // the signature-params value) but carry no meaning to this verifier.
        break
    }
  }
  if (!p.eof()) throw new HttpSignatureError('malformed-structured-field', 'trailing data')
  return { label, components, params, signatureParamsValue: raw }
}

// -- Dictionary members (RFC 9421 §2.1.2) ------------------------------------

/** Serialize a bare item per RFC 8941 §4.1.3 (strings, integers, booleans, tokens, byte sequences). */
function sfBare(v: SfBareItem): string {
  if (typeof v === 'string') return sfString(v)
  if (typeof v === 'number') return String(v)
  if (typeof v === 'boolean') return v ? '?1' : '?0'
  if (v instanceof Uint8Array) return `:${bytesToBase64(v)}:`
  return v.token
}

function sfParams(params: SfParams): string {
  return params.map(([k, v]) => (v === true ? `;${k}` : `;${k}=${sfBare(v)}`)).join('')
}

/**
 * The strictly re-serialized value of dictionary member `key` in `fieldValue`.
 * Supports items and inner lists of items, each with parameters.
 */
export function getDictionaryMember(fieldValue: string, key: string): string {
  const members = new Map<string, string>()
  for (const raw of splitTopLevel(fieldValue, ',')) {
    const p = new SfParser(raw.trim())
    const k = p.key()
    let out: string
    if (p.peek() === '=') {
      p.expect('=')
      if (p.peek() === '(') {
        p.expect('(')
        const items: string[] = []
        p.skipSp()
        while (p.peek() !== ')') {
          if (p.eof()) throw new HttpSignatureError('malformed-structured-field', 'unterminated inner list')
          const bare = p.bareItem()
          items.push(sfBare(bare) + sfParams(p.params()))
          p.skipSp()
        }
        p.expect(')')
        out = `(${items.join(' ')})` + sfParams(p.params())
      } else {
        const bare = p.bareItem()
        out = sfBare(bare) + sfParams(p.params())
      }
    } else {
      out = '?1' + sfParams(p.params())
    }
    p.skipOws()
    if (!p.eof()) throw new HttpSignatureError('malformed-structured-field', 'dictionary member')
    members.set(k, out) // later duplicates win, as in RFC 8941
  }
  const value = members.get(key)
  if (value === undefined) throw new HttpSignatureError('component-not-found', `dictionary key '${key}'`)
  return value
}

function getField(headers: HttpMessage['headers'], name: string): string[] {
  const lower = name.toLowerCase()
  const values: string[] = []
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== lower || v === undefined) continue
    for (const one of Array.isArray(v) ? v : [v]) values.push(one)
  }
  return values
}

/**
 * Parse `Signature-Input` and `Signature` into signatures. Every labelled
 * signature must appear in both fields; a mismatch is an error, not a partial result.
 */
export function parseSignatures(headers: HttpMessage['headers']): ParsedSignature[] {
  const inputs = getField(headers, 'signature-input').join(', ')
  const sigs = getField(headers, 'signature').join(', ')
  if (!inputs || !sigs) throw new HttpSignatureError('missing-signature')
  if (inputs.length > MAX_FIELD_BYTES || sigs.length > MAX_FIELD_BYTES) throw new HttpSignatureError('field-too-large')

  const inputMembers = new Map<string, string>()
  const inputParts = splitTopLevel(inputs, ',')
  if (inputParts.length > MAX_MEMBERS) throw new HttpSignatureError('too-many-signatures')
  for (const part of inputParts) {
    const m = /^\s*([a-z*][a-z0-9_.*-]*)=(.*)$/s.exec(part)
    if (!m) throw new HttpSignatureError('malformed-structured-field', 'signature-input member')
    if (inputMembers.has(m[1])) throw new HttpSignatureError('duplicate-label', m[1])
    inputMembers.set(m[1], m[2].trim())
  }

  const sigMembers = new Map<string, Uint8Array>()
  for (const part of splitTopLevel(sigs, ',')) {
    const m = /^\s*([a-z*][a-z0-9_.*-]*)=:([A-Za-z0-9+/=]*):\s*$/.exec(part)
    if (!m) throw new HttpSignatureError('malformed-structured-field', 'signature member')
    const bytes = base64ToBytes(m[2])
    if (!bytes) throw new HttpSignatureError('malformed-structured-field', 'signature base64')
    if (sigMembers.has(m[1])) throw new HttpSignatureError('duplicate-label', m[1])
    sigMembers.set(m[1], bytes)
  }

  const out: ParsedSignature[] = []
  for (const [label, raw] of inputMembers) {
    const signature = sigMembers.get(label)
    if (!signature) throw new HttpSignatureError('signature-missing-for-label', label)
    out.push({ ...parseSignatureInputMember(label, raw), signature })
  }
  return out
}

// ---------------------------------------------------------------------------
// Component resolution and the signature base (RFC 9421 §2)
// ---------------------------------------------------------------------------

interface UrlParts {
  scheme: string
  authority: string
  path: string
  /** Includes the leading `?` when present (even if empty); `undefined` when absent. */
  query: string | undefined
}

function parseUrl(url: string): UrlParts {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(?:#.*)?$/.exec(url)
  if (!m) throw new HttpSignatureError('invalid-url', url)
  const scheme = m[1].toLowerCase()
  let authority = m[2].toLowerCase()
  if (authority.includes('@')) throw new HttpSignatureError('invalid-url', 'userinfo not allowed in the target URI')
  const defaultPort = scheme === 'https' ? ':443' : scheme === 'http' ? ':80' : undefined
  if (defaultPort && authority.endsWith(defaultPort)) authority = authority.slice(0, -defaultPort.length)
  return { scheme, authority, path: m[3] === '' ? '/' : m[3], query: m[4] }
}

/** WHATWG form-urlencoded serialization, except space is `%20` (as RFC 9421's examples require). */
function formEncode(decoded: string): string {
  let out = ''
  for (const byte of encoder.encode(decoded)) {
    const c = String.fromCharCode(byte)
    if (/[A-Za-z0-9*\-._]/.test(c)) out += c
    else out += '%' + byte.toString(16).toUpperCase().padStart(2, '0')
  }
  return out
}

function formDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '))
  } catch {
    throw new HttpSignatureError('invalid-query-encoding')
  }
}

/**
 * `name` is the already-encoded parameter name, exactly as it appears in the
 * component identifier (RFC 9421 §2.2.8), e.g. `fa%C3%A7ade%22%3A%20`.
 */
function queryParam(query: string | undefined, name: string): string {
  const raw = query === undefined ? '' : query.slice(1)
  const wanted = name
  let found: string | undefined
  let count = 0
  if (raw !== '') {
    for (const pair of raw.split('&')) {
      const eq = pair.indexOf('=')
      const k = formEncode(formDecode(eq === -1 ? pair : pair.slice(0, eq)))
      if (k !== wanted) continue
      count++
      found = formEncode(formDecode(eq === -1 ? '' : pair.slice(eq + 1)))
    }
  }
  if (count === 0) throw new HttpSignatureError('component-not-found', `query parameter '${name}'`)
  if (count > 1) throw new HttpSignatureError('ambiguous-query-parameter', name)
  return found ?? ''
}

function fieldValue(headers: HttpMessage['headers'], name: string): string {
  const values = getField(headers, name)
  if (values.length === 0) throw new HttpSignatureError('component-not-found', name)
  const cleaned = values.map((v) => {
    if (/[\r\n]/.test(v)) throw new HttpSignatureError('invalid-field-value', name)
    return v.trim()
  })
  return cleaned.join(', ')
}

interface Context {
  message: HttpMessage
  /** For responses: the request the `req` parameter refers to. */
  request?: HttpMessage
  isResponse: boolean
}

function resolveComponent(id: string, ctx: Context): string {
  const p = new SfParser(id)
  const name = p.string()
  const params = p.params()

  let req = false
  let paramName: string | undefined
  let dictKey: string | undefined
  for (const [k, v] of params) {
    if (k === 'req' && v === true) req = true
    else if (k === 'name' && typeof v === 'string') paramName = v
    else if (k === 'key' && typeof v === 'string') dictKey = v
    else throw new HttpSignatureError('unsupported-component-parameter', k)
  }
  if (req && !ctx.isResponse) throw new HttpSignatureError('req-on-request')
  if (req && !ctx.request) throw new HttpSignatureError('req-without-request')
  const target = req ? ctx.request! : ctx.message

  if (name.startsWith('@')) {
    if (dictKey !== undefined) throw new HttpSignatureError('unsupported-component-parameter', 'key')
    if (paramName !== undefined && name !== '@query-param') throw new HttpSignatureError('unsupported-component-parameter', 'name')
    if (name === '@status') {
      if (!ctx.isResponse || req) throw new HttpSignatureError('component-not-applicable', name)
      if (target.status === undefined) throw new HttpSignatureError('component-not-found', name)
      return String(target.status)
    }
    if (ctx.isResponse && !req) throw new HttpSignatureError('component-not-applicable', name)
    if (name === '@method') {
      if (!target.method) throw new HttpSignatureError('component-not-found', name)
      return target.method
    }
    if (!target.url) throw new HttpSignatureError('component-not-found', name)
    if (name === '@target-uri') return target.url.replace(/#.*$/s, '')
    const u = parseUrl(target.url)
    switch (name) {
      case '@authority':
        return u.authority
      case '@scheme':
        return u.scheme
      case '@path':
        return u.path
      case '@query':
        return u.query ?? '?'
      case '@request-target':
        return u.path + (u.query ?? '')
      case '@query-param':
        if (paramName === undefined) throw new HttpSignatureError('component-not-found', '@query-param requires name')
        return queryParam(u.query, paramName)
      default:
        throw new HttpSignatureError('unknown-derived-component', name)
    }
  }
  if (paramName !== undefined) throw new HttpSignatureError('unsupported-component-parameter', 'name')
  const value = fieldValue(target.headers, name)
  return dictKey === undefined ? value : getDictionaryMember(value, dictKey)
}

function buildSignatureBase(components: string[], signatureParams: string, ctx: Context): string {
  const seen = new Set<string>()
  let out = ''
  for (const id of components) {
    if (seen.has(id)) throw new HttpSignatureError('duplicate-component', id)
    seen.add(id)
    const value = resolveComponent(id, ctx)
    if (/[\r\n]/.test(value)) throw new HttpSignatureError('invalid-component-value', id)
    out += `${id}: ${value}\n`
  }
  out += `"@signature-params": ${signatureParams}`
  for (let i = 0; i < out.length; i++) {
    if (out.charCodeAt(i) > 0x7f) throw new HttpSignatureError('non-ascii-signature-base')
  }
  return out
}

/** The exact bytes that get signed. Exposed for tests and debugging. */
export function createSignatureBase(
  message: HttpMessage,
  components: string[],
  params: SignatureParams,
  options: { request?: HttpMessage } = {},
): string {
  const normalized = components.map(normalizeComponentId)
  return buildSignatureBase(normalized, serializeSignatureParams(normalized, params), {
    message,
    request: options.request,
    isResponse: message.status !== undefined,
  })
}

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

export type SigningKey =
  | { alg: 'ed25519'; privateKey: string } // PKCS8, base64url (as the rest of 7h3)
  | { alg: 'hmac-sha256'; secret: string | Uint8Array } // string = UTF-8 bytes

export type VerificationKey =
  | { alg: 'ed25519'; publicKey: string } // SPKI, base64url
  | { alg: 'hmac-sha256'; secret: string | Uint8Array }

async function signBytes(key: SigningKey, data: Uint8Array): Promise<Uint8Array> {
  if (key.alg === 'ed25519') {
    const pk = await subtle().importKey('pkcs8', buf(base64ToBytes(fromBase64Url(key.privateKey)) ?? new Uint8Array()), { name: 'Ed25519' }, false, ['sign'])
    return new Uint8Array(await subtle().sign({ name: 'Ed25519' }, pk, buf(data)))
  }
  const raw = typeof key.secret === 'string' ? encoder.encode(key.secret) : key.secret
  const hk = await subtle().importKey('raw', buf(raw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await subtle().sign('HMAC', hk, buf(data)))
}

async function verifyBytes(key: VerificationKey, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  try {
    if (key.alg === 'ed25519') {
      const pub = await subtle().importKey('spki', buf(base64ToBytes(fromBase64Url(key.publicKey)) ?? new Uint8Array()), { name: 'Ed25519' }, false, ['verify'])
      return await subtle().verify({ name: 'Ed25519' }, pub, buf(signature), buf(data))
    }
    const raw = typeof key.secret === 'string' ? encoder.encode(key.secret) : key.secret
    const hk = await subtle().importKey('raw', buf(raw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const expected = new Uint8Array(await subtle().sign('HMAC', hk, buf(data)))
    return constantTimeEqual(expected, signature)
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

export interface SignMessageOptions {
  /** Signature label (default `sig1`). */
  label?: string
  /** Covered components. Each may be bare (`@method`, `content-type`) or in structured-field form. */
  components: string[]
  key: SigningKey
  keyId?: string
  /** Unix seconds. Defaults to now. Pass `false` to omit `created`. */
  created?: number | false
  /** Unix seconds. */
  expires?: number
  /** `true` generates a random nonce; a string uses that value. */
  nonce?: string | true
  tag?: string
  /** Include the `alg` parameter (default false: the verifier should derive the algorithm from the key). */
  includeAlg?: boolean
  /** For responses that cover request components with `;req`. */
  request?: HttpMessage
}

export interface SignedMessage {
  label: string
  signatureInput: string
  signature: string
  /** Header fields to add to the message. */
  headers: { 'signature-input': string; signature: string }
}

export async function signMessage(message: HttpMessage, opts: SignMessageOptions): Promise<SignedMessage> {
  const label = opts.label ?? 'sig1'
  if (!/^[a-z*][a-z0-9_.*-]*$/.test(label)) throw new HttpSignatureError('invalid-label', label)
  const components = opts.components.map(normalizeComponentId)
  if (components.includes('"@signature-params"')) throw new HttpSignatureError('reserved-component')

  const params: SignatureParams = {}
  if (opts.created !== false) params.created = opts.created ?? Math.floor(Date.now() / 1000)
  if (opts.expires !== undefined) params.expires = opts.expires
  if (opts.nonce !== undefined) params.nonce = opts.nonce === true ? randomHex(16) : opts.nonce
  if (opts.includeAlg) params.alg = opts.key.alg
  if (opts.keyId !== undefined) params.keyid = opts.keyId
  if (opts.tag !== undefined) params.tag = opts.tag

  const sigParams = serializeSignatureParams(components, params)
  const base = buildSignatureBase(components, sigParams, { message, request: opts.request, isResponse: message.status !== undefined })
  const signature = await signBytes(opts.key, encoder.encode(base))
  const signatureInput = `${label}=${sigParams}`
  const sigField = `${label}=:${bytesToBase64(signature)}:`
  return { label, signatureInput, signature: sigField, headers: { 'signature-input': signatureInput, signature: sigField } }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export type HttpSignatureFailure =
  | 'missing-signature'
  | 'malformed-signature'
  | 'no-matching-signature'
  | 'unsupported-component'
  | 'component-unresolvable'
  | 'insufficient-coverage'
  | 'body-not-bound'
  | 'digest-mismatch'
  | 'missing-created'
  | 'missing-expires'
  | 'not-yet-valid'
  | 'too-old'
  | 'expired'
  | 'tag-mismatch'
  | 'missing-nonce'
  | 'no-key'
  | 'algorithm-mismatch'
  | 'invalid-signature'
  | 'replayed'

export type VerifyMessageResult =
  | { ok: true; signature: ParsedSignature; keyId?: string; covered: string[] }
  | { ok: false; reason: HttpSignatureFailure; detail?: string }

export interface VerifyMessageOptions {
  /** Which labelled signature to verify. Default: the first one that passes the tag filter. */
  label?: string
  /** Only consider signatures carrying exactly this `tag` (recommended: signatures are otherwise unscoped). */
  tag?: string
  /** Resolve key material for a `keyid`. Returning `null` fails verification. */
  resolveKey: (keyId: string | undefined, params: SignatureParams) => Promise<VerificationKey | null> | VerificationKey | null
  /**
   * Components that MUST be covered. A valid signature that omits any of them is
   * refused. Required and non-empty: verifying a signature that covers nothing
   * useful is how attackers get a "valid" signature over an unrelated message.
   */
  requiredComponents: string[]
  /** The raw body, so a covered `content-digest` can be checked against it. */
  body?: string | Uint8Array
  /**
   * When true and a non-empty body is present, `content-digest` must be covered
   * (and is checked). Set this on any route where the body matters.
   */
  requireBodyBinding?: boolean
  /** Maximum signature age in ms, from `created` (default 5 minutes). */
  maxAgeMs?: number
  /** Tolerated clock skew in ms (default 30 seconds). */
  clockSkewMs?: number
  /** Refuse signatures with no `created` (default true). */
  requireCreated?: boolean
  /** Refuse signatures with no `expires` (default false). */
  requireExpires?: boolean
  /** Require and consume a `nonce` (single use) through this store. */
  nonceStore?: ReplayStore
  now?: number
  request?: HttpMessage
}

export async function verifyMessage(message: HttpMessage, opts: VerifyMessageOptions): Promise<VerifyMessageResult> {
  if (opts.requiredComponents.length === 0) {
    throw new Error('verifyMessage: requiredComponents must not be empty')
  }
  const required = opts.requiredComponents.map(normalizeComponentId)

  let signatures: ParsedSignature[]
  try {
    signatures = parseSignatures(message.headers)
  } catch (e) {
    if (e instanceof HttpSignatureError) {
      return { ok: false, reason: e.code === 'missing-signature' ? 'missing-signature' : 'malformed-signature', detail: e.code }
    }
    throw e
  }

  const candidates = signatures.filter((s) => (opts.label === undefined || s.label === opts.label) && (opts.tag === undefined || s.params.tag === opts.tag))
  if (candidates.length === 0) return { ok: false, reason: opts.tag !== undefined && signatures.length > 0 && opts.label === undefined ? 'tag-mismatch' : 'no-matching-signature' }

  // Verify the first candidate only. Trying several and accepting any would let an
  // attacker append a signature they CAN produce next to one they cannot.
  const sig = candidates[0]

  for (const c of required) {
    if (!sig.components.includes(c)) return { ok: false, reason: 'insufficient-coverage', detail: c }
  }
  const digestCovered = sig.components.includes('"content-digest"')
  const hasBody = opts.body !== undefined && (typeof opts.body === 'string' ? opts.body.length > 0 : opts.body.length > 0)
  if (opts.requireBodyBinding && hasBody && !digestCovered) return { ok: false, reason: 'body-not-bound' }

  const now = opts.now ?? Date.now()
  const skewS = Math.ceil((opts.clockSkewMs ?? 30_000) / 1000)
  const nowS = Math.floor(now / 1000)
  const maxAgeS = Math.ceil((opts.maxAgeMs ?? 5 * 60_000) / 1000)
  if (sig.params.created === undefined) {
    if (opts.requireCreated !== false) return { ok: false, reason: 'missing-created' }
  } else {
    if (sig.params.created > nowS + skewS) return { ok: false, reason: 'not-yet-valid' }
    if (nowS - sig.params.created > maxAgeS + skewS) return { ok: false, reason: 'too-old' }
  }
  if (sig.params.expires === undefined) {
    if (opts.requireExpires) return { ok: false, reason: 'missing-expires' }
  } else if (nowS >= sig.params.expires) {
    return { ok: false, reason: 'expired' }
  }

  const key = await opts.resolveKey(sig.params.keyid, sig.params)
  if (!key) return { ok: false, reason: 'no-key' }
  // The algorithm comes from the key the verifier trusts, never from the message.
  if (sig.params.alg !== undefined && sig.params.alg !== key.alg) return { ok: false, reason: 'algorithm-mismatch' }

  let base: string
  try {
    base = buildSignatureBase(sig.components, sig.signatureParamsValue, {
      message,
      request: opts.request,
      isResponse: message.status !== undefined,
    })
  } catch (e) {
    if (e instanceof HttpSignatureError) {
      const unsupported = e.code === 'unsupported-component-parameter' || e.code === 'unknown-derived-component'
      return { ok: false, reason: unsupported ? 'unsupported-component' : 'component-unresolvable', detail: e.code }
    }
    throw e
  }
  if (!(await verifyBytes(key, encoder.encode(base), sig.signature))) return { ok: false, reason: 'invalid-signature' }

  // Signature is authentic; now make the covered digest mean something.
  if (digestCovered && opts.body !== undefined) {
    const header = fieldValue(message.headers, 'content-digest')
    if (!(await verifyContentDigest(header, opts.body))) return { ok: false, reason: 'digest-mismatch' }
  }

  // Consume the nonce last, only for an otherwise fully valid signature.
  if (opts.nonceStore) {
    if (sig.params.nonce === undefined) return { ok: false, reason: 'missing-nonce' }
    const lifetimeMs = Math.max(1, (maxAgeS + skewS) * 1000)
    const replayed = await opts.nonceStore.check(`7h3:http-sig:${sig.params.keyid ?? ''}:${sig.params.nonce}`, lifetimeMs)
    if (replayed) return { ok: false, reason: 'replayed' }
  }
  return { ok: true, signature: sig, keyId: sig.params.keyid, covered: sig.components }
}

/** Convenience: the base64url form 7h3 uses elsewhere for a base64 signature. */
export const signatureToBase64Url = (sig: Uint8Array): string => toBase64Url(bytesToBase64(sig))
