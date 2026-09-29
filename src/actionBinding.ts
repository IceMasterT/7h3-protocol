/**
 * Shared primitives for signed statements that are bound to one concrete action
 * (approval grants, provenance claims, payment mandates).
 *
 * Two things live here because every such statement needs them and each must be
 * byte-identical everywhere it is produced or checked:
 *
 *   - `stableStringify` — deterministic JSON (recursively sorted keys) so a
 *     signature covers exactly one byte string;
 *   - `bindAction` — the `{ method, path, bodySha256 }` triple that ties a
 *     statement to a single HTTP-shaped action, so it cannot be replayed against
 *     a different route, verb or payload.
 */

/** A concrete action, reduced to the parts a statement must be bound to. */
export interface BoundAction {
  /** Upper-case HTTP method (or the RPC verb). */
  method: string
  /** Normalized absolute path (see `normalizeGatewayPath`). */
  path: string
  /** Lower-case hex SHA-256 of the request body bytes (UTF-8); empty body hashes the empty string. */
  bodySha256: string
}

export interface ActionInput {
  method: string
  path: string
  /** Request body. `undefined` and `''` are the same action. */
  body?: string | Uint8Array
}

const textEncoder = new TextEncoder()

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle
  if (!s) throw new Error('WebCrypto (crypto.subtle) is required')
  return s
}

function toHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Lower-case hex SHA-256 of a string (UTF-8) or byte array. */
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? textEncoder.encode(data) : data
  // Copy into a fresh ArrayBuffer-backed view: TypeScript 5.9 types Uint8Array as
  // possibly SharedArrayBuffer-backed, which BufferSource rejects.
  return toHex(await subtle().digest('SHA-256', new Uint8Array(bytes)))
}

/** Reduce a request to the triple statements are bound to. */
export async function bindAction(input: ActionInput): Promise<BoundAction> {
  if (typeof input.method !== 'string' || input.method.length === 0) {
    throw new Error('bindAction: method is required')
  }
  if (typeof input.path !== 'string' || !input.path.startsWith('/')) {
    throw new Error('bindAction: path must be an absolute, normalized path')
  }
  return {
    method: input.method.toUpperCase(),
    path: input.path,
    bodySha256: await sha256Hex(input.body ?? ''),
  }
}

export function actionsEqual(a: BoundAction, b: BoundAction): boolean {
  return a.method === b.method && a.path === b.path && a.bodySha256 === b.bodySha256
}

/** Structural check used when parsing untrusted JSON. */
export function isBoundAction(value: unknown): value is BoundAction {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  return (
    typeof v.method === 'string' &&
    v.method.length > 0 &&
    typeof v.path === 'string' &&
    v.path.startsWith('/') &&
    typeof v.bodySha256 === 'string' &&
    /^[0-9a-f]{64}$/.test(v.bodySha256)
  )
}

/**
 * Deterministic JSON: object keys sorted (by UTF-16 code unit) at every level,
 * arrays kept in order, no whitespace. Throws on values JSON cannot represent
 * unambiguously (`undefined`, functions, symbols, non-finite numbers, bigint)
 * so a signature can never cover something that round-trips differently.
 * `undefined` object members are rejected rather than skipped: silently dropping
 * one would let two different in-memory statements sign to the same bytes.
 */
export function stableStringify(value: unknown): string {
  if (value === null) return 'null'
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value)
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number':
      if (!Number.isFinite(value)) throw new Error('stableStringify: non-finite number')
      return JSON.stringify(value)
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
      const obj = value as Record<string, unknown>
      const keys = Object.keys(obj).sort()
      return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`
    }
    default:
      throw new Error(`stableStringify: unsupported value of type ${typeof value}`)
  }
}
