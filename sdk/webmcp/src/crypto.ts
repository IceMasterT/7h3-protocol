/**
 * Small Web Crypto helpers shared by the receipt chain and the manifest.
 *
 * Deliberately Web Crypto only — no Node built-ins, no dependencies — so this
 * package runs unchanged in a page, a Worker, and a test process.
 */

const encoder = new TextEncoder()

/** Lowercase hex SHA-256 of a UTF-8 string. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Deterministic JSON: object keys sorted alphabetically at every level.
 *
 * The whole protocol depends on two parties producing byte-identical payloads
 * from the same logical value, so this must never depend on insertion order.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`
}
