/**
 * Fuzz harness: wire decoder resilience.
 *
 * Invariant: decodeEnvelope must NEVER throw on any input — arbitrary strings
 * and arbitrary bytes both. On garbage it must return {ok: false}.
 *
 * Strategy: start from the conformance corpus, apply mutations, run N rounds.
 */

import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { decodeEnvelope } from '../../src/index.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const VECTORS_PATH = join(__dir, '../../conformance/7h3_v0_1.json')
const ROUNDS = parseInt(process.env.FUZZ_ROUNDS ?? '50000', 10)

const { vectors, ed25519Vectors = [] } = JSON.parse(readFileSync(VECTORS_PATH, 'utf-8'))

// --- corpus: valid JSON and compact encodings from conformance vectors ---
const corpus: (string | Uint8Array)[] = []
for (const v of [...vectors, ...ed25519Vectors]) {
  const env = v.envelope
  corpus.push(JSON.stringify(env))
  // compact encoding
  corpus.push(
    JSON.stringify({
      v: env.header?.version,
      mid: env.header?.messageId,
      ts: env.header?.timestampMs,
      ttl: env.header?.ttlMs,
      s: env.header?.sender,
      n: env.header?.nonce,
      i: env.body?.intent,
      c: env.body?.content,
    }),
  )
}
// seed with known-bad corpus
corpus.push('', '{}', '[]', 'null', '"string"', '{', '{"header":{}}', '{"header":{},"body":{}}')

// --- mutators ---
type Mutator = (input: string, rand: () => number) => string

const mutators: Mutator[] = [
  // bit flip a byte
  (s, r) => {
    const buf = Buffer.from(s, 'utf-8')
    if (!buf.length) return s
    buf[Math.floor(r() * buf.length)] ^= 1 << Math.floor(r() * 8)
    return buf.toString('utf-8')
  },
  // insert random byte
  (s, r) => {
    const buf = Buffer.from(s, 'utf-8')
    const idx = Math.floor(r() * (buf.length + 1))
    const b = Math.floor(r() * 256)
    return Buffer.concat([buf.subarray(0, idx), Buffer.from([b]), buf.subarray(idx)]).toString('utf-8')
  },
  // delete a byte
  (s, r) => {
    const buf = Buffer.from(s, 'utf-8')
    if (!buf.length) return s
    const idx = Math.floor(r() * buf.length)
    return Buffer.concat([buf.subarray(0, idx), buf.subarray(idx + 1)]).toString('utf-8')
  },
  // truncate
  (s, r) => {
    const buf = Buffer.from(s, 'utf-8')
    return buf.subarray(0, Math.floor(r() * buf.length)).toString('utf-8')
  },
  // mutate a JSON field
  (s, r) => {
    try {
      const obj = JSON.parse(s) as Record<string, unknown>
      const keys = Object.keys(obj)
      if (!keys.length) return s
      const key = keys[Math.floor(r() * keys.length)]
      const replacement = [null, 0, 1, -1, '', [], {}, true, false][Math.floor(r() * 9)]
      obj[key] = replacement
      return JSON.stringify(obj)
    } catch {
      return s
    }
  },
  // replace a known token with another
  (s, r) => {
    const tokens = ['7h3/0.1', 'TASK', 'PING', 'RESULT', 'HS256', 'ED25519', '"sender"', '"body"']
    const replacements = ['aip/0.2', 'INVALID', '', '0', 'NONE', 'RSA', '"SENDER"', '"Body"']
    const i = Math.floor(r() * tokens.length)
    return s.split(tokens[i]).join(replacements[i])
  },
]

// --- runner ---
let crashes = 0
let okFalse = 0
let okTrue = 0

function rand(): number {
  return Math.random()
}

let current = corpus[0] as string

for (let i = 0; i < ROUNDS; i++) {
  // pick a mutator and apply it
  const mutator = mutators[Math.floor(rand() * mutators.length)]
  current = mutator(current, rand)

  // occasionally reset to a fresh corpus item
  if (i % 500 === 0) {
    current = corpus[Math.floor(rand() * corpus.length)] as string
  }

  try {
    const result = decodeEnvelope(current)
    if (result.ok) {
      okTrue++
    } else {
      okFalse++
    }
  } catch (err) {
    crashes++
    console.error(`\nCRASH at round ${i}:`)
    console.error('  Input (first 200 chars):', JSON.stringify(current.slice(0, 200)))
    console.error('  Error:', err)
  }
}

console.log(`[harness-decode] rounds=${ROUNDS} ok=${okTrue} ok:false=${okFalse} crashes=${crashes}`)
if (crashes > 0) {
  console.error(`FAIL: ${crashes} crash(es) detected`)
  process.exit(1)
}
