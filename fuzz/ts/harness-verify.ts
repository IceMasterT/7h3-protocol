/**
 * Fuzz harness: signature verification with tampered envelopes.
 *
 * Invariants:
 *   1. verifyEnvelopeHmac must NEVER throw — tampered or malformed envelopes
 *      must return false, not crash.
 *   2. A valid envelope always verifies as true (regression check).
 *   3. Single-byte tampering of any signed field must make verification fail.
 *
 * Strategy: start from valid signed envelopes, apply structural and byte mutations.
 */

import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createEnvelope, signEnvelopeHmac, verifyEnvelopeHmac } from '../../src/index.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const VECTORS_PATH = join(__dir, '../../conformance/7h3_v0_1.json')
const ROUNDS = parseInt(process.env.FUZZ_ROUNDS ?? '20000', 10)

const { vectors } = JSON.parse(readFileSync(VECTORS_PATH, 'utf-8'))

const SECRET = vectors[0].secret as string

// Build and sign a fresh envelope so we have a known-valid baseline
const BASE_ENVELOPE = await signEnvelopeHmac(
  createEnvelope({ sender: 'fuzzer', recipient: 'target', intent: 'TASK', content: 'baseline' }),
  SECRET,
)

// Regression: valid envelope must verify
const baseOk = await verifyEnvelopeHmac(BASE_ENVELOPE, SECRET)
if (!baseOk) {
  console.error('FAIL: baseline verification returned false — test setup error')
  process.exit(1)
}

// --- corpus of tampered envelopes ---
function deepClone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T
}

type Env = typeof BASE_ENVELOPE

async function tamper(env: Env, rand: () => number): Promise<Env> {
  const e = deepClone(env)
  const target = rand() < 0.5 ? 'header' : 'body'
  const obj = e[target] as unknown as Record<string, unknown>
  const keys = Object.keys(obj)
  const key = keys[Math.floor(rand() * keys.length)]
  const v = obj[key]
  // Mutate the value
  if (typeof v === 'string') {
    if (v.length === 0) {
      obj[key] = 'mutated'
    } else {
      const buf = Buffer.from(v, 'utf-8')
      const idx = Math.floor(rand() * buf.length)
      buf[idx] ^= 1 << Math.floor(rand() * 8)
      obj[key] = buf.toString('utf-8')
    }
  } else if (typeof v === 'number') {
    // Ensure delta is non-zero: map [0, 999] → [-500, -1] ∪ [1, 500]
    const raw = Math.floor(rand() * 1000)
    const delta = raw < 500 ? raw - 500 : raw - 499 // skips 0
    obj[key] = v + delta
  } else {
    obj[key] = null
  }

  // Guard: if the mutation produced no net change (e.g. bit flip round-tripped
  // through invalid UTF-8 to the same replacement character), force a known change.
  if (JSON.stringify(e) === JSON.stringify(env)) {
    const guard = e.body as unknown as Record<string, unknown>
    guard['content'] = '__forced_tamper__'
  }

  return e
}

// --- runner ---
let crashes = 0
let tamperFalsePositive = 0

for (let i = 0; i < ROUNDS; i++) {
  const rand = () => Math.random()
  const tampered = await tamper(BASE_ENVELOPE, rand)

  try {
    const result = await verifyEnvelopeHmac(tampered, SECRET)
    if (result === true) {
      tamperFalsePositive++
      console.error(`\nFAIL false positive at round ${i} — tampered envelope verified as ok`)
      console.error('  Tampered:', JSON.stringify(tampered).slice(0, 300))
    }
  } catch (err) {
    crashes++
    console.error(`\nCRASH at round ${i}:`)
    console.error('  Input:', JSON.stringify(tampered).slice(0, 300))
    console.error('  Error:', err)
  }

  // Occasionally test with a structurally broken envelope (missing fields)
  if (i % 200 === 0) {
    const broken = { header: {}, body: {}, signature: BASE_ENVELOPE.signature } as unknown as Env
    try {
      await verifyEnvelopeHmac(broken, SECRET)
    } catch (err) {
      crashes++
      console.error(`\nCRASH (broken envelope) at round ${i}:`, err)
    }
  }
}

console.log(
  `[harness-verify] rounds=${ROUNDS} tamper-false-positives=${tamperFalsePositive} crashes=${crashes}`,
)
if (crashes > 0 || tamperFalsePositive > 0) {
  process.exit(1)
}
