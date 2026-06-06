/**
 * Fuzz campaign runner — executes all TypeScript harnesses in sequence.
 *
 * Usage:
 *   npm run fuzz:ts              # default 50k/20k rounds
 *   FUZZ_ROUNDS=200000 npm run fuzz:ts
 */

import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dir = dirname(fileURLToPath(import.meta.url))

const HARNESSES = ['harness-decode.ts', 'harness-verify.ts']

let failed = false
for (const harness of HARNESSES) {
  process.stdout.write(`Running ${harness} ... `)
  const result = spawnSync('npx', ['tsx', join(__dir, harness)], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env },
  })
  const out = result.stdout.toString().trim()
  const err = result.stderr.toString().trim()
  if (result.status !== 0) {
    console.error(`FAIL\n${out}\n${err}`)
    failed = true
  } else {
    console.log(`PASS  ${out}`)
    if (err) console.error(err)
  }
}

process.exit(failed ? 1 : 0)
