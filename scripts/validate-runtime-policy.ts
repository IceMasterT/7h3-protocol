import { readFile } from 'node:fs/promises'
import { parseRuntimePolicyJson } from '../src/runtimePolicy'

async function main(): Promise<void> {
  const path = process.argv[2] ?? 'AI_RUNTIME_POLICY.json'
  const text = await readFile(path, 'utf8')
  const policy = parseRuntimePolicyJson(text)
  if (!policy.hard_invariants || !policy.slo_defaults || !policy.tuning) {
    throw new Error('Runtime policy is missing one or more required sections: hard_invariants, slo_defaults, tuning')
  }
  console.log(`Runtime policy validated: ${policy.name}@${policy.version} (${policy.status})`)
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
