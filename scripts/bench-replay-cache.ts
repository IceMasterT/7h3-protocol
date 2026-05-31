import { mkdir, writeFile } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import process from 'node:process'
import { createEnvelope, type ProtocolEnvelope } from '../src/protocol'
import { InMemoryReplayCache } from '../src/protocolReplay'

type ProfileName = 'quick' | 'full'

const PROFILES: Record<ProfileName, { iterations: number; batchSize: number }> = {
  quick: { iterations: 50_000, batchSize: 32 },
  full: { iterations: 500_000, batchSize: 128 },
}

function parseProfile(argv: string[]): ProfileName {
  const idx = argv.indexOf('--profile')
  const value = idx >= 0 ? argv[idx + 1] : undefined
  return value === 'full' ? 'full' : 'quick'
}

function buildEnvelope(sequence: number): ProtocolEnvelope {
  return createEnvelope({
    sender: 'bench.replay',
    intent: 'PING',
    content: 'replay-bench',
    messageId: `replay-${sequence}`,
    nonce: `nonce-${sequence}`,
    nowMs: 1_700_000_000_000,
    ttlMs: 60_000,
  })
}

function round3(value: number): number {
  return Number(value.toFixed(3))
}

async function run(): Promise<void> {
  const profileName = parseProfile(process.argv)
  const profile = PROFILES[profileName]
  const cache = new InMemoryReplayCache(profile.iterations * 2)
  const envelopes = Array.from({ length: profile.iterations }, (_, index) => buildEnvelope(index))

  const singleStart = performance.now()
  for (const envelope of envelopes) {
    const result = cache.consume(envelope, 1_700_000_000_001)
    if (!result.ok) throw new Error('single replay benchmark unexpectedly rejected envelope')
  }
  const singleMs = performance.now() - singleStart

  const batchCache = new InMemoryReplayCache(profile.iterations * 2)
  const batchStart = performance.now()
  for (let offset = 0; offset < envelopes.length; offset += profile.batchSize) {
    const results = batchCache.consumeMany(envelopes.slice(offset, offset + profile.batchSize), 1_700_000_000_001)
    if (results.some((result) => !result.ok)) throw new Error('batch replay benchmark unexpectedly rejected envelope')
  }
  const batchMs = performance.now() - batchStart

  const output = {
    generatedAt: new Date().toISOString(),
    profile: profileName,
    iterations: profile.iterations,
    batchSize: profile.batchSize,
    singleOpsPerSecond: round3((profile.iterations * 1000) / singleMs),
    batchOpsPerSecond: round3((profile.iterations * 1000) / batchMs),
    singleUsPerOp: round3((singleMs * 1000) / profile.iterations),
    batchUsPerOp: round3((batchMs * 1000) / profile.iterations),
  }

  console.log(JSON.stringify(output, null, 2))
  await mkdir('bench-results', { recursive: true })
  await writeFile(`bench-results/replay-cache-${profileName}-${Date.now()}.json`, `${JSON.stringify(output, null, 2)}\n`, 'utf8')
}

run().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error))
  process.exitCode = 1
})
