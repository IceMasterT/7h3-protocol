import { mkdir, writeFile } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import process from 'node:process'
import { createEnvelope, signEnvelopeHmac } from '../src/protocol'
import { decodeEnvelope, encodeEnvelope } from '../src/protocolTransport'
import { decodeEnvelopeBinary, encodeEnvelopeBinary } from '../src/protocolBinary'

type ProfileName = 'quick' | 'full'

interface Profile {
  iterations: number
}

interface CodecResult {
  profile: ProfileName
  payloadBytes: number
  format: 'compact-json' | 'binary'
  encodedBytes: number
  encodeUsPerOp: number
  decodeUsPerOp: number
  encodeOpsPerSecond: number
  decodeOpsPerSecond: number
}

const PROFILES: Record<ProfileName, Profile> = {
  quick: { iterations: 10_000 },
  full: { iterations: 100_000 },
}

const PAYLOAD_SIZES = [256, 1024, 4096, 16384]

function parseProfile(argv: string[]): ProfileName {
  const idx = argv.indexOf('--profile')
  if (idx >= 0) {
    const value = argv[idx + 1]
    if (value === 'quick' || value === 'full') return value
  }
  return 'quick'
}

function payloadOfSize(bytes: number): string {
  return 'x'.repeat(bytes)
}

function round3(value: number): number {
  return Number(value.toFixed(3))
}

async function run(): Promise<void> {
  const profileName = parseProfile(process.argv)
  const profile = PROFILES[profileName]

  const results: CodecResult[] = []

  for (const payloadBytes of PAYLOAD_SIZES) {
    const envelope = await signEnvelopeHmac(
      createEnvelope({
        sender: 'agent.bench',
        recipient: 'agent.verify',
        intent: 'TASK',
        content: payloadOfSize(payloadBytes),
        capability: 'task.bench',
        correlationId: `corr-${payloadBytes}`,
        messageId: `m-${payloadBytes}`,
        nonce: `n-${payloadBytes}`,
        nowMs: 1_700_000_000_000,
        ttlMs: 60_000,
      }),
      'bench-secret',
      'k1',
    )

    const compactEncoded = encodeEnvelope(envelope, 'compact')
    const compactSize = Buffer.byteLength(compactEncoded, 'utf8')
    const compactEncodeStart = performance.now()
    for (let i = 0; i < profile.iterations; i += 1) {
      encodeEnvelope(envelope, 'compact')
    }
    const compactEncodeMs = performance.now() - compactEncodeStart

    const compactDecodeStart = performance.now()
    for (let i = 0; i < profile.iterations; i += 1) {
      const decoded = decodeEnvelope(compactEncoded)
      if (!decoded.ok) throw new Error('Compact decode failed')
    }
    const compactDecodeMs = performance.now() - compactDecodeStart

    results.push({
      profile: profileName,
      payloadBytes,
      format: 'compact-json',
      encodedBytes: compactSize,
      encodeUsPerOp: round3((compactEncodeMs * 1000) / profile.iterations),
      decodeUsPerOp: round3((compactDecodeMs * 1000) / profile.iterations),
      encodeOpsPerSecond: round3((profile.iterations * 1000) / compactEncodeMs),
      decodeOpsPerSecond: round3((profile.iterations * 1000) / compactDecodeMs),
    })

    const binaryEncoded = encodeEnvelopeBinary(envelope)
    const binaryEncodeStart = performance.now()
    for (let i = 0; i < profile.iterations; i += 1) {
      encodeEnvelopeBinary(envelope)
    }
    const binaryEncodeMs = performance.now() - binaryEncodeStart

    const binaryDecodeStart = performance.now()
    for (let i = 0; i < profile.iterations; i += 1) {
      const decoded = decodeEnvelopeBinary(binaryEncoded)
      if (!decoded.ok) throw new Error('Binary decode failed')
    }
    const binaryDecodeMs = performance.now() - binaryDecodeStart

    results.push({
      profile: profileName,
      payloadBytes,
      format: 'binary',
      encodedBytes: binaryEncoded.byteLength,
      encodeUsPerOp: round3((binaryEncodeMs * 1000) / profile.iterations),
      decodeUsPerOp: round3((binaryDecodeMs * 1000) / profile.iterations),
      encodeOpsPerSecond: round3((profile.iterations * 1000) / binaryEncodeMs),
      decodeOpsPerSecond: round3((profile.iterations * 1000) / binaryDecodeMs),
    })
  }

  console.log('\nWire codec benchmark results\n')
  for (const row of results) {
    console.log(
      [
        `profile=${row.profile}`,
        `payload=${row.payloadBytes}B`,
        `format=${row.format}`,
        `size=${row.encodedBytes}B`,
        `enc_us=${row.encodeUsPerOp}`,
        `dec_us=${row.decodeUsPerOp}`,
        `enc_ops_s=${row.encodeOpsPerSecond}`,
        `dec_ops_s=${row.decodeOpsPerSecond}`,
      ].join(' | '),
    )
  }

  await mkdir('bench-results', { recursive: true })
  const outputPath = `bench-results/wire-codecs-${profileName}-${Date.now()}.json`
  await writeFile(
    outputPath,
    `${JSON.stringify({
      generatedAt: new Date().toISOString(),
      profile: profileName,
      iterations: profile.iterations,
      payloadSizes: PAYLOAD_SIZES,
      results,
    }, null, 2)}\n`,
    'utf8',
  )
  console.log(`\nSaved benchmark results to ${outputPath}`)
}

run().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
