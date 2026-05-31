import { mkdir, writeFile } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import process from 'node:process'
import {
  canonicalizeEnvelope,
  createEnvelope,
  generateEd25519KeypairBase64Url,
  signCanonicalPayloadEd25519,
  signCanonicalPayloadHmac,
  verifyCanonicalPayloadEd25519,
  verifyCanonicalPayloadHmac,
} from '../src/protocol'

type ProfileName = 'quick' | 'full'
type SignatureAlg = 'HS256' | 'ED25519'

interface Profile {
  iterations: number
}

interface ScenarioResult {
  profile: ProfileName
  payloadBytes: number
  algorithm: SignatureAlg
  signUsPerOp: number
  verifyUsPerOp: number
  signOpsPerSecond: number
  verifyOpsPerSecond: number
}

const PROFILES: Record<ProfileName, Profile> = {
  quick: { iterations: 2_000 },
  full: { iterations: 20_000 },
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
  if (bytes <= 0) return ''
  return 'x'.repeat(bytes)
}

function round3(value: number): number {
  return Number(value.toFixed(3))
}

async function measureSignVerify(
  algorithm: SignatureAlg,
  canonical: string,
  iterations: number,
  material: { secret: string } | { privateKey: string; publicKey: string },
): Promise<Pick<ScenarioResult, 'signUsPerOp' | 'verifyUsPerOp' | 'signOpsPerSecond' | 'verifyOpsPerSecond'>> {
  const signStart = performance.now()
  let lastSignature = ''
  for (let i = 0; i < iterations; i += 1) {
    if (algorithm === 'HS256') {
      lastSignature = await signCanonicalPayloadHmac(canonical, material.secret)
    } else {
      lastSignature = await signCanonicalPayloadEd25519(canonical, material.privateKey)
    }
  }
  const signMs = performance.now() - signStart

  const verifyStart = performance.now()
  let verifiedCount = 0
  for (let i = 0; i < iterations; i += 1) {
    const ok =
      algorithm === 'HS256'
        ? await verifyCanonicalPayloadHmac(canonical, lastSignature, material.secret)
        : await verifyCanonicalPayloadEd25519(canonical, lastSignature, material.publicKey)
    if (ok) verifiedCount += 1
  }
  const verifyMs = performance.now() - verifyStart
  if (verifiedCount !== iterations) {
    throw new Error(`Verification mismatch for ${algorithm}: ${verifiedCount}/${iterations}`)
  }

  return {
    signUsPerOp: round3((signMs * 1000) / iterations),
    verifyUsPerOp: round3((verifyMs * 1000) / iterations),
    signOpsPerSecond: round3((iterations * 1000) / signMs),
    verifyOpsPerSecond: round3((iterations * 1000) / verifyMs),
  }
}

function printResults(results: ScenarioResult[]): void {
  console.log('\nAIP signature profile benchmark results\n')
  for (const result of results) {
    console.log(
      [
        `profile=${result.profile}`,
        `payload=${result.payloadBytes}B`,
        `alg=${result.algorithm}`,
        `sign_us_op=${result.signUsPerOp}`,
        `verify_us_op=${result.verifyUsPerOp}`,
        `sign_ops_s=${result.signOpsPerSecond}`,
        `verify_ops_s=${result.verifyOpsPerSecond}`,
      ].join(' | '),
    )
  }
}

async function run(): Promise<void> {
  const profileName = parseProfile(process.argv)
  const profile = PROFILES[profileName]
  const sharedSecret = 'bench-signature-secret'
  const ed25519Keys = await generateEd25519KeypairBase64Url()

  const results: ScenarioResult[] = []

  for (const payloadBytes of PAYLOAD_SIZES) {
    const unsigned = createEnvelope({
      sender: 'agent.bench',
      recipient: 'agent.worker',
      intent: 'TASK',
      content: payloadOfSize(payloadBytes),
      capability: 'task.bench',
      correlationId: `bench-${payloadBytes}`,
      messageId: `bench-${payloadBytes}`,
      nonce: `n-${payloadBytes}`,
      nowMs: 1_700_000_000_000,
      ttlMs: 60_000,
    })
    const canonical = canonicalizeEnvelope(unsigned)

    const hs = await measureSignVerify('HS256', canonical, profile.iterations, { secret: sharedSecret })
    results.push({
      profile: profileName,
      payloadBytes,
      algorithm: 'HS256',
      ...hs,
    })

    const ed = await measureSignVerify('ED25519', canonical, profile.iterations, {
      privateKey: ed25519Keys.privateKey,
      publicKey: ed25519Keys.publicKey,
    })
    results.push({
      profile: profileName,
      payloadBytes,
      algorithm: 'ED25519',
      ...ed,
    })
  }

  printResults(results)
  await mkdir('bench-results', { recursive: true })
  const outputPath = `bench-results/signature-profiles-${profileName}-${Date.now()}.json`
  await writeFile(
    outputPath,
    `${JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        profile: profileName,
        iterations: profile.iterations,
        payloadSizes: PAYLOAD_SIZES,
        results,
      },
      null,
      2,
    )}\n`,
    'utf8',
  )
  console.log(`\nSaved benchmark results to ${outputPath}`)
}

run().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
