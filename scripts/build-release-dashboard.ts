import { access, mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises'
import process from 'node:process'

interface E2ERow {
  mode: string
  payloadBytes: number
  concurrency: number
  opsPerSecond: number
  p99Ms: number
}

interface OpenLoopRow {
  mode: string
  payloadBytes: number
  concurrency: number
  opsPerSecond: number
  p99Ms: number
  dropPct: number
}

interface SignatureRow {
  algorithm: 'HS256' | 'ED25519'
  signUsPerOp: number
  verifyUsPerOp: number
}

interface WireRow {
  payloadBytes: number
  format: 'compact-json' | 'binary'
  encodedBytes: number
  encodeUsPerOp: number
  decodeUsPerOp: number
}

async function readJson<T>(filePath: string): Promise<T> {
  const raw = await readFile(filePath, 'utf8')
  return JSON.parse(raw) as T
}

async function readJsonIfExists<T>(filePath: string): Promise<T | null> {
  try {
    await access(filePath)
    return await readJson<T>(filePath)
  } catch {
    return null
  }
}

async function newestFileMatching(dir: string, prefix: string): Promise<string | null> {
  let entries: string[]
  try {
    entries = await readdir(dir)
  } catch {
    return null
  }

  const matches = entries.filter((name) => name.startsWith(prefix) && name.endsWith('.json'))
  if (matches.length === 0) return null

  let newest: { path: string; mtimeMs: number } | null = null
  for (const name of matches) {
    const path = `${dir}/${name}`
    const info = await stat(path)
    if (!newest || info.mtimeMs > newest.mtimeMs) {
      newest = { path, mtimeMs: info.mtimeMs }
    }
  }
  return newest?.path ?? null
}

function range(values: number[]): { min: number; max: number } {
  if (values.length === 0) return { min: 0, max: 0 }
  return {
    min: Number(Math.min(...values).toFixed(3)),
    max: Number(Math.max(...values).toFixed(3)),
  }
}

async function main(): Promise<void> {
  const warnings: string[] = []

  const e2e = await readJsonIfExists<{ results: E2ERow[] }>('dist/bench/protocol-e2e.quick.latest.json')
  const openloop = await readJsonIfExists<{ results: OpenLoopRow[] }>('dist/bench/protocol-openloop.quick.latest.json')
  if (!e2e) warnings.push('Missing dist/bench/protocol-e2e.quick.latest.json (run npm run bench:e2e:quick)')
  if (!openloop) warnings.push('Missing dist/bench/protocol-openloop.quick.latest.json (run npm run bench:openloop:adaptive:quick)')

  const signaturePath = await newestFileMatching('bench-results', 'signature-profiles-quick-')
  const wirePath = await newestFileMatching('bench-results', 'wire-codecs-quick-')

  const signature = signaturePath ? await readJson<{ results: SignatureRow[] }>(signaturePath) : { results: [] }
  const wire = wirePath ? await readJson<{ results: WireRow[] }>(wirePath) : { results: [] }

  const e2eRows = e2e?.results ?? []
  const openloopRows = openloop?.results ?? []

  const e2eHttp1000 = e2eRows.find((row) => row.mode === 'http' && row.payloadBytes === 256 && row.concurrency === 1000) ?? null
  const e2eWs100 = e2eRows.find((row) => row.mode === 'ws' && row.payloadBytes === 256 && row.concurrency === 100) ?? null
  const e2eInproc100 = e2eRows.find((row) => row.mode === 'inproc' && row.payloadBytes === 256 && row.concurrency === 100) ?? null

  const openloopHttp1000 = openloopRows.find((row) => row.mode === 'http' && row.payloadBytes === 256 && row.concurrency === 1000) ?? null

  const hs = signature.results.filter((row) => row.algorithm === 'HS256')
  const ed = signature.results.filter((row) => row.algorithm === 'ED25519')
  const hsSign = range(hs.map((row) => row.signUsPerOp))
  const hsVerify = range(hs.map((row) => row.verifyUsPerOp))
  const edSign = range(ed.map((row) => row.signUsPerOp))
  const edVerify = range(ed.map((row) => row.verifyUsPerOp))

  const wire256Compact =
    wire.results.find((row) => row.payloadBytes === 256 && row.format === 'compact-json') ?? null
  const wire256Binary = wire.results.find((row) => row.payloadBytes === 256 && row.format === 'binary') ?? null

  const dashboard = {
    generatedAt: new Date().toISOString(),
    warnings,
    highlights: {
      e2eHttp1000,
      e2eWs100,
      e2eInproc100,
      openloopHttp1000,
      signatures: {
        hs256: { signUsPerOp: hsSign, verifyUsPerOp: hsVerify },
        ed25519: { signUsPerOp: edSign, verifyUsPerOp: edVerify },
      },
      wire256: {
        compact: wire256Compact,
        binary: wire256Binary,
      },
    },
  }

  const markdownLines = [
    '# Release Dashboard (Quick Bench)',
    '',
    `Generated: ${dashboard.generatedAt}`,
    ...(warnings.length > 0
      ? ['', '## Warnings', '', ...warnings.map((warning) => `- ${warning}`)]
      : []),
    '',
    '## Transport highlights',
    '',
    `- E2E HTTP 256B c=1000: ops/s=${e2eHttp1000?.opsPerSecond ?? 0}, p99=${e2eHttp1000?.p99Ms ?? 0}ms`,
    `- E2E WS 256B c=100: ops/s=${e2eWs100?.opsPerSecond ?? 0}, p99=${e2eWs100?.p99Ms ?? 0}ms`,
    `- E2E InProc 256B c=100: ops/s=${e2eInproc100?.opsPerSecond ?? 0}, p99=${e2eInproc100?.p99Ms ?? 0}ms`,
    `- OpenLoop HTTP 256B c=1000: ops/s=${openloopHttp1000?.opsPerSecond ?? 0}, p99=${openloopHttp1000?.p99Ms ?? 0}ms, drop=${openloopHttp1000?.dropPct ?? 0}%`,
    '',
    '## Signature ranges (us/op)',
    '',
    `- HS256 sign=${hsSign.min}-${hsSign.max}, verify=${hsVerify.min}-${hsVerify.max}`,
    `- ED25519 sign=${edSign.min}-${edSign.max}, verify=${edVerify.min}-${edVerify.max}`,
    '',
    '## Wire format (256B)',
    '',
    `- compact-json size=${wire256Compact?.encodedBytes ?? 0}B, enc=${wire256Compact?.encodeUsPerOp ?? 0}us, dec=${wire256Compact?.decodeUsPerOp ?? 0}us`,
    `- binary size=${wire256Binary?.encodedBytes ?? 0}B, enc=${wire256Binary?.encodeUsPerOp ?? 0}us, dec=${wire256Binary?.decodeUsPerOp ?? 0}us`,
    '',
  ]

  await mkdir('dist/release-dashboard', { recursive: true })
  await writeFile('dist/release-dashboard/latest.json', `${JSON.stringify(dashboard, null, 2)}\n`, 'utf8')
  await writeFile('dist/release-dashboard/latest.md', `${markdownLines.join('\n')}\n`, 'utf8')

  console.log('Wrote dist/release-dashboard/latest.json')
  console.log('Wrote dist/release-dashboard/latest.md')
  if (warnings.length > 0) {
    console.log('Dashboard generated with warnings:')
    for (const warning of warnings) console.log(`- ${warning}`)
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
