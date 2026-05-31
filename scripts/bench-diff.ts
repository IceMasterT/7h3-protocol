import { readFile } from 'node:fs/promises'

interface BenchRow {
  mode: string
  payloadBytes: number
  concurrency: number
  opsPerSecond: number
  p99Ms: number
}

interface BenchPayload {
  profile: string
  results: BenchRow[]
}

interface DiffRow {
  key: string
  baselineOps: number
  candidateOps: number
  opsChangePct: number
  baselineP99: number
  candidateP99: number
  p99ChangePct: number
  regression: boolean
}

function parseArg(flag: string, argv: string[]): string | null {
  const index = argv.indexOf(flag)
  if (index < 0) return null
  return argv[index + 1] ?? null
}

function keyOf(row: BenchRow): string {
  return `${row.mode}|${row.payloadBytes}|${row.concurrency}`
}

function round2(value: number): number {
  return Number(value.toFixed(2))
}

async function loadPayload(path: string): Promise<BenchPayload> {
  const raw = await readFile(path, 'utf8')
  const parsed = JSON.parse(raw) as BenchPayload
  if (!Array.isArray(parsed.results)) {
    throw new Error(`Invalid benchmark payload at ${path}`)
  }
  return parsed
}

function renderMarkdown(rows: DiffRow[]): string {
  const lines: string[] = []
  lines.push('| case | baseline ops/s | candidate ops/s | ops Δ% | baseline p99 | candidate p99 | p99 Δ% | regressed |')
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |')
  for (const row of rows) {
    lines.push(
      `| ${row.key} | ${row.baselineOps} | ${row.candidateOps} | ${row.opsChangePct} | ${row.baselineP99} | ${row.candidateP99} | ${row.p99ChangePct} | ${row.regression ? 'yes' : 'no'} |`,
    )
  }
  return `${lines.join('\n')}\n`
}

async function main(): Promise<void> {
  const baselinePath = parseArg('--baseline', process.argv)
  const candidatePath = parseArg('--candidate', process.argv)

  if (!baselinePath || !candidatePath) {
    throw new Error('Usage: tsx scripts/bench-diff.ts --baseline <path> --candidate <path>')
  }

  const baseline = await loadPayload(baselinePath)
  const candidate = await loadPayload(candidatePath)

  const baselineMap = new Map<string, BenchRow>()
  baseline.results.forEach((row) => baselineMap.set(keyOf(row), row))

  const diffs: DiffRow[] = []
  for (const row of candidate.results) {
    const key = keyOf(row)
    const previous = baselineMap.get(key)
    if (!previous) continue

    const opsChangePct = previous.opsPerSecond === 0 ? 0 : ((row.opsPerSecond - previous.opsPerSecond) / previous.opsPerSecond) * 100
    const p99ChangePct = previous.p99Ms === 0 ? 0 : ((row.p99Ms - previous.p99Ms) / previous.p99Ms) * 100
    const regression = opsChangePct < -5 || p99ChangePct > 10

    diffs.push({
      key,
      baselineOps: round2(previous.opsPerSecond),
      candidateOps: round2(row.opsPerSecond),
      opsChangePct: round2(opsChangePct),
      baselineP99: round2(previous.p99Ms),
      candidateP99: round2(row.p99Ms),
      p99ChangePct: round2(p99ChangePct),
      regression,
    })
  }

  diffs.sort((a, b) => {
    if (a.regression !== b.regression) return a.regression ? -1 : 1
    return a.key.localeCompare(b.key)
  })

  const regressions = diffs.filter((row) => row.regression)
  console.log(`Compared ${diffs.length} matching cases`)
  console.log(`Regressions: ${regressions.length}`)
  console.log('')
  console.log(renderMarkdown(diffs))

  if (regressions.length > 0) {
    process.exitCode = 2
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
