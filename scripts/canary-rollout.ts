interface CanaryStage {
  percent: number
  durationMinutes: number
  required: {
    maxDropPct: number
    maxP99Ms: number
  }
}

const DEFAULT_PLAN: CanaryStage[] = [
  { percent: 5, durationMinutes: 15, required: { maxDropPct: 0.1, maxP99Ms: 20 } },
  { percent: 25, durationMinutes: 30, required: { maxDropPct: 0.1, maxP99Ms: 20 } },
  { percent: 50, durationMinutes: 30, required: { maxDropPct: 0.1, maxP99Ms: 20 } },
  { percent: 100, durationMinutes: 60, required: { maxDropPct: 0.1, maxP99Ms: 20 } },
]

function renderStage(stage: CanaryStage): string {
  return [
    `- Stage ${stage.percent}% for ${stage.durationMinutes}m`,
    `  - maxDropPct <= ${stage.required.maxDropPct}`,
    `  - maxP99Ms <= ${stage.required.maxP99Ms}`,
  ].join('\n')
}

async function main(): Promise<void> {
  console.log('Canary rollout plan')
  console.log('===================')
  for (const stage of DEFAULT_PLAN) {
    console.log(renderStage(stage))
  }
  console.log('\nRollback trigger: if any stage breaches limits for sustained window, rollback immediately.')
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
