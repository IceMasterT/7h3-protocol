export interface TelemetryFeedbackInput {
  mode: string
  p99Ms: number
  dropPct: number
  concurrency: number
}

export interface TelemetryFeedbackRecommendation {
  severity: 'normal' | 'warn' | 'critical'
  actions: string[]
}

export function recommendPolicyAdjustments(input: TelemetryFeedbackInput): TelemetryFeedbackRecommendation {
  const actions: string[] = []
  let severity: TelemetryFeedbackRecommendation['severity'] = 'normal'

  if (input.dropPct > 0.1) {
    actions.push('reduce inflight cap')
    actions.push('reduce batch size')
    actions.push('increase retry backoff')
    if (input.mode === 'http' && input.concurrency >= 100) {
      actions.push('switch to http-binary-batch')
    }
    severity = input.dropPct > 2 ? 'critical' : 'warn'
  }

  if (input.p99Ms > 20) {
    actions.push('reduce batch size')
    actions.push('run adaptive benchmark and re-baseline')
    if (severity === 'normal') severity = 'warn'
    if (input.p99Ms > 100) severity = 'critical'
  }

  return {
    severity,
    actions,
  }
}
