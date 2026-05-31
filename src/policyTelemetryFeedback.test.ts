import { describe, expect, it } from 'vitest'
import { recommendPolicyAdjustments } from './policyTelemetryFeedback'

describe('policy telemetry feedback', () => {
  it('returns critical recommendation for severe drop/latency', () => {
    const rec = recommendPolicyAdjustments({
      mode: 'http',
      p99Ms: 120,
      dropPct: 5,
      concurrency: 200,
    })
    expect(rec.severity).toBe('critical')
    expect(rec.actions.length).toBeGreaterThan(0)
  })

  it('returns normal when metrics are healthy', () => {
    const rec = recommendPolicyAdjustments({
      mode: 'http-binary-batch',
      p99Ms: 8,
      dropPct: 0,
      concurrency: 100,
    })
    expect(rec.severity).toBe('normal')
  })
})
