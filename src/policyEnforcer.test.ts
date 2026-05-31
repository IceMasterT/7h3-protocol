import { describe, expect, it } from 'vitest'
import { bootstrapRuntimePolicyEnforcer, createPolicyEnforcer, isRuntimeMode } from './policyEnforcer'
import type { RuntimePolicy } from './runtimePolicy'

const policy: RuntimePolicy = {
  version: '1.0',
  name: 'gluv-runtime-policy',
  status: 'active',
  slo_defaults: {
    drop_pct_max: 0.1,
    p99_ms_max: 20,
  },
  tuning: {
    batch_size: {
      low_traffic: [4, 8],
      medium_traffic: [8, 32],
      high_traffic: [32, 64],
    },
    inflight_cap: {
      low_traffic: [16, 64],
      medium_traffic: [64, 256],
      high_traffic: [256, 1024],
    },
    retry_backoff_ms: {
      low_traffic: [1, 2],
      medium_traffic: [2, 8],
      high_traffic: [4, 16],
    },
    max_retry_attempts: 3,
    retriable_status_codes: [503],
  },
}

describe('policy enforcer', () => {
  it('selects binary batch for high concurrency', () => {
    const enforcer = createPolicyEnforcer(policy)
    expect(enforcer.selectMode({ concurrency: 100 })).toBe('http-binary-batch')
  })

  it('selects ws-batch for latency-sensitive low concurrency', () => {
    const enforcer = createPolicyEnforcer(policy)
    expect(enforcer.selectMode({ concurrency: 10, latencySensitive: true })).toBe('ws-batch')
  })

  it('returns tuning ranges and remediation actions', () => {
    const enforcer = createPolicyEnforcer(policy)
    const decision = enforcer.tune({
      trafficClass: 'high',
      dropPct: 1,
      p99Ms: 30,
    })
    expect(decision.batchSizeRange).toEqual([32, 64])
    expect(decision.inflightCapRange).toEqual([256, 1024])
    expect(decision.retryBackoffMsRange).toEqual([4, 16])
    expect(decision.actions.length).toBeGreaterThan(0)
  })

  it('retries only retriable status and under attempt cap', () => {
    const enforcer = createPolicyEnforcer(policy)
    expect(enforcer.shouldRetry({ error: new Error('http status 503: overloaded'), attempt: 1 })).toBe(true)
    expect(enforcer.shouldRetry({ error: new Error('http status 400: bad request'), attempt: 1 })).toBe(false)
    expect(enforcer.shouldRetry({ error: new Error('http status 503: overloaded'), attempt: 3 })).toBe(false)
  })

  it('asserts invariants', () => {
    const enforcer = createPolicyEnforcer(policy)
    expect(() =>
      enforcer.assertInvariant({
        signatureVerification: true,
        canonicalization: true,
        replayDefense: true,
        ttlClockSkewEnforcement: true,
      }),
    ).not.toThrow()
    expect(() =>
      enforcer.assertInvariant({
        signatureVerification: false,
        canonicalization: true,
        replayDefense: true,
        ttlClockSkewEnforcement: true,
      }),
    ).toThrow(/Invariant violation/i)
  })

  it('checks runtime mode literals', () => {
    expect(isRuntimeMode('http-binary-batch')).toBe(true)
    expect(isRuntimeMode('invalid-mode')).toBe(false)
  })

  it('bootstraps policy + enforcer in one call', async () => {
    const bootstrapped = await bootstrapRuntimePolicyEnforcer({
      path: '/virtual/AI_RUNTIME_POLICY.json',
      readTextFile: async () => JSON.stringify(policy),
    })

    expect(bootstrapped.policy.name).toBe('gluv-runtime-policy')
    expect(bootstrapped.enforcer.selectMode({ concurrency: 100 })).toBe('http-binary-batch')
  })
})
