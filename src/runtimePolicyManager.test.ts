import { describe, expect, it } from 'vitest'
import { RuntimePolicyManager } from './runtimePolicyManager'

describe('runtime policy manager', () => {
  it('loads initial policy and exposes snapshot', async () => {
    const manager = new RuntimePolicyManager({
      path: '/virtual/AI_RUNTIME_POLICY.json',
      readTextFile: async () =>
        JSON.stringify({
          version: '1.0',
          name: 'gluv-runtime-policy',
          status: 'active',
          hard_invariants: {},
          slo_defaults: {},
          tuning: {
            batch_size: { low_traffic: [4, 8], medium_traffic: [8, 32], high_traffic: [32, 64] },
            inflight_cap: { low_traffic: [16, 64], medium_traffic: [64, 256], high_traffic: [256, 1024] },
            retry_backoff_ms: { low_traffic: [1, 2], medium_traffic: [2, 8], high_traffic: [4, 16] },
            max_retry_attempts: 3,
            retriable_status_codes: [503],
          },
        }),
    })

    const loaded = await manager.loadInitial()
    expect(loaded.policy.name).toBe('gluv-runtime-policy')
    expect(manager.current().policy.version).toBe('1.0')
  })
})
