import { describe, expect, it } from 'vitest'
import { loadRuntimePolicy, parseRuntimePolicyJson, validateRuntimePolicy } from './runtimePolicy'

describe('runtime policy loader', () => {
  it('parses valid policy JSON', () => {
    const policy = parseRuntimePolicyJson(
      JSON.stringify({
        version: '1.0',
        name: 'gluv-runtime-policy',
        status: 'active',
      }),
    )

    expect(policy.version).toBe('1.0')
    expect(policy.name).toBe('gluv-runtime-policy')
    expect(policy.status).toBe('active')
  })

  it('rejects invalid JSON', () => {
    expect(() => parseRuntimePolicyJson('{')).toThrow(/Invalid runtime policy JSON/i)
  })

  it('rejects invalid root object', () => {
    expect(() => validateRuntimePolicy('not-an-object')).toThrow(/root must be an object/i)
  })

  it('rejects missing required fields', () => {
    expect(() => validateRuntimePolicy({ name: 'x', status: 'active' })).toThrow(/version/i)
    expect(() => validateRuntimePolicy({ version: '1.0', status: 'active' })).toThrow(/name/i)
    expect(() => validateRuntimePolicy({ version: '1.0', name: 'x' })).toThrow(/status/i)
  })

  it('loads policy using injected reader and path', async () => {
    const policy = await loadRuntimePolicy({
      path: '/virtual/AI_RUNTIME_POLICY.json',
      readTextFile: async (filePath) => {
        expect(filePath).toBe('/virtual/AI_RUNTIME_POLICY.json')
        return JSON.stringify({
          version: '1.0',
          name: 'gluv-runtime-policy',
          status: 'active',
          owner: 'platform-ai-ops',
        })
      },
    })

    expect(policy.owner).toBe('platform-ai-ops')
  })
})
