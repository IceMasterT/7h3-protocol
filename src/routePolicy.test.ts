import { describe, it, expect } from 'vitest'
import { matchGlob, matchPolicy, isAllowedSender, type RoutePolicy } from './routePolicy'

describe('matchGlob', () => {
  it('exact match', () => {
    expect(matchGlob('/health', '/health')).toBe(true)
    expect(matchGlob('/health', '/healthz')).toBe(false)
  })

  it('single * does not cross segments', () => {
    expect(matchGlob('/api/*', '/api/users')).toBe(true)
    expect(matchGlob('/api/*', '/api/users/list')).toBe(false)
    expect(matchGlob('/api/*', '/api/')).toBe(true) // empty segment is still "within"
  })

  it('double ** matches any depth', () => {
    expect(matchGlob('/api/**', '/api/users')).toBe(true)
    expect(matchGlob('/api/**', '/api/users/list')).toBe(true)
    expect(matchGlob('/api/**', '/api/a/b/c/d')).toBe(true)
    expect(matchGlob('/api/**', '/other/users')).toBe(false)
  })

  it('? matches single non-slash char', () => {
    expect(matchGlob('/v?/api', '/v1/api')).toBe(true)
    expect(matchGlob('/v?/api', '/v12/api')).toBe(false)
    expect(matchGlob('/v?/api', '/v//api')).toBe(false)
  })

  it('handles regex metacharacters in literal path', () => {
    expect(matchGlob('/api/v1.0/health', '/api/v1.0/health')).toBe(true)
    expect(matchGlob('/api/v1.0/health', '/api/v100/health')).toBe(false)
  })
})

describe('matchPolicy', () => {
  const policies: RoutePolicy[] = [
    { path: '/health', require: 'none' },
    { path: '/api/admin/**', require: 'ed25519', allowedSenders: ['admin-agent'] },
    { path: '/api/*', require: 'any' },
    { path: '/webhook/**', require: 'hmac' },
  ]

  it('returns first matching policy (exact before wildcard)', () => {
    const result = matchPolicy(policies, '/health')
    expect(result?.require).toBe('none')
  })

  it('matches /api/users with /api/*', () => {
    const result = matchPolicy(policies, '/api/users')
    expect(result?.require).toBe('any')
  })

  it('/api/admin/delete matches /api/admin/** before /api/*', () => {
    const result = matchPolicy(policies, '/api/admin/delete')
    expect(result?.require).toBe('ed25519')
  })

  it('matches deep webhook path', () => {
    const result = matchPolicy(policies, '/webhook/stripe/events')
    expect(result?.require).toBe('hmac')
  })

  it('returns null for no match', () => {
    const result = matchPolicy(policies, '/unknown')
    expect(result).toBeNull()
  })
})

describe('isAllowedSender', () => {
  it('allows all senders when allowedSenders not set', () => {
    const policy: RoutePolicy = { path: '/api/*', require: 'any' }
    expect(isAllowedSender(policy, 'any-agent')).toBe(true)
    expect(isAllowedSender(policy, 'another-agent')).toBe(true)
  })

  it('allows only listed senders', () => {
    const policy: RoutePolicy = { path: '/api/*', require: 'ed25519', allowedSenders: ['trusted-agent', 'another-agent'] }
    expect(isAllowedSender(policy, 'trusted-agent')).toBe(true)
    expect(isAllowedSender(policy, 'another-agent')).toBe(true)
    expect(isAllowedSender(policy, 'unknown-agent')).toBe(false)
  })

  it('empty allowedSenders array allows all', () => {
    const policy: RoutePolicy = { path: '/api/*', require: 'any', allowedSenders: [] }
    expect(isAllowedSender(policy, 'anyone')).toBe(true)
  })
})
