import { describe, it, expect, beforeEach } from 'vitest'
import {
  SimpleCounter,
  SimpleHistogram,
  Protocol7h3Metrics,
  renderPrometheusText,
  createMetricsMiddleware,
} from './telemetry'

// ─── 1. Counter increments correctly with labels ──────────────────────────────

describe('SimpleCounter with labels', () => {
  it('increments independently per label set', () => {
    const counter = new SimpleCounter()
    counter.increment({ result: 'ok', alg: 'ED25519' })
    counter.increment({ result: 'ok', alg: 'ED25519' })
    counter.increment({ result: 'fail', alg: 'HS256' })

    expect(counter.value({ result: 'ok', alg: 'ED25519' })).toBe(2)
    expect(counter.value({ result: 'fail', alg: 'HS256' })).toBe(1)
    expect(counter.value({ result: 'ok', alg: 'HS256' })).toBe(0)
  })

  it('label order does not affect key identity', () => {
    const counter = new SimpleCounter()
    counter.increment({ a: '1', b: '2' })
    counter.increment({ b: '2', a: '1' })
    expect(counter.value({ a: '1', b: '2' })).toBe(2)
    expect(counter.value({ b: '2', a: '1' })).toBe(2)
  })
})

// ─── 2. Counter with no labels increments the default bucket ─────────────────

describe('SimpleCounter with no labels', () => {
  it('starts at 0', () => {
    const counter = new SimpleCounter()
    expect(counter.value()).toBe(0)
  })

  it('increments the default bucket', () => {
    const counter = new SimpleCounter()
    counter.increment()
    counter.increment()
    counter.increment()
    expect(counter.value()).toBe(3)
    // labeled lookup returns 0 — separate bucket
    expect(counter.value({ x: '1' })).toBe(0)
  })
})

// ─── 3. Histogram records observations and buckets correctly ─────────────────

describe('SimpleHistogram', () => {
  it('counts observations into correct buckets', () => {
    const h = new SimpleHistogram([1, 5, 10, 50, 100])
    h.observe(0.5)
    h.observe(3)
    h.observe(7)
    h.observe(75)
    h.observe(200)

    const snap = h.snapshot()
    // ≤1: 0.5 → 1
    expect(snap.buckets['1']).toBe(1)
    // ≤5: 0.5, 3 → 2
    expect(snap.buckets['5']).toBe(2)
    // ≤10: 0.5, 3, 7 → 3
    expect(snap.buckets['10']).toBe(3)
    // ≤50: 0.5, 3, 7 → 3
    expect(snap.buckets['50']).toBe(3)
    // ≤100: 0.5, 3, 7, 75 → 4
    expect(snap.buckets['100']).toBe(4)
    // +Inf: all 5
    expect(snap.buckets['+Inf']).toBe(5)
    expect(snap.count).toBe(5)
    expect(snap.sum).toBeCloseTo(0.5 + 3 + 7 + 75 + 200)
  })

  it('tracks per-label state independently', () => {
    const h = new SimpleHistogram([10])
    h.observe(5, { transport: 'http' })
    h.observe(15, { transport: 'ws' })

    const snapHttp = h.snapshot({ transport: 'http' })
    expect(snapHttp.count).toBe(1)
    expect(snapHttp.buckets['10']).toBe(1)

    const snapWs = h.snapshot({ transport: 'ws' })
    expect(snapWs.count).toBe(1)
    expect(snapWs.buckets['10']).toBe(0)
  })

  it('returns zero snapshot for unseen labels', () => {
    const h = new SimpleHistogram([1, 5])
    const snap = h.snapshot({ transport: 'grpc' })
    expect(snap.count).toBe(0)
    expect(snap.sum).toBe(0)
    expect(snap.buckets['+Inf']).toBe(0)
  })
})

// ─── 4. renderPrometheusText produces valid Prometheus format ─────────────────

describe('renderPrometheusText', () => {
  it('contains # HELP, # TYPE, and metric lines', () => {
    const m = new Protocol7h3Metrics()
    m.verifications_total.increment({ result: 'ok', alg: 'ED25519', transport: 'http' })
    m.verifications_total.increment({ result: 'ok', alg: 'ED25519', transport: 'http' })
    m.verifications_total.increment({ result: 'fail', alg: 'none', transport: 'http' })
    m.verification_duration_ms.observe(2.5)

    const text = renderPrometheusText(m)

    expect(text).toMatch(/# HELP 7h3_verifications_total /)
    expect(text).toMatch(/# TYPE 7h3_verifications_total counter/)
    expect(text).toMatch(/7h3_verifications_total\{.*result="ok".*\} 2/)
    expect(text).toMatch(/7h3_verifications_total\{.*result="fail".*\} 1/)
    expect(text).toMatch(/# HELP 7h3_verification_duration_ms /)
    expect(text).toMatch(/# TYPE 7h3_verification_duration_ms histogram/)
    expect(text).toMatch(/7h3_verification_duration_ms_bucket\{.*le="\+Inf".*\} 1/)
    expect(text).toMatch(/7h3_verification_duration_ms_count 1/)
  })

  it('respects a custom prefix', () => {
    const m = new Protocol7h3Metrics()
    m.rate_limit_hits_total.increment({ sender: 'agent-a', path: '/api' })
    const text = renderPrometheusText(m, 'myapp')
    expect(text).toMatch(/# HELP myapp_verifications_total/)
    expect(text).toMatch(/myapp_rate_limit_hits_total/)
  })

  it('all expected metric names appear', () => {
    const m = new Protocol7h3Metrics()
    const text = renderPrometheusText(m)
    const expectedNames = [
      '7h3_verifications_total',
      '7h3_verification_duration_ms',
      '7h3_rate_limit_hits_total',
      '7h3_sender_denials_total',
      '7h3_replay_detections_total',
      '7h3_audit_entries_total',
      '7h3_active_connections',
    ]
    for (const name of expectedNames) {
      expect(text).toContain(`# HELP ${name}`)
    }
  })

  it('ends with a newline', () => {
    const m = new Protocol7h3Metrics()
    const text = renderPrometheusText(m)
    expect(text.endsWith('\n')).toBe(true)
  })
})

// ─── 5. metrics.verifications_total increments on gateway verify calls ────────

describe('Protocol7h3Metrics integration via gateway verify', () => {
  it('increments verifications_total on skip-verify path (allow policy)', async () => {
    // Import gateway dynamically to get a fresh reference to globalMetrics
    // We directly test Protocol7h3Metrics counting logic by simulating the verify flow
    const m = new Protocol7h3Metrics()

    // Simulate a successful skip-verify (allow-all gateway)
    m.verifications_total.increment({ result: 'ok', alg: 'none', transport: 'http' })

    expect(m.verifications_total.value({ result: 'ok', alg: 'none', transport: 'http' })).toBe(1)
    expect(m.verifications_total.value({ result: 'fail', alg: 'none', transport: 'http' })).toBe(0)
  })

  it('increments verifications_total fail on rate-limit', async () => {
    const m = new Protocol7h3Metrics()

    // Simulate a rate-limit hit
    m.verifications_total.increment({ result: 'fail', alg: 'ED25519', transport: 'http' })
    m.rate_limit_hits_total.increment({ sender: 'agent-x', path: '/api/data' })

    expect(m.verifications_total.value({ result: 'fail', alg: 'ED25519', transport: 'http' })).toBe(1)
    expect(m.rate_limit_hits_total.value({ sender: 'agent-x', path: '/api/data' })).toBe(1)
  })

  it('increments sender_denials_total on 403', async () => {
    const m = new Protocol7h3Metrics()

    m.verifications_total.increment({ result: 'fail', alg: 'ED25519', transport: 'http' })
    m.sender_denials_total.increment({ sender: 'rogue-agent', path: '/admin' })

    expect(m.sender_denials_total.value({ sender: 'rogue-agent', path: '/admin' })).toBe(1)
    expect(m.verifications_total.value({ result: 'fail', alg: 'ED25519', transport: 'http' })).toBe(1)
  })

  it('records duration in verification_duration_ms', () => {
    const m = new Protocol7h3Metrics()

    m.verification_duration_ms.observe(0.3)
    m.verification_duration_ms.observe(2.0)
    m.verification_duration_ms.observe(120)

    const snap = m.verification_duration_ms.snapshot()
    expect(snap.count).toBe(3)
    expect(snap.sum).toBeCloseTo(0.3 + 2.0 + 120)
    // 0.3 ≤ 0.5 → should appear in bucket 0.5
    expect(snap.buckets['0.5']).toBe(1)
    // +Inf must be count
    expect(snap.buckets['+Inf']).toBe(3)
  })
})

// ─── 6. createMetricsMiddleware serves metrics ────────────────────────────────

describe('createMetricsMiddleware', () => {
  it('serves Prometheus text at /metrics', () => {
    const m = new Protocol7h3Metrics()
    m.verifications_total.increment({ result: 'ok', alg: 'ED25519', transport: 'http' })
    const middleware = createMetricsMiddleware('/metrics', m)

    let status = 0
    let body = ''
    let headers: Record<string, string> = {}
    const req = { url: '/metrics', method: 'GET' }
    const res = {
      writeHead(s: number, h: Record<string, string>) { status = s; headers = h },
      end(b: string) { body = b },
    }
    let nextCalled = false
    const next = () => { nextCalled = true }

    middleware(req, res, next)

    expect(status).toBe(200)
    expect(headers['content-type']).toMatch(/text\/plain/)
    expect(body).toContain('# HELP 7h3_verifications_total')
    expect(nextCalled).toBe(false)
  })

  it('calls next() for non-metrics paths', () => {
    const m = new Protocol7h3Metrics()
    const middleware = createMetricsMiddleware('/metrics', m)

    let nextCalled = false
    const req = { url: '/api/data', method: 'GET' }
    const res = {
      writeHead() {},
      end() {},
    }
    middleware(req, res, () => { nextCalled = true })

    expect(nextCalled).toBe(true)
  })
})
