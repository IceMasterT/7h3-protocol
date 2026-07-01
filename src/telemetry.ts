/**
 * telemetry.ts — Prometheus metrics for 7h3 Protocol
 *
 * Zero runtime dependencies. Plain in-memory counters and histograms rendered
 * to standard Prometheus text exposition format.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TelemetryConfig {
  enabled?: boolean
  prefix?: string // default '7h3'
}

export interface Counter {
  increment(labels?: Record<string, string>): void
  value(labels?: Record<string, string>): number
}

export interface HistogramSnapshot {
  count: number
  sum: number
  buckets: Record<string, number> // upper bound (as string) → cumulative count
}

export interface Histogram {
  observe(value: number, labels?: Record<string, string>): void
  snapshot(labels?: Record<string, string>): HistogramSnapshot
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function labelKey(labels?: Record<string, string>): string {
  if (!labels || Object.keys(labels).length === 0) return '__default__'
  return Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join(',')
}

function renderLabels(labels?: Record<string, string>): string {
  if (!labels || Object.keys(labels).length === 0) return ''
  const parts = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${v}"`)
  return `{${parts.join(',')}}`
}

// ─── SimpleCounter ────────────────────────────────────────────────────────────

export class SimpleCounter implements Counter {
  private counts = new Map<string, number>()
  private labelSets = new Map<string, Record<string, string> | undefined>()

  increment(labels?: Record<string, string>): void {
    const key = labelKey(labels)
    this.counts.set(key, (this.counts.get(key) ?? 0) + 1)
    if (!this.labelSets.has(key)) {
      this.labelSets.set(key, labels)
    }
  }

  value(labels?: Record<string, string>): number {
    return this.counts.get(labelKey(labels)) ?? 0
  }

  entries(): Array<{ labels?: Record<string, string>; value: number }> {
    const result: Array<{ labels?: Record<string, string>; value: number }> = []
    for (const [key, value] of this.counts) {
      result.push({ labels: this.labelSets.get(key), value })
    }
    return result
  }
}

// ─── SimpleHistogram ──────────────────────────────────────────────────────────

interface BucketState {
  count: number
  sum: number
  // bucket upper bounds → cumulative count (populated on snapshot)
  observations: number[]
}

export class SimpleHistogram implements Histogram {
  private bucketBounds: number[]
  private states = new Map<string, BucketState>()
  private labelSets = new Map<string, Record<string, string> | undefined>()

  constructor(buckets: number[] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]) {
    this.bucketBounds = [...buckets].sort((a, b) => a - b)
  }

  observe(value: number, labels?: Record<string, string>): void {
    const key = labelKey(labels)
    if (!this.states.has(key)) {
      this.states.set(key, { count: 0, sum: 0, observations: [] })
      this.labelSets.set(key, labels)
    }
    const state = this.states.get(key)!
    state.count++
    state.sum += value
    state.observations.push(value)
  }

  snapshot(labels?: Record<string, string>): HistogramSnapshot {
    const key = labelKey(labels)
    const state = this.states.get(key) ?? { count: 0, sum: 0, observations: [] }

    const buckets: Record<string, number> = {}
    for (const bound of this.bucketBounds) {
      buckets[String(bound)] = state.observations.filter(v => v <= bound).length
    }
    // +Inf bucket
    buckets['+Inf'] = state.count

    return { count: state.count, sum: state.sum, buckets }
  }

  entries(): Array<{ labels?: Record<string, string>; snapshot: HistogramSnapshot }> {
    const result: Array<{ labels?: Record<string, string>; snapshot: HistogramSnapshot }> = []
    for (const [key] of this.states) {
      const labels = this.labelSets.get(key)
      result.push({ labels, snapshot: this.snapshot(labels) })
    }
    return result
  }

  getBounds(): number[] {
    return [...this.bucketBounds]
  }
}

// ─── Protocol7h3Metrics ───────────────────────────────────────────────────────

export class Protocol7h3Metrics {
  /** labels: result (ok|fail), alg (ED25519|HS256|none), transport (http|ws|grpc|queue|webhook) */
  verifications_total = new SimpleCounter()

  /** buckets in ms */
  verification_duration_ms = new SimpleHistogram([0.1, 0.5, 1, 5, 10, 50, 100])

  /** labels: sender, path */
  rate_limit_hits_total = new SimpleCounter()

  /** labels: sender, path */
  sender_denials_total = new SimpleCounter()

  /** labels: transport */
  replay_detections_total = new SimpleCounter()

  /** labels: type */
  audit_entries_total = new SimpleCounter()

  /** labels: transport — use for WS/gRPC connection tracking */
  active_connections = new SimpleCounter()
}

// ─── Global instance ──────────────────────────────────────────────────────────

export const metrics = new Protocol7h3Metrics()

// ─── Prometheus text format renderer ─────────────────────────────────────────

export function renderPrometheusText(m: Protocol7h3Metrics, prefix = '7h3'): string {
  const lines: string[] = []

  // Helper: emit a counter
  function emitCounter(name: string, help: string, counter: SimpleCounter): void {
    const fullName = `${prefix}_${name}`
    lines.push(`# HELP ${fullName} ${help}`)
    lines.push(`# TYPE ${fullName} counter`)
    const entries = counter.entries()
    if (entries.length === 0) {
      lines.push(`${fullName} 0`)
    } else {
      for (const { labels, value } of entries) {
        if (labels && Object.keys(labels).length > 0) {
          lines.push(`${fullName}${renderLabels(labels)} ${value}`)
        } else {
          lines.push(`${fullName} ${value}`)
        }
      }
    }
  }

  // Helper: emit a histogram
  function emitHistogram(name: string, help: string, histogram: SimpleHistogram): void {
    const fullName = `${prefix}_${name}`
    lines.push(`# HELP ${fullName} ${help}`)
    lines.push(`# TYPE ${fullName} histogram`)
    const entries = histogram.entries()
    if (entries.length === 0) {
      // Emit empty histogram with zero counts
      for (const bound of histogram.getBounds()) {
        lines.push(`${fullName}_bucket{le="${bound}"} 0`)
      }
      lines.push(`${fullName}_bucket{le="+Inf"} 0`)
      lines.push(`${fullName}_sum 0`)
      lines.push(`${fullName}_count 0`)
    } else {
      for (const { labels, snapshot } of entries) {
        const labelStr = labels && Object.keys(labels).length > 0
          ? renderLabels(labels)
          : ''

        for (const [bound, count] of Object.entries(snapshot.buckets)) {
          if (bound === '+Inf') continue
          const bucketLabels = labelStr
            ? labelStr.slice(0, -1) + `,le="${bound}"}`
            : `{le="${bound}"}`
          lines.push(`${fullName}_bucket${bucketLabels} ${count}`)
        }
        // +Inf bucket
        const infLabels = labelStr
          ? labelStr.slice(0, -1) + `,le="+Inf"}`
          : `{le="+Inf"}`
        lines.push(`${fullName}_bucket${infLabels} ${snapshot.count}`)
        lines.push(`${fullName}_sum${labelStr} ${snapshot.sum}`)
        lines.push(`${fullName}_count${labelStr} ${snapshot.count}`)
      }
    }
  }

  emitCounter(
    'verifications_total',
    'Total number of AIP envelope verifications, by result, algorithm, and transport',
    m.verifications_total,
  )

  emitHistogram(
    'verification_duration_ms',
    'Verification latency in milliseconds',
    m.verification_duration_ms,
  )

  emitCounter(
    'rate_limit_hits_total',
    'Total number of rate-limit rejections, by sender and path',
    m.rate_limit_hits_total,
  )

  emitCounter(
    'sender_denials_total',
    'Total number of sender-denied (403) rejections, by sender and path',
    m.sender_denials_total,
  )

  emitCounter(
    'replay_detections_total',
    'Total number of replay-detected events, by transport',
    m.replay_detections_total,
  )

  emitCounter(
    'audit_entries_total',
    'Total number of audit log entries written, by type',
    m.audit_entries_total,
  )

  emitCounter(
    'active_connections',
    'Current active connections, by transport (WS/gRPC)',
    m.active_connections,
  )

  return lines.join('\n') + '\n'
}

// ─── Node.js http-compatible metrics middleware ───────────────────────────────

type NodeReq = { url?: string; method?: string }
type NodeRes = {
  writeHead(status: number, headers: Record<string, string>): void
  end(body: string): void
}
type NextFn = () => void

/**
 * Returns a Node.js http-compatible middleware that serves Prometheus metrics
 * at the given path (default: /metrics).
 */
export function createMetricsMiddleware(
  path = '/metrics',
  m: Protocol7h3Metrics = metrics,
  prefix = '7h3',
): (req: NodeReq, res: NodeRes, next: NextFn) => void {
  return (req, res, next) => {
    if (req.url === path && (req.method === 'GET' || req.method === undefined)) {
      const body = renderPrometheusText(m, prefix)
      res.writeHead(200, {
        'content-type': 'text/plain; version=0.0.4; charset=utf-8',
      })
      res.end(body)
    } else {
      next()
    }
  }
}
