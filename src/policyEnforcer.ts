import { loadRuntimePolicy, type LoadRuntimePolicyOptions, type RuntimePolicy } from './runtimePolicy'

export type RuntimeMode =
  | 'http'
  | 'ws'
  | 'http-binary'
  | 'http-batch'
  | 'http-binary-batch'
  | 'ws-batch'
  | 'ws-binary'
  | 'ws-binary-batch'

export interface ModeSelectionInput {
  concurrency: number
  latencySensitive?: boolean
  compatibilityFirst?: boolean
}

export interface TuningInput {
  trafficClass: 'low' | 'medium' | 'high'
  p99Ms?: number
  dropPct?: number
}

export interface TuningDecision {
  batchSizeRange: [number, number]
  inflightCapRange: [number, number]
  retryBackoffMsRange: [number, number]
  actions: string[]
}

export interface RetryInput {
  error: unknown
  attempt: number
}

export interface InvariantConfig {
  signatureVerification: boolean
  canonicalization: boolean
  replayDefense: boolean
  ttlClockSkewEnforcement: boolean
}

function asNumberPair(value: unknown, label: string): [number, number] {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error(`Invalid policy tuning range '${label}': expected [min,max]`)
  }
  const min = Number(value[0])
  const max = Number(value[1])
  if (!Number.isFinite(min) || !Number.isFinite(max) || min <= 0 || max < min) {
    throw new Error(`Invalid policy tuning range '${label}': expected positive ascending numbers`)
  }
  return [Math.floor(min), Math.floor(max)]
}

function includeHttpLiteral(mode: string): mode is RuntimeMode {
  return (
    mode === 'http' ||
    mode === 'ws' ||
    mode === 'http-binary' ||
    mode === 'http-batch' ||
    mode === 'http-binary-batch' ||
    mode === 'ws-batch' ||
    mode === 'ws-binary' ||
    mode === 'ws-binary-batch'
  )
}

export function createPolicyEnforcer(policy: RuntimePolicy) {
  const dropPctMax = Number((policy.slo_defaults ?? {}).drop_pct_max ?? 0.1)
  const p99MsMax = Number((policy.slo_defaults ?? {}).p99_ms_max ?? 20)
  const maxRetryAttempts = Number((policy.tuning ?? {}).max_retry_attempts ?? 3)
  const retriableStatusCodes = Array.isArray((policy.tuning ?? {}).retriable_status_codes)
    ? ((policy.tuning ?? {}).retriable_status_codes as unknown[])
        .map((value) => Number(value))
        .filter((value) => Number.isFinite(value))
    : [503]

  const tuning = policy.tuning ?? {}
  const batchSize = tuning.batch_size as Record<string, unknown>
  const inflightCap = tuning.inflight_cap as Record<string, unknown>
  const retryBackoff = tuning.retry_backoff_ms as Record<string, unknown>

  const getRanges = (trafficClass: 'low' | 'medium' | 'high') => ({
    batchSizeRange: asNumberPair(batchSize?.[`${trafficClass}_traffic`], `batch_size.${trafficClass}_traffic`),
    inflightCapRange: asNumberPair(inflightCap?.[`${trafficClass}_traffic`], `inflight_cap.${trafficClass}_traffic`),
    retryBackoffMsRange: asNumberPair(retryBackoff?.[`${trafficClass}_traffic`], `retry_backoff_ms.${trafficClass}_traffic`),
  })

  function selectMode(input: ModeSelectionInput): RuntimeMode {
    if (input.concurrency >= 100) return 'http-binary-batch'
    if (input.latencySensitive) return 'ws-batch'
    if (input.compatibilityFirst) return 'http'
    return 'ws-batch'
  }

  function tune(input: TuningInput): TuningDecision {
    const ranges = getRanges(input.trafficClass)
    const actions: string[] = []

    if (typeof input.dropPct === 'number' && input.dropPct > dropPctMax) {
      actions.push('reduce inflight cap')
      actions.push('reduce batch size')
      actions.push('increase retry backoff')
      actions.push('switch to binary-batch mode')
    }
    if (typeof input.p99Ms === 'number' && input.p99Ms > p99MsMax) {
      actions.push('reduce batch size')
      actions.push('reduce inflight cap')
      actions.push('re-run adaptive benchmark')
    }

    return {
      ...ranges,
      actions,
    }
  }

  function shouldRetry(input: RetryInput): boolean {
    if (input.attempt >= maxRetryAttempts) return false
    const message = input.error instanceof Error ? input.error.message : String(input.error)
    const statusFromMessage = /http status\s+(\d+)/i.exec(message)
    const statusCode = statusFromMessage ? Number(statusFromMessage[1]) : NaN
    return Number.isFinite(statusCode) && retriableStatusCodes.includes(statusCode)
  }

  function assertInvariant(config: InvariantConfig): void {
    const failures: string[] = []
    if (!config.signatureVerification) failures.push('signatureVerification=false')
    if (!config.canonicalization) failures.push('canonicalization=false')
    if (!config.replayDefense) failures.push('replayDefense=false')
    if (!config.ttlClockSkewEnforcement) failures.push('ttlClockSkewEnforcement=false')
    if (failures.length > 0) {
      throw new Error(`Invariant violation: ${failures.join(', ')}`)
    }
  }

  return {
    selectMode,
    tune,
    shouldRetry,
    assertInvariant,
    metadata: {
      policyName: policy.name,
      policyVersion: policy.version,
      policyStatus: policy.status,
      enforcedSlo: {
        dropPctMax,
        p99MsMax,
      },
    },
  }
}

export type PolicyEnforcer = ReturnType<typeof createPolicyEnforcer>

export type BootstrapRuntimePolicyEnforcerOptions = LoadRuntimePolicyOptions

export async function bootstrapRuntimePolicyEnforcer(
  options: BootstrapRuntimePolicyEnforcerOptions = {},
): Promise<{ policy: RuntimePolicy; enforcer: PolicyEnforcer }> {
  const policy = await loadRuntimePolicy(options)
  const enforcer = createPolicyEnforcer(policy)
  return { policy, enforcer }
}

export function isRuntimeMode(value: string): value is RuntimeMode {
  return includeHttpLiteral(value)
}
