export interface RuntimePolicy {
  version: string
  name: string
  status: string
  owner?: string
  updated_at?: string
  hard_invariants?: Record<string, unknown>
  slo_defaults?: Record<string, unknown>
  mode_selection?: Record<string, unknown>
  guardrails?: Record<string, unknown>
  tuning?: Record<string, unknown>
  adaptive_flow?: Record<string, unknown>
  benchmark_policy?: Record<string, unknown>
  runtime_decision_tree?: unknown[]
  operator_handoff_required_fields?: string[]
  [key: string]: unknown
}

export interface LoadRuntimePolicyOptions {
  path?: string
  readTextFile?: (filePath: string) => Promise<string>
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`Invalid runtime policy: '${field}' must be a non-empty string`)
  }
  return value
}

export function validateRuntimePolicy(value: unknown): RuntimePolicy {
  if (!isRecord(value)) {
    throw new Error('Invalid runtime policy: root must be an object')
  }

  const version = asNonEmptyString(value.version, 'version')
  const name = asNonEmptyString(value.name, 'name')
  const status = asNonEmptyString(value.status, 'status')

  return {
    ...value,
    version,
    name,
    status,
  }
}

export function parseRuntimePolicyJson(jsonText: string): RuntimePolicy {
  let parsed: unknown
  try {
    parsed = JSON.parse(jsonText)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`Invalid runtime policy JSON: ${message}`, { cause: error })
  }
  return validateRuntimePolicy(parsed)
}

async function defaultReadTextFile(filePath: string): Promise<string> {
  if (typeof fetch === 'function') {
    const response = await fetch(filePath)
    if (!response.ok) {
      throw new Error(`Failed to fetch runtime policy at '${filePath}': ${response.status} ${response.statusText}`)
    }
    return response.text()
  }
  throw new Error(
    "No default runtime file reader available in this environment. Provide 'readTextFile' in loadRuntimePolicy(options).",
  )
}

export async function loadRuntimePolicy(options: LoadRuntimePolicyOptions = {}): Promise<RuntimePolicy> {
  const filePath = options.path ?? 'AI_RUNTIME_POLICY.json'
  const readTextFile = options.readTextFile ?? defaultReadTextFile
  const text = await readTextFile(filePath)
  return parseRuntimePolicyJson(text)
}
