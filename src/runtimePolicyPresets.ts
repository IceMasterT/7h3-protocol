import type { RuntimeMode } from './policyEnforcer'

export type RuntimeEnvironment = 'dev' | 'staging' | 'prod'

export interface RuntimeTuningPreset {
  environment: RuntimeEnvironment
  mode: RuntimeMode
  poolSize: number
  batchSize: number
  inflightCap: number
  retryMaxAttempts: number
}

const PRESETS: Record<RuntimeEnvironment, RuntimeTuningPreset> = {
  dev: {
    environment: 'dev',
    mode: 'ws-batch',
    poolSize: 1,
    batchSize: 8,
    inflightCap: 64,
    retryMaxAttempts: 2,
  },
  staging: {
    environment: 'staging',
    mode: 'http-binary-batch',
    poolSize: 2,
    batchSize: 32,
    inflightCap: 256,
    retryMaxAttempts: 3,
  },
  prod: {
    environment: 'prod',
    mode: 'http-binary-batch',
    poolSize: 4,
    batchSize: 64,
    inflightCap: 1024,
    retryMaxAttempts: 3,
  },
}

export function getRuntimeTuningPreset(environment: RuntimeEnvironment): RuntimeTuningPreset {
  return PRESETS[environment]
}
