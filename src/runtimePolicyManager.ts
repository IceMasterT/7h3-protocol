import { bootstrapRuntimePolicyEnforcer, type BootstrapRuntimePolicyEnforcerOptions, type PolicyEnforcer } from './policyEnforcer'
import type { RuntimePolicy } from './runtimePolicy'

export interface RuntimePolicySnapshot {
  policy: RuntimePolicy
  enforcer: PolicyEnforcer
  loadedAtMs: number
}

export class RuntimePolicyManager {
  private snapshot: RuntimePolicySnapshot | null = null
  private readonly options: BootstrapRuntimePolicyEnforcerOptions

  constructor(options: BootstrapRuntimePolicyEnforcerOptions = {}) {
    this.options = options
  }

  async loadInitial(): Promise<RuntimePolicySnapshot> {
    const loaded = await bootstrapRuntimePolicyEnforcer(this.options)
    this.snapshot = {
      ...loaded,
      loadedAtMs: Date.now(),
    }
    return this.snapshot
  }

  current(): RuntimePolicySnapshot {
    if (!this.snapshot) {
      throw new Error('Runtime policy not loaded. Call loadInitial() first.')
    }
    return this.snapshot
  }

  async refresh(): Promise<RuntimePolicySnapshot> {
    const previous = this.snapshot
    try {
      const loaded = await bootstrapRuntimePolicyEnforcer(this.options)
      this.snapshot = {
        ...loaded,
        loadedAtMs: Date.now(),
      }
      return this.snapshot
    } catch (error) {
      if (previous) {
        return previous
      }
      throw error
    }
  }
}
