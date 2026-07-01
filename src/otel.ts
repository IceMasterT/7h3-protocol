/**
 * otel.ts — Optional OpenTelemetry integration for 7h3 Protocol
 *
 * Pass your @opentelemetry/api Tracer provider via setOtelProvider.
 * No hard dependency — works with any OTel-compatible SDK or without any OTel at all.
 *
 * Duck-typed interfaces: any object matching the shape will work, including
 * the real @opentelemetry/api TracerProvider.
 *
 * Usage:
 *   import { setOtelProvider } from '@7h3/protocol/otel'
 *   import { trace } from '@opentelemetry/api'
 *
 *   setOtelProvider(trace.getTracerProvider())
 *
 * Without OTel configured, withVerificationSpan and withAuditSpan call fn(null)
 * with zero overhead.
 */

// ─── Duck-typed OTel interfaces ───────────────────────────────────────────────

/**
 * A minimal OTel-compatible span interface.
 * Compatible with @opentelemetry/api Span.
 */
export interface OtelSpan {
  setAttribute(key: string, value: string | number | boolean): void
  end(): void
  recordException(error: Error): void
}

/**
 * A minimal OTel-compatible tracer interface.
 * Compatible with @opentelemetry/api Tracer.
 */
export interface OtelTracer {
  startSpan(name: string, attrs?: Record<string, string | number>): OtelSpan
}

/**
 * A minimal OTel-compatible provider interface.
 * Compatible with @opentelemetry/api TracerProvider.
 */
export interface OtelProvider {
  getTracer(name: string): OtelTracer
}

// ─── State ────────────────────────────────────────────────────────────────────

let _provider: OtelProvider | null = null

// ─── Provider management ──────────────────────────────────────────────────────

/**
 * Register an OTel provider. Call once at application startup.
 * Subsequent calls replace the previous provider.
 */
export function setOtelProvider(provider: OtelProvider): void {
  _provider = provider
}

/**
 * Returns the active OTel tracer for '7h3/protocol', or null if no provider
 * has been registered.
 */
export function getOtelTracer(): OtelTracer | null {
  if (_provider === null) return null
  try {
    return _provider.getTracer('7h3/protocol')
  } catch {
    return null
  }
}

// ─── Span helpers ─────────────────────────────────────────────────────────────

/**
 * Creates a span named '7h3.verify' if OTel is configured, calls fn(span),
 * records any exception, and ends the span on completion.
 *
 * If no OTel provider is registered, calls fn(null) directly with zero overhead.
 */
export async function withVerificationSpan<T>(
  fn: (span: OtelSpan | null) => Promise<T>,
  attrs?: Record<string, string | number>,
): Promise<T> {
  const tracer = getOtelTracer()
  if (tracer === null) {
    return fn(null)
  }

  const span = tracer.startSpan('7h3.verify', attrs)
  try {
    const result = await fn(span)
    return result
  } catch (err) {
    if (err instanceof Error) {
      span.recordException(err)
    } else {
      span.recordException(new Error(String(err)))
    }
    throw err
  } finally {
    span.end()
  }
}

/**
 * Creates a span named '7h3.audit.write' if OTel is configured, calls fn(span),
 * records any exception, and ends the span on completion.
 *
 * If no OTel provider is registered, calls fn(null) directly with zero overhead.
 */
export async function withAuditSpan<T>(
  fn: (span: OtelSpan | null) => Promise<T>,
): Promise<T> {
  const tracer = getOtelTracer()
  if (tracer === null) {
    return fn(null)
  }

  const span = tracer.startSpan('7h3.audit.write')
  try {
    const result = await fn(span)
    return result
  } catch (err) {
    if (err instanceof Error) {
      span.recordException(err)
    } else {
      span.recordException(new Error(String(err)))
    }
    throw err
  } finally {
    span.end()
  }
}
