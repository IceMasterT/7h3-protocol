/**
 * Property-based fuzz tests using fast-check.
 *
 * Area 1: Wire decoder resilience — decodeEnvelope must never throw on arbitrary
 *         string or Uint8Array input; it must always return {ok: false} on garbage.
 *
 * Area 2: Canonicalization determinism — canonicalizeEnvelope must be pure and
 *         stable: calling it twice on the same envelope returns the same string,
 *         and reordering the object's fields has no effect.
 *
 * Area 3: Replay cache idempotency — for any (sender, messageId, nonce) triple
 *         the first consume() is ok:true and a second is ok:false, provided the
 *         key is unique in the cache. Key collision via the "|" separator is
 *         handled explicitly (see comment below).
 */

import * as fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { canonicalizeEnvelope } from './protocol'
import type { ProtocolBody, ProtocolHeader } from './protocol'
import { InMemoryReplayCache } from './protocolReplay'
import { decodeEnvelope } from './protocolTransport'

// ---------------------------------------------------------------------------
// Area 1 — Wire decoder resilience
// ---------------------------------------------------------------------------

describe('decodeEnvelope resilience (property-based)', () => {
  it('never throws on arbitrary string input — always returns {ok}', () => {
    fc.assert(
      fc.property(fc.string(), (raw) => {
        let result: ReturnType<typeof decodeEnvelope>
        expect(() => {
          result = decodeEnvelope(raw)
        }).not.toThrow()
        // Must have an `ok` boolean — when the string is garbage it will be false.
        expect(typeof result!.ok).toBe('boolean')
      }),
    )
  })

  it('never throws on arbitrary Uint8Array input — always returns {ok}', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 512 }), (bytes) => {
        let result: ReturnType<typeof decodeEnvelope>
        expect(() => {
          result = decodeEnvelope(bytes)
        }).not.toThrow()
        expect(typeof result!.ok).toBe('boolean')
      }),
    )
  })

  it('returns ok:false (not throws) for partial JSON strings', () => {
    // Strings that begin like JSON but are truncated or malformed.
    fc.assert(
      fc.property(
        fc.oneof(
          // Truncated JSON
          fc.string({ maxLength: 20 }).map((s) => '{' + s),
          // Random non-JSON
          fc.string({ minLength: 1, maxLength: 64 }).filter((s) => {
            try {
              JSON.parse(s)
              return false
            } catch {
              return true
            }
          }),
        ),
        (raw) => {
          const result = decodeEnvelope(raw)
          expect(result.ok).toBe(false)
        },
      ),
    )
  })
})

// ---------------------------------------------------------------------------
// Area 2 — Canonicalization determinism
// ---------------------------------------------------------------------------

/** Arbitraries for the valid types in headers and bodies. */
const intentKindArb = fc.constantFrom(
  'PING' as const,
  'PONG' as const,
  'CAPS' as const,
  'TASK' as const,
  'RESULT' as const,
  'ERROR' as const,
)

const headerArb: fc.Arbitrary<ProtocolHeader> = fc.record({
  version: fc.constant('aip/0.1' as const),
  messageId: fc.string({ minLength: 1, maxLength: 64 }),
  timestampMs: fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
  ttlMs: fc.integer({ min: 1, max: 86_400_000 }),
  sender: fc.string({ minLength: 1, maxLength: 64 }),
  nonce: fc.string({ minLength: 1, maxLength: 32 }),
  // recipient is optional — generate it or leave it undefined
  recipient: fc.option(fc.string({ minLength: 1, maxLength: 64 }), { nil: undefined }),
})

const bodyArb: fc.Arbitrary<ProtocolBody> = fc.record({
  intent: intentKindArb,
  content: fc.string({ maxLength: 256 }),
  capability: fc.option(fc.string({ minLength: 1, maxLength: 64 }), { nil: undefined }),
  correlationId: fc.option(fc.string({ minLength: 1, maxLength: 64 }), { nil: undefined }),
})

describe('canonicalizeEnvelope determinism (property-based)', () => {
  it('returns the same string when called twice on the same envelope', () => {
    fc.assert(
      fc.property(headerArb, bodyArb, (header, body) => {
        const envelope = { header, body }
        expect(canonicalizeEnvelope(envelope)).toBe(canonicalizeEnvelope(envelope))
      }),
    )
  })

  it('is not affected by key insertion order in the header object', () => {
    fc.assert(
      fc.property(headerArb, bodyArb, (header, body) => {
        // Build a structurally identical header whose keys are inserted in reverse
        // order to the one produced by headerArb.
        const reversedHeader: ProtocolHeader = Object.fromEntries(
          Object.entries(header).reverse(),
        ) as unknown as ProtocolHeader

        const canonical = canonicalizeEnvelope({ header, body })
        const canonicalReversed = canonicalizeEnvelope({ header: reversedHeader, body })
        expect(canonical).toBe(canonicalReversed)
      }),
    )
  })

  it('is not affected by key insertion order in the body object', () => {
    fc.assert(
      fc.property(headerArb, bodyArb, (header, body) => {
        const reversedBody: ProtocolBody = Object.fromEntries(
          Object.entries(body).reverse(),
        ) as unknown as ProtocolBody

        const canonical = canonicalizeEnvelope({ header, body })
        const canonicalReversed = canonicalizeEnvelope({ header, body: reversedBody })
        expect(canonical).toBe(canonicalReversed)
      }),
    )
  })
})

// ---------------------------------------------------------------------------
// Area 3 — Replay cache properties
// ---------------------------------------------------------------------------

/**
 * The InMemoryReplayCache key is built as `${sender}|${messageId}|${nonce}`.
 * Because the separator is unescaped, two distinct (sender, messageId, nonce)
 * triples can map to the same cache key — e.g. ("a|b", "c", "d") and
 * ("a", "b|c", "d") both yield "a|b|c|d".  We track seen keys ourselves
 * using the same join rule so our assertions match what the cache actually does.
 */
function replayCacheKey(sender: string, messageId: string, nonce: string): string {
  return `${sender}|${messageId}|${nonce}`
}

const tripleArb = fc.record({
  sender: fc.string({ maxLength: 32 }),
  messageId: fc.string({ maxLength: 32 }),
  nonce: fc.string({ maxLength: 32 }),
})

/** Build a minimal ProtocolEnvelope skeleton sufficient for InMemoryReplayCache.consume(). */
function makeEnvelope(sender: string, messageId: string, nonce: string, nowMs: number) {
  return {
    header: {
      version: 'aip/0.1' as const,
      sender,
      messageId,
      nonce,
      timestampMs: nowMs,
      ttlMs: 600_000, // 10 min — ensures entry lives well past both consume() calls
      recipient: undefined,
    },
    body: {
      intent: 'PING' as const,
      content: '',
    },
  }
}

describe('InMemoryReplayCache properties (property-based)', () => {
  it('first consume() ok:true, second consume() ok:false for any unique triple', () => {
    fc.assert(
      fc.property(tripleArb, ({ sender, messageId, nonce }) => {
        const cache = new InMemoryReplayCache()
        const nowMs = 1_700_000_000_000
        const envelope = makeEnvelope(sender, messageId, nonce, nowMs)

        const first = cache.consume(envelope, nowMs)
        expect(first.ok).toBe(true)

        const second = cache.consume(envelope, nowMs)
        expect(second.ok).toBe(false)
      }),
    )
  })

  it('for a sequence of triples: first reserve for a key is ok:true, repeat is ok:false', () => {
    fc.assert(
      fc.property(fc.array(tripleArb, { minLength: 1, maxLength: 20 }), (triples) => {
        const cache = new InMemoryReplayCache()
        const nowMs = 1_700_000_000_000
        // Track which keys the cache has already seen (mirrors makeKey internals).
        const seenKeys = new Set<string>()

        for (const { sender, messageId, nonce } of triples) {
          const key = replayCacheKey(sender, messageId, nonce)
          const envelope = makeEnvelope(sender, messageId, nonce, nowMs)
          const result = cache.consume(envelope, nowMs)

          if (seenKeys.has(key)) {
            // Cache already has this key — must be rejected as replay.
            expect(result.ok).toBe(false)
          } else {
            // First time this key is presented — must be accepted.
            expect(result.ok).toBe(true)
            seenKeys.add(key)
          }
        }
      }),
    )
  })
})
