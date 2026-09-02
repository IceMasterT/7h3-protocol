/**
 * Cross-SDK parity between the browser SDK and the core.
 *
 * sdk/browser is a self-contained reimplementation — it shares no code with
 * src/ — so nothing but a test keeps the two in step. The whole premise of the
 * protocol is that an envelope signed anywhere verifies everywhere, and a
 * browser peer must accept exactly what the other SDKs accept.
 *
 * Lives here rather than in sdk/browser so the package keeps zero dependencies
 * on the core.
 */

import { describe, expect, it } from 'vitest'
import {
  canonicalizeEnvelope as coreCanonicalize,
  generateEd25519KeypairBase64Url,
  signEnvelopeEd25519,
  validateEnvelope as coreValidate,
  verifyEnvelopeEd25519,
  MAX_CLOCK_SKEW_MS as CORE_SKEW,
  MAX_TTL_MS as CORE_TTL,
} from './protocol'
import {
  canonicalizeEnvelope as browserCanonicalize,
  generateKeypair as browserGenerateKeypair,
  signEnvelope as browserSign,
  validateEnvelope as browserValidate,
  verifyEnvelope as browserVerify,
  MAX_CLOCK_SKEW_MS as BROWSER_SKEW,
  MAX_TTL_MS as BROWSER_TTL,
} from '../sdk/browser/index'

const now = 1_700_000_000_000
const header = {
  version: '7h3/0.1', messageId: 'msg-1', timestampMs: now, ttlMs: 60_000,
  sender: 'a@b.test', recipient: 'c@d.test', nonce: 'abc123',
}
const body = { intent: 'TASK' as const, content: 'hello' }
const envelope = { header, body }

describe('browser SDK ↔ core parity', () => {
  it('shares the same ceilings', () => {
    expect(BROWSER_TTL).toBe(CORE_TTL)
    expect(BROWSER_SKEW).toBe(CORE_SKEW)
  })

  it('canonicalizes byte-identically', () => {
    expect(browserCanonicalize(envelope as never)).toBe(coreCanonicalize(envelope as never))
  })

  it('canonicalizes byte-identically without an optional recipient', () => {
    const { recipient: _drop, ...rest } = header
    const e = { header: rest, body }
    expect(browserCanonicalize(e as never)).toBe(coreCanonicalize(e as never))
  })

  it('verifies a browser-signed envelope with the core', async () => {
    const kp = await browserGenerateKeypair()
    const signed = await browserSign(envelope as never, kp.privateKey, 'k1')
    expect(await verifyEnvelopeEd25519(signed as never, kp.publicKey)).toBe(true)
  })

  it('verifies a core-signed envelope with the browser SDK', async () => {
    const kp = await generateEd25519KeypairBase64Url()
    const signed = await signEnvelopeEd25519(envelope as never, kp.privateKey, 'k1')
    expect(await browserVerify(signed as never, kp.publicKey)).toBe(true)
  })

  it('agrees on which envelopes are invalid, and why', () => {
    const cases: Record<string, unknown>[] = [
      {},
      { ttlMs: CORE_TTL + 1 },
      { timestampMs: now + 31_536_000_000 },
      { ttlMs: NaN },
      { timestampMs: NaN },
      { ttlMs: Infinity },
      { ttlMs: 0 },
      { nonce: '' },
      { sender: '' },
      { messageId: '' },
      { version: '7h3/9.9' },
      { timestampMs: now - 120_000 },
    ]
    for (const over of cases) {
      const e = { header: { ...header, ...over }, body }
      const core = coreValidate(e as never, now).filter((d) => d.level === 'error').map((d) => d.message).sort()
      const browser = browserValidate(e as never, now).filter((d) => d.level === 'error').map((d) => d.message).sort()
      expect(browser, `mismatch for ${JSON.stringify(over)}`).toEqual(core)
    }
  })
})
