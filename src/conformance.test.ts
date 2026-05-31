import { describe, expect, it } from 'vitest'
import {
  canonicalizeEnvelope,
  signCanonicalPayloadEd25519,
  signCanonicalPayloadHmac,
  signEnvelopeEd25519,
  signEnvelopeHmac,
  verifyCanonicalPayloadEd25519,
  verifyCanonicalPayloadHmac,
  verifyEnvelopeEd25519,
  verifyEnvelopeHmac,
} from './protocol'
import { InMemoryReplayCache } from './protocolReplay'
import { decodeEnvelope, encodeEnvelope, receiveEnvelope } from './protocolTransport'
import { decodeEnvelopeBinary, encodeEnvelopeBinary } from './protocolBinary'
import { AIP_V01_CONFORMANCE_VECTORS, AIP_V01_ED25519_CONFORMANCE_VECTORS } from './conformanceVectors'

describe('AIP v0.1 conformance vectors', () => {
  for (const vector of AIP_V01_CONFORMANCE_VECTORS) {
    it(`${vector.id}: canonicalization and signatures match fixture`, async () => {
      const canonical = canonicalizeEnvelope(vector.envelope)
      expect(canonical).toBe(vector.canonical)

      const signature = await signCanonicalPayloadHmac(canonical, vector.secret)
      expect(signature).toBe(vector.signature)

      const signed = await signEnvelopeHmac(vector.envelope, vector.secret, vector.keyId)
      expect(signed.signature).toEqual({
        alg: 'HS256',
        keyId: vector.keyId,
        value: vector.signature,
      })

      expect(await verifyCanonicalPayloadHmac(canonical, vector.signature, vector.secret)).toBe(true)
      expect(await verifyEnvelopeHmac(signed, vector.secret)).toBe(true)
      expect(await verifyEnvelopeHmac(signed, `${vector.secret}-wrong`)).toBe(false)
    })

    it(`${vector.id}: transport roundtrip and replay/ttl checks`, async () => {
      const signed = await signEnvelopeHmac(vector.envelope, vector.secret, vector.keyId)
      const encodedCompact = encodeEnvelope(signed, 'compact')
      const decoded = decodeEnvelope(encodedCompact)
      expect(decoded.ok).toBe(true)
      expect(decoded.envelope).toEqual(signed)

      const binary = encodeEnvelopeBinary(signed)
      const decodedBinary = decodeEnvelopeBinary(binary)
      expect(decodedBinary.ok).toBe(true)
      expect(decodedBinary.envelope).toEqual(signed)

      const replayCache = new InMemoryReplayCache()
      const first = await receiveEnvelope(encodedCompact, {
        nowMs: vector.envelope.header.timestampMs + 1,
        replayCache,
        secretResolver: async () => vector.secret,
      })
      expect(first.ok).toBe(true)

      const replay = await receiveEnvelope(encodedCompact, {
        nowMs: vector.envelope.header.timestampMs + 2,
        replayCache,
        secretResolver: async () => vector.secret,
      })
      expect(replay.ok).toBe(false)
      expect(replay.diagnostics.some((d) => d.message.includes('Replay detected'))).toBe(true)

      const expired = await receiveEnvelope(encodedCompact, {
        nowMs: vector.envelope.header.timestampMs + vector.envelope.header.ttlMs + 1,
        replayCache: new InMemoryReplayCache(),
        secretResolver: async () => vector.secret,
      })
      expect(expired.ok).toBe(false)
      expect(expired.diagnostics.some((d) => d.message === 'Message TTL expired')).toBe(true)
    })
  }

  for (const vector of AIP_V01_ED25519_CONFORMANCE_VECTORS) {
    it(`${vector.id}: canonicalization and Ed25519 signatures match fixture`, async () => {
      const canonical = canonicalizeEnvelope(vector.envelope)
      expect(canonical).toBe(vector.canonical)

      const signature = await signCanonicalPayloadEd25519(canonical, vector.privateKey)
      expect(signature).toBe(vector.signature)

      const signed = await signEnvelopeEd25519(vector.envelope, vector.privateKey, vector.keyId)
      expect(signed.signature).toEqual({
        alg: 'ED25519',
        keyId: vector.keyId,
        value: vector.signature,
      })

      expect(await verifyCanonicalPayloadEd25519(canonical, vector.signature, vector.publicKey)).toBe(true)
      expect(await verifyEnvelopeEd25519(signed, vector.publicKey)).toBe(true)

      const tampered = {
        ...signed,
        body: {
          ...signed.body,
          content: `${signed.body.content}:tampered`,
        },
      }
      expect(await verifyEnvelopeEd25519(tampered, vector.publicKey)).toBe(false)
    })

    it(`${vector.id}: transport verify via signatureResolver`, async () => {
      const signed = await signEnvelopeEd25519(vector.envelope, vector.privateKey, vector.keyId)
      const encodedCompact = encodeEnvelope(signed, 'compact')
      const decoded = decodeEnvelope(encodedCompact)
      expect(decoded.ok).toBe(true)
      expect(decoded.envelope).toEqual(signed)

      const binary = encodeEnvelopeBinary(signed)
      const decodedBinary = decodeEnvelopeBinary(binary)
      expect(decodedBinary.ok).toBe(true)
      expect(decodedBinary.envelope).toEqual(signed)

      const first = await receiveEnvelope(encodedCompact, {
        nowMs: vector.envelope.header.timestampMs + 1,
        replayCache: new InMemoryReplayCache(),
        signatureResolver: async (signature, sender) =>
          signature.alg === 'ED25519' && signature.keyId === vector.keyId && sender === vector.envelope.header.sender
            ? { alg: 'ED25519', publicKey: vector.publicKey }
            : undefined,
      })
      expect(first.ok).toBe(true)

      const expired = await receiveEnvelope(encodedCompact, {
        nowMs: vector.envelope.header.timestampMs + vector.envelope.header.ttlMs + 1,
        replayCache: new InMemoryReplayCache(),
        signatureResolver: async () => ({ alg: 'ED25519', publicKey: vector.publicKey }),
      })
      expect(expired.ok).toBe(false)
      expect(expired.diagnostics.some((d) => d.message === 'Message TTL expired')).toBe(true)
    })
  }
})
