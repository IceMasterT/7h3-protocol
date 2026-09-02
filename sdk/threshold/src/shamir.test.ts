import { describe, expect, it } from 'vitest'
import { generateEd25519KeypairBase64Url } from '@7h3/protocol'
import { generateBlsKeyPair, reconstructPrivateKey, splitPrivateKey } from './index'

describe('splitPrivateKey — fails closed rather than corrupting', () => {
  it('round-trips a real BLS key', () => {
    const { privateKey } = generateBlsKeyPair()
    const shares = splitPrivateKey(privateKey, 2, 3)
    expect(shares).toHaveLength(3)
    expect(reconstructPrivateKey(shares.slice(0, 2), 2)).toBe(privateKey)
    expect(reconstructPrivateKey(shares.slice(1, 3), 2)).toBe(privateKey)
  })

  it('rejects an Ed25519 PKCS8 key instead of silently reconstructing a different one', async () => {
    // 48 bytes. Previously this split and "reconstructed" into an unrelated
    // 32-byte key with no error — data loss that only surfaces when the backup
    // is finally needed.
    const { privateKey } = await generateEd25519KeypairBase64Url()
    expect(() => splitPrivateKey(privateKey, 2, 3)).toThrow(/32-byte BLS private key/)
  })

  it('rejects any key that is not exactly 32 bytes', () => {
    const short = Buffer.alloc(16).toString('base64url')
    const long = Buffer.alloc(64).toString('base64url')
    expect(() => splitPrivateKey(short, 2, 3)).toThrow(/32-byte/)
    expect(() => splitPrivateKey(long, 2, 3)).toThrow(/32-byte/)
  })

  it('rejects a 32-byte value at or above the field order', () => {
    // Would be reduced by fieldMod and reconstruct to a different value.
    const allFF = Buffer.alloc(32, 0xff).toString('base64url')
    expect(() => splitPrivateKey(allFF, 2, 3)).toThrow(/field order/)
  })

  it('still refuses an impossible threshold', () => {
    const { privateKey } = generateBlsKeyPair()
    expect(() => splitPrivateKey(privateKey, 1, 3)).toThrow(/Invalid threshold/)
    expect(() => splitPrivateKey(privateKey, 4, 3)).toThrow(/Invalid threshold/)
  })
})
