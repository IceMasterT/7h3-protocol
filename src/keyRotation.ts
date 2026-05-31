import type { ProtocolEnvelope, SignatureVerificationMaterial } from './protocol'

export type KeyStatus = 'active' | 'verify-only' | 'revoked'

export interface KeyRecord {
  sender: string
  keyId: string
  alg: SignatureVerificationMaterial['alg']
  status: KeyStatus
  notBeforeMs: number
  notAfterMs: number
  material: SignatureVerificationMaterial
}

export class RollingKeyring {
  private readonly records: KeyRecord[]

  constructor(records: KeyRecord[] = []) {
    this.records = [...records]
  }

  add(record: KeyRecord): void {
    this.records.push(record)
  }

  revoke(sender: string, keyId: string, revokedAtMs = Date.now()): boolean {
    const record = this.records.find((entry) => entry.sender === sender && entry.keyId === keyId)
    if (!record) return false
    record.status = 'revoked'
    record.notAfterMs = Math.min(record.notAfterMs, revokedAtMs)
    return true
  }

  selectSigningKey(sender: string, alg: SignatureVerificationMaterial['alg'], nowMs = Date.now()): KeyRecord | null {
    const candidates = this.records
      .filter(
        (entry) =>
          entry.sender === sender &&
          entry.alg === alg &&
          entry.status === 'active' &&
          entry.notBeforeMs <= nowMs &&
          nowMs < entry.notAfterMs,
      )
      .sort((a, b) => b.notBeforeMs - a.notBeforeMs)
    return candidates[0] ?? null
  }

  resolveVerificationMaterial(
    signature: NonNullable<ProtocolEnvelope['signature']>,
    sender: string,
    nowMs = Date.now(),
  ): SignatureVerificationMaterial | undefined {
    const candidates = this.records
      .filter(
        (entry) =>
          entry.sender === sender &&
          entry.keyId === signature.keyId &&
          entry.alg === signature.alg &&
          entry.status !== 'revoked' &&
          entry.notBeforeMs <= nowMs &&
          nowMs < entry.notAfterMs,
      )
      .sort((a, b) => b.notBeforeMs - a.notBeforeMs)

    return candidates[0]?.material
  }
}

export function createKeyringSignatureResolver(keyring: RollingKeyring, nowMsProvider: () => number = () => Date.now()) {
  return async (signature: NonNullable<ProtocolEnvelope['signature']>, sender: string): Promise<SignatureVerificationMaterial | undefined> =>
    keyring.resolveVerificationMaterial(signature, sender, nowMsProvider())
}
