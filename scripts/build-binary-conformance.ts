import { mkdir, writeFile } from 'node:fs/promises'
import { signEnvelopeEd25519, signEnvelopeHmac } from '../src/protocol'
import { encodeEnvelopeBinary } from '../src/protocolBinary'
import { AIP_V01_CONFORMANCE_VECTORS, AIP_V01_ED25519_CONFORMANCE_VECTORS } from '../src/conformanceVectors'

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function run(): Promise<void> {
  const hmac = await Promise.all(
    AIP_V01_CONFORMANCE_VECTORS.map(async (vector) => {
      const signed = await signEnvelopeHmac(vector.envelope, vector.secret, vector.keyId)
      return { id: vector.id, alg: 'HS256', binaryHex: toHex(encodeEnvelopeBinary(signed)) }
    }),
  )
  const ed25519 = await Promise.all(
    AIP_V01_ED25519_CONFORMANCE_VECTORS.map(async (vector) => {
      const signed = await signEnvelopeEd25519(vector.envelope, vector.privateKey, vector.keyId)
      return { id: vector.id, alg: 'ED25519', binaryHex: toHex(encodeEnvelopeBinary(signed)) }
    }),
  )

  await mkdir('conformance', { recursive: true })
  await writeFile(
    'conformance/aip_v0_1_binary.json',
    `${JSON.stringify({ generatedAt: new Date().toISOString(), vectors: [...hmac, ...ed25519] }, null, 2)}\n`,
    'utf8',
  )
  console.log('Wrote conformance/aip_v0_1_binary.json')
}

run().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error))
  process.exitCode = 1
})
