import { signCanonicalPayloadHmac, signCanonicalPayloadEd25519 } from '../src/protocol'
import { AIP_V01_CONFORMANCE_VECTORS, AIP_V01_ED25519_CONFORMANCE_VECTORS } from '../src/conformanceVectors'

async function main() {
  console.log('=== HMAC vectors ===')
  for (const v of AIP_V01_CONFORMANCE_VECTORS) {
    const sig = await signCanonicalPayloadHmac(v.canonical, v.secret)
    console.log(`${v.id}: '${sig}'`)
  }

  console.log('\n=== Ed25519 vectors ===')
  for (const v of AIP_V01_ED25519_CONFORMANCE_VECTORS) {
    const sig = await signCanonicalPayloadEd25519(v.canonical, v.privateKey)
    console.log(`${v.id}: '${sig}'`)
  }
}

main().catch(e => { console.error(e); process.exit(1) })
