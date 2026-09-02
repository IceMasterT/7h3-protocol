/**
 * Pack the real tarball, install it into a scratch project, and import it with
 * plain Node.
 *
 * The unit suite cannot catch what this catches. vitest resolves module
 * specifiers its own way, so a build can pass every test and still be
 * unimportable once installed — @7h3/protocol-webmcp@0.6.0 shipped exactly that
 * way, with ERR_MODULE_NOT_FOUND. Only a real install exercises Node's resolver
 * the way a consumer does.
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const pkgDir = resolve(import.meta.dirname, '..')
const work = mkdtempSync(join(tmpdir(), '7h3-browser-smoke-'))
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: 'pipe' })

try {
  run('npm', ['pack', '--pack-destination', work], pkgDir)
  const tarball = readdirSync(work).find((f) => f.endsWith('.tgz'))
  if (!tarball) throw new Error('npm pack produced no tarball')

  writeFileSync(join(work, 'package.json'), JSON.stringify({ name: 'smoke', private: true, type: 'module' }))
  run('npm', ['install', '--no-audit', '--no-fund', join(work, tarball)], work)

  writeFileSync(
    join(work, 'smoke.mjs'),
    `
    import {
      generateKeypair, createEnvelope, signEnvelope, verifyEnvelope,
      validateEnvelope, isEnvelopeExpired, canonicalizeEnvelope,
      MAX_TTL_MS, MAX_CLOCK_SKEW_MS, WIRE_VERSION,
    } from '@7h3/protocol-browser'

    if (WIRE_VERSION !== '7h3/0.1') throw new Error('wire version drifted: ' + WIRE_VERSION)
    if (MAX_TTL_MS !== 86400000 || MAX_CLOCK_SKEW_MS !== 30000) throw new Error('ceilings drifted')

    const { publicKey, privateKey } = await generateKeypair()
    // Note the nested body: this SDK's createEnvelope takes { sender, body },
    // unlike the core's flattened { sender, intent, content }.
    const envelope = createEnvelope({ sender: 'a@b.test', body: { intent: 'TASK', content: 'hello' } })

    const signed = await signEnvelope(envelope, privateKey, 'k1')
    if (await verifyEnvelope(signed, publicKey) !== true) throw new Error('a freshly signed envelope did not verify')

    const tampered = { ...signed, body: { ...signed.body, content: 'MODIFIED' } }
    if (await verifyEnvelope(tampered, publicKey) !== false) throw new Error('tampering was not detected')

    if (validateEnvelope(signed).filter((d) => d.level === 'error').length !== 0) throw new Error('a valid envelope produced errors')

    const postDated = { ...signed, header: { ...signed.header, timestampMs: Date.now() + 31536000000 } }
    if (!validateEnvelope(postDated).some((d) => d.message.includes('in the future'))) throw new Error('post-dated timestamp was accepted')

    const noNonce = { ...signed, header: { ...signed.header, nonce: '' } }
    if (!validateEnvelope(noNonce).some((d) => d.message.includes('Missing nonce'))) throw new Error('missing nonce was accepted')

    const nanTtl = { ...signed, header: { ...signed.header, ttlMs: NaN } }
    if (!isEnvelopeExpired(nanTtl)) throw new Error('a NaN ttl was not treated as expired')

    if (typeof canonicalizeEnvelope({ header: signed.header, body: signed.body }) !== 'string') throw new Error('canonicalize did not return a string')

    console.log('ok: imported from a real install; sign/verify, tamper detection and validation all behave')
    `,
  )

  process.stdout.write(run('node', ['smoke.mjs'], work))
  console.log('Package smoke test passed.')
} finally {
  rmSync(work, { recursive: true, force: true })
}
