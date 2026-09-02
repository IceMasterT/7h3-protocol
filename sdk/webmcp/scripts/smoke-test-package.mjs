/**
 * Pack the real tarball, install it into a scratch project, and import it with
 * plain Node.
 *
 * This exists because the unit suite cannot catch the failure it guards against.
 * vitest resolves extensionless relative specifiers happily, so `from './guard'`
 * passes every test — and then Node's ESM resolver rejects it at install time
 * with ERR_MODULE_NOT_FOUND. @7h3/protocol-webmcp@0.6.0 shipped exactly that way.
 * Only a real install exercises the resolver the way a consumer does.
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const pkgDir = resolve(import.meta.dirname, '..')
const work = mkdtempSync(join(tmpdir(), '7h3-webmcp-smoke-'))
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
    import { guard, verifyChain, verifyManifest, isWebMcpSupported } from '@7h3/protocol-webmcp'
    import { generateEd25519KeypairBase64Url } from '@7h3/protocol'

    const { publicKey, privateKey } = await generateEd25519KeypairBase64Url()
    const g = guard({ origin: 'smoke.test', privateKey, publicKey })

    let ran = 0
    await g.registerTool({
      name: 'pay', description: 'pay', scope: 'money/pay',
      limit: { field: 'amountCents', max: 50000 },
      execute: async () => { ran++; return { ok: true } },
    })

    const refused = await g.invoke('pay', { amountCents: 100 })
    if (refused.ok !== false || refused.reason !== 'no-active-grant') throw new Error('expected refusal without a grant')

    await g.grant({ subject: 'agent', scopes: ['money/*'], caps: { amountCents: 5000 }, ttlMs: 60000 })
    if ((await g.invoke('pay', { amountCents: 1000 })).ok !== true) throw new Error('expected an in-scope call to be allowed')
    if ((await g.invoke('pay', { amountCents: 40000 })).reason !== 'limit-exceeded') throw new Error('expected the cap to bind')
    if (ran !== 1) throw new Error('handler ran ' + ran + ' times; only the authorized call should execute')

    const chain = await verifyChain(g.receipts.all(), publicKey)
    if (!chain.ok) throw new Error('receipt chain did not verify')

    const manifest = await g.manifest()
    if (!(await verifyManifest(manifest, publicKey)).ok) throw new Error('manifest did not verify')

    if (typeof isWebMcpSupported() !== 'boolean') throw new Error('isWebMcpSupported must return a boolean')

    console.log('ok: imported from a real install, ' + g.receipts.length + ' receipts, chain verified')
    `,
  )

  process.stdout.write(run('node', ['smoke.mjs'], work))
  console.log('Package smoke test passed.')
} finally {
  rmSync(work, { recursive: true, force: true })
}
