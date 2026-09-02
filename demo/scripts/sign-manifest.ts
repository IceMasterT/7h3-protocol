/**
 * Sign the Ledger tool surface at deploy time.
 *
 * Two distinct keys, deliberately:
 *
 *   Origin identity key — long-lived, lives on the deploy machine, never ships
 *     to the browser. Signs the manifest: "these are the tools this origin
 *     publishes." Only its public half is served.
 *
 *   Session key — generated in the browser per visitor. Signs that visitor's
 *     grants and receipts.
 *
 * Conflating them would mean shipping a private key in the bundle, which is
 * exactly the mistake a signing layer should not make.
 *
 * Outputs, both served as static assets:
 *   public/.well-known/7h3-webmcp-manifest.json   the signed manifest
 *   public/.well-known/7h3-keys.json              the origin public key
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateEd25519KeypairBase64Url } from '@7h3/protocol'
import { manifestEntry, signManifest } from '../../sdk/webmcp/src/index'
import { TOOL_DEFS } from '../src/tool-defs'

const here = dirname(fileURLToPath(import.meta.url))
const demoRoot = join(here, '..')
const KEY_PATH = join(demoRoot, '.origin-key.json')
const WELL_KNOWN = join(demoRoot, 'public', '.well-known')

const ORIGIN = '7h3-webmcp-ledger'
const KEY_ID = `${ORIGIN}-origin-k1`

interface Keypair {
  publicKey: string
  privateKey: string
}

/**
 * Load the origin key, creating it on first run.
 *
 * The private half stays in a gitignored file. Regenerating it is harmless for
 * a demo — it changes the published public key alongside the manifest — but a
 * real deployment would keep this in a secret store and rotate deliberately.
 */
async function loadOriginKey(): Promise<Keypair> {
  try {
    return JSON.parse(await readFile(KEY_PATH, 'utf8')) as Keypair
  } catch {
    const keys = await generateEd25519KeypairBase64Url()
    await writeFile(KEY_PATH, JSON.stringify(keys, null, 2))
    console.log(`generated a new origin key at ${KEY_PATH}`)
    return keys
  }
}

async function main(): Promise<void> {
  const keys = await loadOriginKey()
  const entries = await Promise.all(TOOL_DEFS.map(manifestEntry))
  const manifest = await signManifest({
    origin: ORIGIN,
    entries,
    privateKey: keys.privateKey,
    keyId: KEY_ID,
  })

  await mkdir(WELL_KNOWN, { recursive: true })
  await writeFile(join(WELL_KNOWN, '7h3-webmcp-manifest.json'), JSON.stringify(manifest, null, 2))
  await writeFile(
    join(WELL_KNOWN, '7h3-keys.json'),
    JSON.stringify({ keys: [{ keyId: KEY_ID, publicKey: keys.publicKey, algorithm: 'Ed25519' }] }, null, 2),
  )

  const reads = entries.filter((e) => e.method === 'READ').length
  console.log(`signed ${entries.length} tools (${reads} read, ${entries.length - reads} write)`)
  console.log(`surface digest ${manifest.surfaceDigest}`)
}

await main()
