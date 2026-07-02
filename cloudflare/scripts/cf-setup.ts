#!/usr/bin/env tsx
/**
 * cf-setup.ts — Cloudflare Gateway first-time setup
 *
 * Automates:
 *   1. Generate Ed25519 keypair
 *   2. Create two KV namespaces (KEY_REGISTRY + REPLAY_STORE)
 *   3. Patch wrangler.toml with the namespace IDs
 *   4. Write GATEWAY_PRIVATE_KEY to wrangler secret
 *   5. Print the public key for peer registration
 *
 * Run from cloudflare/:
 *   npx tsx scripts/cf-setup.ts [--env staging|production]
 */

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const deployEnv = process.argv.includes('--env')
  ? process.argv[process.argv.indexOf('--env') + 1]
  : undefined

const cwd = join(import.meta.dirname, '..')
const tomlPath = join(cwd, 'wrangler.toml')

// Run a binary with an explicit argument array — no shell, no injection risk
function runBin(bin: string, args: string[], input?: string): string {
  return execFileSync(bin, args, {
    cwd,
    encoding: 'utf8',
    input,            // passed as stdin when set (replaces the echo | pipe pattern)
  }).trim()
}

function wrangler(args: string[], input?: string): string {
  return runBin('wrangler', args, input)
}

console.log('\n7h3 Protocol — Cloudflare Gateway Setup\n')

// 1. Generate keypair using the 7h3 CLI
console.log('Step 1/5 — Generating Ed25519 keypair…')
const keyJson = runBin('node', [
  '../node_modules/.bin/tsx',
  '../bin/7h3.ts',
  'keygen',
  '--json',
])
const { publicKey, privateKey } = JSON.parse(keyJson) as { publicKey: string; privateKey: string }
console.log(`  Public key: ${publicKey.slice(0, 32)}…`)

// 2. Create KV namespaces
console.log('\nStep 2/5 — Creating KV namespaces…')
const keyNs         = JSON.parse(wrangler(['kv:namespace', 'create', 'KEY_REGISTRY',  '--json']))
const replayNs      = JSON.parse(wrangler(['kv:namespace', 'create', 'REPLAY_STORE',  '--json']))
const keyPreviewNs  = JSON.parse(wrangler(['kv:namespace', 'create', 'KEY_REGISTRY',  '--preview', '--json']))
const replayPreviewNs = JSON.parse(wrangler(['kv:namespace', 'create', 'REPLAY_STORE', '--preview', '--json']))
console.log(`  KEY_REGISTRY id: ${keyNs.id}`)
console.log(`  REPLAY_STORE id: ${replayNs.id}`)

// 3. Patch wrangler.toml — replace placeholder strings with real IDs
console.log('\nStep 3/5 — Patching wrangler.toml…')
let toml = readFileSync(tomlPath, 'utf8')
toml = toml
  .replace('REPLACE_WITH_KEY_REGISTRY_KV_ID',         keyNs.id)
  .replace('REPLACE_WITH_REPLAY_STORE_KV_ID',          replayNs.id)
  .replace('REPLACE_WITH_KEY_REGISTRY_KV_PREVIEW_ID',  keyPreviewNs.id)
  .replace('REPLACE_WITH_REPLAY_STORE_KV_PREVIEW_ID',  replayPreviewNs.id)
writeFileSync(tomlPath, toml)
console.log('  wrangler.toml updated.')

// 4. Store the gateway's own public key in KV
console.log('\nStep 4/5 — Loading gateway public key into KV…')
const sender = 'gateway@7h3.agency'
wrangler(['kv:key', 'put', '--namespace-id', keyNs.id, `7h3:pk:${sender}`, publicKey])
console.log(`  Stored public key for ${sender}`)

// 5. Set private key as a Wrangler secret — pass via stdin, not shell arg
console.log('\nStep 5/5 — Setting GATEWAY_PRIVATE_KEY secret…')
const secretArgs = ['secret', 'put', 'GATEWAY_PRIVATE_KEY']
if (deployEnv) secretArgs.push('--env', deployEnv)
wrangler(secretArgs, privateKey)   // privateKey sent as stdin, never interpolated into a shell string
console.log('  Secret stored.')

console.log(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Setup complete! Next steps:

1. Edit wrangler.toml and set UPSTREAM_URL to your service
2. Register trusted agent public keys:
     wrangler kv:key put --namespace-id "${keyNs.id}" \\
       "7h3:pk:agent@example.com" "<base64url-pubkey>"

3. Deploy:
     npm run deploy:staging    # test first
     npm run deploy:production

4. Share this gateway public key with peers:
     ${publicKey}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`)
