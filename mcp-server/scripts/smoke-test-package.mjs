/**
 * Pack the real tarball, install it, and drive the server over stdio with an
 * actual MCP session.
 *
 * Importing the entry point is not enough for a binary: @7h3/protocol-mcp@0.6.1
 * shipped unable to start at all — `tsc` emitted `from './scaffold'`, which
 * Node's ESM resolver rejects — and no unit test noticed, because the suite
 * imports the modules directly rather than launching the built server. This
 * initializes, lists tools, and calls one.
 */

import { spawn, execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const pkgDir = resolve(import.meta.dirname, '..')
const work = mkdtempSync(join(tmpdir(), '7h3-mcp-smoke-'))
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: 'pipe' })

function rpc(child, message) {
  child.stdin.write(JSON.stringify(message) + '\n')
}

try {
  run('npm', ['pack', '--pack-destination', work], pkgDir)
  const tarball = readdirSync(work).find((f) => f.endsWith('.tgz'))
  if (!tarball) throw new Error('npm pack produced no tarball')

  writeFileSync(join(work, 'package.json'), JSON.stringify({ name: 'smoke', private: true }))
  run('npm', ['install', '--no-audit', '--no-fund', join(work, tarball)], work)

  const entry = join(work, 'node_modules', '@7h3', 'protocol-mcp', 'dist', 'index.js')
  const child = spawn('node', [entry], { cwd: work, stdio: ['pipe', 'pipe', 'pipe'] })

  let out = ''
  let err = ''
  child.stdout.on('data', (c) => { out += c.toString() })
  child.stderr.on('data', (c) => { err += c.toString() })

  const done = new Promise((resolveP, rejectP) => {
    child.on('error', rejectP)
    child.on('exit', (code) => rejectP(new Error(`server exited early (code ${code})\n${err}`)))
    setTimeout(() => resolveP(), 6000)
  })

  rpc(child, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
    protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } } })
  rpc(child, { jsonrpc: '2.0', method: 'notifications/initialized' })
  rpc(child, { jsonrpc: '2.0', id: 2, method: 'tools/list' })
  rpc(child, { jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: '7h3_generate_keypair', arguments: {} } })

  await Promise.race([
    done,
    new Promise((r) => {
      const check = setInterval(() => {
        if (out.includes('"id":3')) { clearInterval(check); r() }
      }, 100)
    }),
  ])
  child.kill('SIGTERM')

  const responses = out.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean)
  const byId = (id) => responses.find((r) => r.id === id)

  const init = byId(1)
  if (!init?.result?.serverInfo) throw new Error('initialize did not return serverInfo:\n' + out + err)

  const tools = byId(2)?.result?.tools
  if (!Array.isArray(tools) || tools.length === 0) throw new Error('tools/list returned no tools')
  const names = tools.map((t) => t.name)
  for (const required of ['7h3_generate_keypair', '7h3_sign', '7h3_verify', '7h3_scaffold']) {
    if (!names.includes(required)) throw new Error(`tools/list is missing ${required}`)
  }

  const call = byId(3)
  const text = call?.result?.content?.[0]?.text ?? ''
  if (!text.includes('publicKey') || !text.includes('privateKey')) {
    throw new Error('7h3_generate_keypair did not return a keypair: ' + text.slice(0, 200))
  }

  console.log(`ok: server started, initialized as ${init.result.serverInfo.name}@${init.result.serverInfo.version}, ` +
              `${tools.length} tools listed, 7h3_generate_keypair returned a keypair`)
  console.log('Package smoke test passed.')
} finally {
  rmSync(work, { recursive: true, force: true })
}
