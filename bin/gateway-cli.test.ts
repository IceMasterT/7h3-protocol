import { spawn } from 'node:child_process'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

// Spawning through `npx tsx ...` adds an extra process layer (npx resolves
// and execs a child), and SIGTERM sent to that outer process doesn't
// reliably propagate to the actual tsx/node grandchild — it can survive the
// test and keep holding its port. Spawning the local tsx binary directly
// keeps this to one process we can actually kill.
const TSX_BIN = path.join(process.cwd(), 'node_modules', '.bin', 'tsx')

function runGatewayCli(args: string[], timeoutMs = 5_000): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
  return new Promise((resolve, reject) => {
    // detached: true puts the child in its own process group, so it (and
    // any grandchild tsx re-execs into) can be killed as a group with
    // `process.kill(-pid, ...)` — killing only the immediate child's PID
    // isn't reliable here since tsx's launcher may not replace its own PID.
    const child = spawn(TSX_BIN, ['bin/7h3.ts', 'gateway', ...args], {
      cwd: process.cwd(),
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    })

    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8') })
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8') })

    const killGroup = () => {
      if (child.pid === undefined) return
      try {
        process.kill(-child.pid, 'SIGKILL')
      } catch {
        // Group already gone, or this platform doesn't support negative-pid group kill.
      }
    }

    const timer = setTimeout(() => {
      // Still running after timeoutMs: treat as "started successfully" and kill it.
      killGroup()
      resolve({ stdout, stderr, exitCode: null })
    }, timeoutMs)

    child.on('exit', (code) => {
      clearTimeout(timer)
      killGroup()
      resolve({ stdout, stderr, exitCode: code })
    })
    child.on('error', reject)
  })
}

describe('7h3 gateway CLI — unverified-passthrough refusal', () => {
  it('refuses to start with no verification flags and no --allow-unverified', async () => {
    const { stderr, exitCode } = await runGatewayCli(['--upstream', 'http://localhost:9', '--port', '0'])
    expect(exitCode).not.toBe(null)
    expect(exitCode).not.toBe(0)
    expect(stderr).toMatch(/refusing to start an unverified passthrough gateway/)
  }, 10_000)

  it('starts when --allow-unverified is passed explicitly', async () => {
    // --port 0: let the OS assign a free ephemeral port, so this can't
    // collide with a port a previous/parallel test run is still using.
    const { stderr, exitCode } = await runGatewayCli(
      ['--upstream', 'http://localhost:9', '--port', '0', '--allow-unverified'],
    )
    // exitCode null means it was still running (and got killed) after the
    // timeout — i.e. it started successfully rather than dying immediately.
    expect(exitCode).toBeNull()
    expect(stderr).toMatch(/gateway listening on port \d+/)
  }, 10_000)

  it('starts when --require ed25519 is passed, without needing --allow-unverified', async () => {
    const { stderr, exitCode } = await runGatewayCli(
      ['--upstream', 'http://localhost:9', '--port', '0', '--require', 'ed25519'],
    )
    expect(exitCode).toBeNull()
    expect(stderr).toMatch(/gateway listening on port \d+/)
  }, 10_000)
})
