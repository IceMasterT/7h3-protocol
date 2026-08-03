import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import process from 'node:process'

// Regression guard for the packaging bug where dist/npm-protocol/package.json
// dropped every documented "@7h3/protocol/<subpath>" export and the CLI bin
// entry. This packs the real npm artifact and imports it exactly the way an
// external consumer would — through node_modules, not the repo source tree.
const OUT_DIR = 'dist/npm-protocol'

async function main(): Promise<void> {
  const rootPkg = JSON.parse(await readFile(`${OUT_DIR}/package.json`, 'utf8')) as {
    exports: Record<string, unknown>
    bin?: Record<string, string>
  }
  const subpaths = Object.keys(rootPkg.exports).filter((p) => p !== '.')

  const workDir = await mkdtemp(join(tmpdir(), '7h3-pack-smoke-'))
  try {
    const tarballName = execFileSync(
      'npm',
      ['pack', '--silent', `--pack-destination=${workDir}`, resolve(OUT_DIR)],
      { cwd: workDir, encoding: 'utf8' },
    ).trim()

    execFileSync('npm', ['init', '-y'], { cwd: workDir, stdio: 'ignore' })
    execFileSync('npm', ['install', '--no-audit', '--no-fund', join(workDir, tarballName)], {
      cwd: workDir,
      stdio: 'inherit',
    })

    for (const subpath of ['.', ...subpaths]) {
      const specifier = subpath === '.' ? '@7h3/protocol' : `@7h3/protocol${subpath.slice(1)}`
      execFileSync('node', ['-e', `import('${specifier}').then(() => console.log('ok: ${specifier}'))`], {
        cwd: workDir,
        stdio: 'inherit',
      })
    }

    if (rootPkg.bin) {
      execFileSync('npx', ['7h3', 'help'], { cwd: workDir, stdio: 'inherit' })
      execFileSync('npx', ['7h3', 'keygen'], { cwd: workDir, stdio: 'inherit' })
      console.log('ok: CLI bin (7h3 help / keygen)')
    }

    console.log(`\nPackage smoke test passed: ${subpaths.length + 1} import path(s) resolved.`)
  } finally {
    await rm(workDir, { recursive: true, force: true })
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
