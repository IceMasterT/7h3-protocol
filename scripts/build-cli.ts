import { execFileSync } from 'node:child_process'
import { copyFile, rm } from 'node:fs/promises'

// tsc refuses to emit into a directory that is also one of its own include
// roots (outDir === rootDir triggers "no inputs found"), so we compile into a
// scratch directory and move the single output file into place.
const SCRATCH_DIR = '.bin-build'

async function main(): Promise<void> {
  execFileSync('npx', ['tsc', '-p', 'tsconfig.bin.json'], { stdio: 'inherit' })
  await copyFile(`${SCRATCH_DIR}/7h3.js`, 'bin/7h3.js')
  await rm(SCRATCH_DIR, { recursive: true, force: true })
  console.log('Compiled bin/7h3.ts -> bin/7h3.js')
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
