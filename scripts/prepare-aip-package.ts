import { mkdir, readFile, writeFile, copyFile, readdir, access } from 'node:fs/promises'
import process from 'node:process'

interface RootExportEntry {
  types?: string
  import?: string
}

interface RootPackageJson {
  version?: string
  exports?: Record<string, RootExportEntry>
}

function parseVersionArg(argv: string[]): string | undefined {
  const idx = argv.indexOf('--version')
  if (idx < 0) return undefined
  return argv[idx + 1]
}

async function readRootPackageJson(): Promise<RootPackageJson> {
  const raw = await readFile('package.json', 'utf8')
  return JSON.parse(raw) as RootPackageJson
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

// The root package.json's "exports" map is the source of truth for which
// subpaths (@7h3/protocol/gateway, /http, ...) are public API. Every one of
// them resolves ("import" condition) to the single bundled dist/protocol/index.js
// produced by vite.lib.config.ts — there is no per-module JS output — while
// "types" keeps pointing at the per-module .d.ts file so editors/tsc still see
// the narrower per-subpath type surface. The generated publish package must
// mirror this shape exactly, or documented subpath imports 404 after publish.
function buildExportsMap(rootExports: Record<string, RootExportEntry>): Record<string, RootExportEntry> {
  const exportsMap: Record<string, RootExportEntry> = {}
  for (const [subpath, entry] of Object.entries(rootExports)) {
    const typesFile = entry.types ? entry.types.replace('./dist/protocol/', './') : undefined
    exportsMap[subpath] = {
      types: typesFile,
      import: './index.js',
    }
  }
  return exportsMap
}

async function main(): Promise<void> {
  const rootPackageJson = await readRootPackageJson()
  const version = parseVersionArg(process.argv) ?? rootPackageJson.version ?? '0.0.0'
  const outDir = 'dist/npm-protocol'

  await mkdir(outDir, { recursive: true })
  await copyFile('dist/protocol/index.js', `${outDir}/index.js`)

  // Copy all .d.ts files — index.d.ts re-exports from the individual module files,
  // so all of them must be present for TypeScript consumers to resolve types.
  const distFiles = await readdir('dist/protocol')
  for (const file of distFiles) {
    if (file.endsWith('.d.ts')) {
      await copyFile(`dist/protocol/${file}`, `${outDir}/${file}`)
    }
  }

  const files = ['index.js', '*.d.ts', 'README.md', 'LICENSE', 'NOTICE']

  // The CLI binary is optional: scripts/build-cli.ts must have run first
  // (package:protocol wires it in via `npm run build:cli`). Ship it only if
  // present rather than failing the whole package step when it's missing.
  const cliBuilt = await fileExists('bin/7h3.js')
  let bin: Record<string, string> | undefined
  if (cliBuilt) {
    await mkdir(`${outDir}/bin`, { recursive: true })
    await copyFile('bin/7h3.js', `${outDir}/bin/7h3.js`)
    files.push('bin/7h3.js')
    bin = { '7h3': './bin/7h3.js' }
  } else {
    console.warn('bin/7h3.js not found — run `npm run build:cli` first. Publishing without the CLI binary.')
  }

  const packageJson = {
    name: '@7h3/protocol',
    version,
    description: '7h3 Protocol: deterministic, signed, replay-safe AI-to-AI message envelopes (wire 7h3/0.1).',
    type: 'module',
    main: './index.js',
    types: './index.d.ts',
    exports: buildExportsMap(rootPackageJson.exports ?? {}),
    ...(bin ? { bin } : {}),
    files,
    license: 'Apache-2.0',
    repository: {
      type: 'git',
      url: 'https://github.com/IceMasterT/7h3-protocol.git',
    },
  }

  const readme = [
    '# @7h3/protocol',
    '',
    '7h3 Protocol (wire version `7h3/0.1`):',
    'deterministic, signed, replay-safe AI-to-AI message envelopes.',
    '',
    'Install:',
    '',
    '```bash',
    'npm install @7h3/protocol',
    '```',
    '',
    'Import:',
    '',
    '```ts',
    "import { createAipAgentAdapter, receiveEnvelope } from '@7h3/protocol'",
    '```',
    '',
  ].join('\n')

  await writeFile(`${outDir}/package.json`, `${JSON.stringify(packageJson, null, 2)}\n`, 'utf8')
  await writeFile(`${outDir}/README.md`, readme, 'utf8')

  // Apache-2.0 §4(a) and §4(d): the license text and the NOTICE must travel with
  // every distributed copy. outDir is assembled from scratch, so they have to be
  // copied in explicitly or the published tarball carries no license at all.
  await copyFile('LICENSE', `${outDir}/LICENSE`)
  await copyFile('NOTICE', `${outDir}/NOTICE`)

  console.log(`Prepared publishable package in ${outDir}`)
  console.log(`Version: ${version}`)
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
