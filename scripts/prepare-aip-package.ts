import { mkdir, readFile, writeFile, copyFile, readdir } from 'node:fs/promises'
import process from 'node:process'

interface RootPackageJson {
  version?: string
}

function parseVersionArg(argv: string[]): string | undefined {
  const idx = argv.indexOf('--version')
  if (idx < 0) return undefined
  return argv[idx + 1]
}

async function readRootVersion(): Promise<string> {
  const raw = await readFile('package.json', 'utf8')
  const parsed = JSON.parse(raw) as RootPackageJson
  return parsed.version ?? '0.0.0'
}

async function main(): Promise<void> {
  const version = parseVersionArg(process.argv) ?? (await readRootVersion())
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

  const packageJson = {
    name: '@7h3/protocol',
    version,
    description: '7h3 Protocol: deterministic, signed, replay-safe AI-to-AI message envelopes (wire 7h3/0.1).',
    type: 'module',
    main: './index.js',
    types: './index.d.ts',
    exports: {
      '.': {
        import: './index.js',
        types: './index.d.ts',
      },
    },
    files: ['index.js', '*.d.ts', 'README.md'],
    license: 'MIT',
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

  console.log(`Prepared publishable package in ${outDir}`)
  console.log(`Version: ${version}`)
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  console.error(message)
  process.exitCode = 1
})
