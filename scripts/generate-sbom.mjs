#!/usr/bin/env node
/**
 * Generate CycloneDX 1.5 SBOMs for the npm packages in this repository.
 *
 *   node scripts/generate-sbom.mjs [--out=dist/sbom]
 *
 * One SBOM per package that ships to npm, produced by `npm sbom` from the installed
 * dependency tree (production dependencies only). The script checks what it wrote
 * instead of trusting the tool: each file must be CycloneDX, must describe the package
 * whose directory it came from (its subject is set from that package.json), must list every
 * runtime dependency the package declares, and every component must carry a package URL. It exits non-zero if any package fails.
 *
 * Install each package's dependencies first (`npm ci` in the root and in each package
 * directory; mcp-server also needs `npm run build:protocol`, because it links the root).
 *
 * Not covered: the Python SDK (no runtime dependencies) and the Rust crate (its
 * dependency set is `sdk/rust/Cargo.lock`).
 */

import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const outArg = process.argv.find((a) => a.startsWith('--out='))
const outDir = path.resolve(root, outArg ? outArg.slice(6) : 'dist/sbom')

/** Packages that publish to npm. */
const PACKAGES = ['.', 'sdk/pq', 'sdk/threshold', 'sdk/browser', 'sdk/webmcp', 'mcp-server']

/** Packages that advertise zero runtime dependencies. The SBOM is the independent check on that claim. */
const ZERO_DEPENDENCY = new Set(['.', 'sdk/browser'])

function generate(dir) {
  const cwd = path.join(root, dir)
  const pkg = JSON.parse(readFileSync(path.join(cwd, 'package.json'), 'utf8'))
  const declared = Object.keys(pkg.dependencies ?? {}).sort()

  // A package with runtime dependencies must have them installed, or the SBOM would silently omit them.
  if (declared.length > 0 && !existsSync(path.join(cwd, 'node_modules'))) {
    throw new Error(`${dir}: dependencies are not installed (run npm ci there first)`)
  }

  const raw = execFileSync('npm', ['sbom', '--sbom-format', 'cyclonedx', '--omit', 'dev'], {
    cwd,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const bom = JSON.parse(raw)

  const problems = []
  if (bom.bomFormat !== 'CycloneDX') problems.push('bomFormat is not CycloneDX')
  if (typeof bom.specVersion !== 'string') problems.push('missing specVersion')

  // `npm sbom` names the subject from the lockfile, which can lag package.json (the root came
  // out as its directory name). The SBOM must describe the package it was made for, so set the
  // subject from package.json. Components are left exactly as npm reported them.
  if (!bom.metadata?.component) {
    problems.push('missing metadata.component')
  } else {
    const purl = `pkg:npm/${pkg.name.startsWith('@') ? '%40' + pkg.name.slice(1) : pkg.name}@${pkg.version}`
    bom.metadata.component = { ...bom.metadata.component, 'bom-ref': `${pkg.name}@${pkg.version}`, name: pkg.name, version: pkg.version, purl }
  }

  const components = Array.isArray(bom.components) ? bom.components : []
  for (const c of components) {
    if (!c.purl) problems.push(`component '${c.name}' has no package URL`)
  }
  const listed = new Set(components.map((c) => c.name))
  const listedDeclared = declared.filter((d) => listed.has(d) || listed.has(d.replace(/^@[^/]+\//, '')))
  const missing = declared.filter((d) => !listedDeclared.includes(d))
  // The package's own dependency on the repository root is a link, not a published component.
  const expectedMissing = missing.filter((d) => d !== '@7h3/protocol')
  if (expectedMissing.length > 0) problems.push(`declared dependencies missing from the SBOM: ${expectedMissing.join(', ')}`)

  if (ZERO_DEPENDENCY.has(dir) && components.length > 0) {
    problems.push(`advertises zero runtime dependencies but the SBOM lists ${components.length}: ${components.map((c) => c.name).join(', ')}`)
  }

  if (problems.length > 0) throw new Error(`${dir}: ${problems.join('; ')}`)
  return { pkg, bom, componentCount: components.length }
}

mkdirSync(outDir, { recursive: true })
let failed = 0
for (const dir of PACKAGES) {
  try {
    const { pkg, bom, componentCount } = generate(dir)
    const file = path.join(outDir, `${pkg.name.replace(/^@/, '').replace('/', '-')}-${pkg.version}.cdx.json`)
    writeFileSync(file, JSON.stringify(bom, null, 2) + '\n')
    console.log(`ok   ${dir.padEnd(14)} ${componentCount} component(s) -> ${path.relative(root, file)}`)
  } catch (error) {
    failed++
    console.error(`FAIL ${dir}: ${error instanceof Error ? error.message : String(error)}`)
  }
}
if (failed > 0) process.exit(1)
