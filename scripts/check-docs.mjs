#!/usr/bin/env node
/**
 * Sanity checks for the documentation, run in CI.
 *
 * Written after a scripted edit once overwrote README.md with CHANGELOG text and nothing
 * noticed: every later README edit silently did nothing, and tests, lint and typecheck all
 * stayed green because none of them look at documentation.
 *
 *   node scripts/check-docs.mjs
 *
 * Checks:
 *   - README.md opens with the banner block and has its structural headings; CHANGELOG.md
 *     opens with its title; the two files are not the same document;
 *   - every table-of-contents entry in README.md resolves to a heading in it;
 *   - every relative link in README.md, CHANGELOG.md and docs/*.md points at a file that exists.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const problems = []
const read = (rel) => readFileSync(path.join(root, rel), 'utf8')

/** GitHub's heading anchor: lower-case, punctuation dropped, spaces to hyphens. */
function slug(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N} _-]/gu, '')
    .replace(/ /g, '-')
}

function headings(markdown) {
  const out = new Map()
  let fenced = false
  for (const line of markdown.split('\n')) {
    if (/^```/.test(line)) fenced = !fenced
    if (fenced) continue
    const m = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line)
    if (!m) continue
    let s = slug(m[1])
    const n = out.get(s) ?? 0
    out.set(s, n + 1)
    if (n > 0) out.set(`${s}-${n}`, 1) // GitHub numbers duplicates: -1, -2, ...
  }
  return new Set(out.keys())
}

// --- structure ---------------------------------------------------------------
const readme = read('README.md')
const changelog = read('CHANGELOG.md')
if (!readme.trimStart().startsWith('<div align="center">')) problems.push('README.md does not open with the banner block')
if (/^#\s+Changelog\b/m.test(readme)) problems.push('README.md contains a "# Changelog" title: is it a copy of CHANGELOG.md?')
for (const h of ['## Table of Contents', '## Installation', '## Quick Start', '## License']) {
  if (!readme.includes(`\n${h}\n`)) problems.push(`README.md is missing "${h}"`)
}
if (!changelog.trimStart().startsWith('# Changelog')) problems.push('CHANGELOG.md does not open with "# Changelog"')
if (readme === changelog) problems.push('README.md and CHANGELOG.md are identical')

// --- table of contents ---------------------------------------------------------
const readmeAnchors = headings(readme)
const toc = readme.split('## Table of Contents')[1]?.split('\n---')[0] ?? ''
for (const m of toc.matchAll(/\]\(#([^)]+)\)/g)) {
  if (!readmeAnchors.has(m[1])) problems.push(`README.md table of contents links to #${m[1]}, which is not a heading`)
}

// --- relative links --------------------------------------------------------------
const files = ['README.md', 'CHANGELOG.md', ...readdirSync(path.join(root, 'docs')).filter((f) => f.endsWith('.md')).map((f) => `docs/${f}`)]
for (const rel of files) {
  const text = read(rel)
  const dir = path.dirname(rel)
  let fenced = false
  for (const line of text.split('\n')) {
    if (/^```/.test(line)) fenced = !fenced
    if (fenced) continue
    for (const m of line.matchAll(/\]\(([^)\s]+)\)/g)) {
      const target = m[1]
      if (/^(https?:|mailto:|#|data:)/.test(target)) continue
      const file = decodeURIComponent(target.split('#')[0])
      if (file === '') continue
      const resolved = path.join(root, dir, file)
      if (!existsSync(resolved)) problems.push(`${rel}: link to ${target} points at a file that does not exist`)
    }
  }
}

if (problems.length > 0) {
  console.error(`docs check failed (${problems.length}):`)
  for (const p of problems) console.error(`  - ${p}`)
  process.exit(1)
}
console.log(`docs ok: ${files.length} files, ${readmeAnchors.size} README anchors`)
