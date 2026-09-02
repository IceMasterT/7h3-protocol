import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import ts from 'typescript'
import { buildScaffold } from './scaffold'
import { MCP_PACKAGE_SPEC, MCP_VERSION } from './version'

/** Targets that emit TypeScript/JavaScript source. */
const CODE_FRAMEWORKS = [
  'webmcp',
  'cloudflare-worker',
  'nextjs',
  'express',
  'hono',
  'fastify',
  'raw',
] as const

/**
 * `claude-code` is the odd one out: it emits a JSON settings block wrapped in
 * `//` comments, not source, so it is validated as JSON instead.
 */
const FRAMEWORKS = [...CODE_FRAMEWORKS, 'claude-code'] as const

/** Syntax-only check: several targets emit TypeScript, so node --check won't do. */
function syntaxErrors(code: string): string[] {
  const result = ts.transpileModule(code, {
    reportDiagnostics: true,
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  })
  return (result.diagnostics ?? []).map((d) => ts.flattenDiagnosticMessageText(d.messageText, ' '))
}

/** Drop the leading `//` commentary and parse what remains as JSON. */
function jsonBody(code: string): unknown {
  const body = code
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n')
    .trim()
  return JSON.parse(body)
}

describe('buildScaffold', () => {
  for (const framework of CODE_FRAMEWORKS) {
    it(`emits syntactically valid source for ${framework}`, () => {
      const code = buildScaffold(framework, 'ed25519', 'agent@example.com', 'https://upstream.example.com')
      expect(code.length).toBeGreaterThan(200)
      expect(syntaxErrors(code)).toEqual([])
    })
  }

  it('emits valid source for the hmac signing method too', () => {
    for (const framework of CODE_FRAMEWORKS) {
      expect(syntaxErrors(buildScaffold(framework, 'hmac', 'agent@example.com'))).toEqual([])
    }
  })

  it('emits a parseable settings block for claude-code', () => {
    const parsed = jsonBody(buildScaffold('claude-code', 'ed25519', 'agent@example.com')) as {
      mcpServers: Record<string, { command: string; args: string[] }>
    }
    expect(parsed.mcpServers['7h3-protocol'].command).toBe('npx')
    expect(parsed.mcpServers['7h3-protocol'].args).toContain(MCP_PACKAGE_SPEC)
  })

  it('pins the install config to the version this server actually ships', () => {
    // Regression guard: this was hardcoded at 0.5.0 while the package was 0.5.6,
    // so every generated config installed a stale release.
    const pkg = JSON.parse(
      readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
    ) as { version: string }
    expect(MCP_VERSION).toBe(pkg.version)
    expect(buildScaffold('claude-code', 'ed25519', 'a@b.test')).toContain(`@7h3/protocol-mcp@${pkg.version}`)
  })

  it('escapes a sender that would otherwise break out of the generated literal', () => {
    const hostile = 'evil", process.env.SECRET, "'
    const code = buildScaffold('webmcp', 'ed25519', hostile)
    expect(syntaxErrors(code)).toEqual([])
    expect(code).not.toContain('process.env.SECRET, "')
  })

  it('produces non-trivial output for every target', () => {
    for (const framework of FRAMEWORKS) {
      expect(buildScaffold(framework, 'ed25519', 'agent@example.com').length).toBeGreaterThan(200)
    }
  })

  it('escapes a sender containing a newline without ending a comment early', () => {
    const code = buildScaffold('express', 'ed25519', 'a@b.test\n// injected')
    expect(syntaxErrors(code)).toEqual([])
    expect(code).not.toContain('\n// injected')
  })
})

describe('buildScaffold — webmcp target', () => {
  const code = buildScaffold('webmcp', 'ed25519', 'shop.example')

  it('registers through the guard rather than document.modelContext directly', () => {
    expect(code).toContain("from '@7h3/protocol-webmcp'")
    expect(code).toContain('g.registerTool(')
    expect(code).toContain('isWebMcpSupported()')
  })

  it('demonstrates a scoped, ceilinged, confirmed write alongside an unguarded read', () => {
    expect(code).toContain("scope: 'orders/place'")
    expect(code).toContain("limit: { field: 'amountCents', max: 500_00 }")
    expect(code).toContain('confirm: true')
    expect(code).toContain('readOnlyHint: true')
  })

  it('binds a spend cap inside the grant and gives it a TTL', () => {
    expect(code).toContain('caps: { amountCents: 100_00 }')
    expect(code).toContain('ttlMs: 10 * 60_000')
  })

  it('carries the origin through into the generated guard', () => {
    expect(code).toContain('"shop.example"')
  })

  it('warns about the two WebMCP platform constraints', () => {
    expect(code).toContain('secure context')
    expect(code).toContain('TOP-LEVEL page')
  })
})
