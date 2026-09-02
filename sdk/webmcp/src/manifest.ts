/**
 * Signed tool manifests.
 *
 * OpenAI's site-tools guidance states plainly that "website-provided tool
 * definitions and results are untrusted content" and that "a tool's name or
 * claim that it only reads data isn't proof of what it does". A manifest signed
 * by the origin's key is that proof: it pins the exact name, description,
 * input schema and annotations of every tool the origin intends to publish.
 *
 * An injected script that registers a lookalike tool, or silently swaps a
 * description to steer an agent (the tool-surface poisoning class of attack),
 * changes the surface digest and the signature stops verifying.
 */

import { signCanonicalPayloadEd25519, verifyCanonicalPayloadEd25519 } from '@7h3/protocol'
import { canonicalJson, sha256Hex } from './crypto.js'
import type { GuardedTool, ManifestEntry, SignedManifest, ToolSurface } from './types.js'

/** Tools that declare `readOnlyHint` are READ; everything else is treated as WRITE. */
export function toolMethod(tool: Pick<GuardedTool, 'annotations'>): 'READ' | 'WRITE' {
  return tool.annotations?.readOnlyHint === true ? 'READ' : 'WRITE'
}

/**
 * Digest of a single tool's agent-visible surface.
 *
 * Covers exactly what an agent reads when deciding whether and how to call the
 * tool. `execute` is deliberately excluded: it is a function, not agent-visible,
 * and including it would make the digest depend on bundler output.
 */
export async function toolDigest(tool: ToolSurface): Promise<string> {
  return sha256Hex(
    canonicalJson({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema ?? null,
      annotations: tool.annotations ?? null,
      scope: tool.scope ?? 'public',
    }),
  )
}

export async function manifestEntry(tool: ToolSurface): Promise<ManifestEntry> {
  return {
    name: tool.name,
    description: tool.description,
    scope: tool.scope ?? 'public',
    method: toolMethod(tool),
    digest: await toolDigest(tool),
  }
}

/** SHA-256 over the per-tool digests in registration order. */
export async function surfaceDigest(entries: ManifestEntry[]): Promise<string> {
  return sha256Hex(entries.map((e) => e.digest).join(''))
}

/** Canonical signing payload: the whole manifest except the signature. */
export function canonicalManifestPayload(manifest: Omit<SignedManifest, 'signature'>): string {
  return canonicalJson(manifest)
}

export async function signManifest(opts: {
  origin: string
  entries: ManifestEntry[]
  privateKey: string
  keyId: string
  now?: number
}): Promise<SignedManifest> {
  const unsigned: Omit<SignedManifest, 'signature'> = {
    version: '7h3-webmcp-manifest/1',
    origin: opts.origin,
    issuedAt: opts.now ?? Date.now(),
    tools: opts.entries,
    surfaceDigest: await surfaceDigest(opts.entries),
    keyId: opts.keyId,
  }
  const signature = await signCanonicalPayloadEd25519(canonicalManifestPayload(unsigned), opts.privateKey)
  return { ...unsigned, signature }
}

export type ManifestVerification =
  | { ok: true }
  | { ok: false; reason: 'bad-signature' | 'surface-digest-mismatch'; detail?: string }

/**
 * Verify a manifest against the origin's public key.
 *
 * Recomputes the surface digest from the listed tools before checking the
 * signature, so a manifest whose digest was recomputed to match tampered tools
 * still fails on the signature, and one whose tool list was edited without
 * recomputing fails on the digest.
 */
export async function verifyManifest(
  manifest: SignedManifest,
  publicKey: string,
): Promise<ManifestVerification> {
  const recomputed = await surfaceDigest(manifest.tools)
  if (recomputed !== manifest.surfaceDigest) {
    return { ok: false, reason: 'surface-digest-mismatch', detail: `expected ${manifest.surfaceDigest}, computed ${recomputed}` }
  }

  const { signature, ...unsigned } = manifest
  const ok = await verifyCanonicalPayloadEd25519(canonicalManifestPayload(unsigned), signature, publicKey)
  return ok ? { ok: true } : { ok: false, reason: 'bad-signature' }
}

/**
 * Check a live tool surface against a signed manifest.
 *
 * This is the check that catches a tool injected *after* the manifest was
 * published: the live surface contains a tool the manifest never listed, or a
 * listed tool whose digest no longer matches.
 */
export async function diffAgainstManifest(
  live: ToolSurface[],
  manifest: SignedManifest,
): Promise<{ ok: boolean; added: string[]; removed: string[]; modified: string[] }> {
  const liveEntries = await Promise.all(live.map(manifestEntry))
  const liveByName = new Map(liveEntries.map((e) => [e.name, e]))
  const manifestByName = new Map(manifest.tools.map((e) => [e.name, e]))

  const added = [...liveByName.keys()].filter((n) => !manifestByName.has(n))
  const removed = [...manifestByName.keys()].filter((n) => !liveByName.has(n))
  const modified = [...liveByName.entries()]
    .filter(([n, e]) => manifestByName.has(n) && manifestByName.get(n)!.digest !== e.digest)
    .map(([n]) => n)

  return { ok: added.length === 0 && removed.length === 0 && modified.length === 0, added, removed, modified }
}
