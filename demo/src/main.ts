/**
 * Ledger — an agent-operable business console.
 *
 * The left half is an ordinary app. The right half is the trust layer: what the
 * agent is currently allowed to do, and a tamper-evident record of everything it
 * has tried. Nothing in `ledger.ts` knows an agent exists.
 */

import { generateEd25519KeypairBase64Url } from '@7h3/protocol'
import {
  diffAgainstManifest,
  guard,
  isWebMcpSupported,
  verifyChain,
  verifyManifest,
  type Receipt,
  type SignedManifest,
} from '@7h3/protocol-webmcp'
import { Ledger, money, type Invoice } from './ledger'
import { POISONED_TOOL } from './tool-defs'
import { registerLedgerTools, registerPoisonedTool } from './tools'
import './styles.css'

const ORIGIN = '7h3-webmcp-ledger'
const KEY_STORAGE = '7h3.ledger.keypair.v1'

// ---------------------------------------------------------------------------
// Keys — persisted per browser so an exported receipt chain stays verifiable.
// ---------------------------------------------------------------------------

async function loadKeys(): Promise<{ publicKey: string; privateKey: string }> {
  try {
    const stored = localStorage.getItem(KEY_STORAGE)
    if (stored) return JSON.parse(stored) as { publicKey: string; privateKey: string }
  } catch {
    // Private window or blocked storage: fall through and use a session key.
  }
  const keys = await generateEd25519KeypairBase64Url()
  try {
    localStorage.setItem(KEY_STORAGE, JSON.stringify(keys))
  } catch {
    // Non-persistent is fine; the chain still verifies for this session.
  }
  return keys
}

// ---------------------------------------------------------------------------
// UI state
// ---------------------------------------------------------------------------

interface PendingConfirm {
  title: string
  body: string
  scopes: string
  resolve: (ok: boolean) => void
}

interface Provenance {
  /** null while the manifest is still being fetched. */
  signatureOk: boolean | null
  keyId: string
  surfaceDigest: string
  added: string[]
  removed: string[]
  modified: string[]
  error?: string
}

const state: {
  verdict: { ok: boolean; text: string } | null
  /**
   * Pending confirmations, oldest first.
   *
   * A queue rather than a single slot: an agent can call two confirm-required
   * tools before the human answers either, and overwriting one slot would drop
   * the first promise's resolve, hanging that tool call forever.
   */
  confirmQueue: PendingConfirm[]
  manifest: SignedManifest | null
  provenance: Provenance | null
} = { verdict: null, confirmQueue: [], manifest: null, provenance: null }

const ledger = new Ledger()
const keys = await loadKeys()

const g = guard({
  origin: ORIGIN,
  privateKey: keys.privateKey,
  publicKey: keys.publicKey,
  onConfirm: (tool, input) =>
    new Promise<boolean>((resolve) => {
      // Show the human the application arguments only; reserved 7h3 fields are
      // plumbing and just add noise to a consent prompt.
      const shown = Object.fromEntries(Object.entries(input).filter(([k]) => !k.startsWith('__7h3')))
      state.confirmQueue.push({
        title: `Confirm: ${tool.name}`,
        body: tool.description,
        scopes: JSON.stringify(shown, null, 2),
        resolve,
      })
      render()
    }),
})

/** The agent asking the human for authority, resolved by the same modal. */
async function requestAccess(reason: string, scopes: string[], capCents?: number): Promise<boolean> {
  const approved = await new Promise<boolean>((resolve) => {
    state.confirmQueue.push({
      title: 'The agent is requesting access',
      body: reason,
      scopes: scopes.join('\n') + (capCents ? `\ncap: ${money(capCents)}` : ''),
      resolve,
    })
    render()
  })
  if (approved) {
    await g.grant({
      subject: 'chatgpt-agent',
      scopes,
      caps: capCents ? { amountCents: capCents } : undefined,
      ttlMs: 10 * 60_000,
    })
    ledger.note(`owner approved: ${scopes.join(', ')}`, 'human')
  } else {
    ledger.note(`owner denied: ${scopes.join(', ')}`, 'human')
  }
  return approved
}

await registerLedgerTools(g, ledger, requestAccess)

/**
 * Check the live tool surface against the manifest this origin published.
 *
 * The manifest is signed at deploy time by the origin identity key, whose public
 * half is served at /.well-known/7h3-keys.json. The browser never sees the
 * private half. Two independent checks run: the manifest verifies under the
 * published key, and the tools actually registered on this page match it.
 */
async function checkProvenance(): Promise<void> {
  try {
    const [manifestRes, keysRes] = await Promise.all([
      fetch('/.well-known/7h3-webmcp-manifest.json'),
      fetch('/.well-known/7h3-keys.json'),
    ])
    if (!manifestRes.ok || !keysRes.ok) throw new Error('manifest or key document unavailable')

    const manifest = (await manifestRes.json()) as SignedManifest
    const keyDoc = (await keysRes.json()) as { keys: { keyId: string; publicKey: string }[] }
    const key = keyDoc.keys.find((k) => k.keyId === manifest.keyId)
    if (!key) throw new Error(`no published key for ${manifest.keyId}`)

    state.manifest = manifest
    const verified = await verifyManifest(manifest, key.publicKey)
    const diff = await diffAgainstManifest(g.registeredTools(), manifest)

    state.provenance = {
      signatureOk: verified.ok,
      keyId: manifest.keyId,
      surfaceDigest: manifest.surfaceDigest,
      added: diff.added,
      removed: diff.removed,
      modified: diff.modified,
    }
  } catch (err) {
    state.provenance = {
      signatureOk: false,
      keyId: '—',
      surfaceDigest: '—',
      added: [],
      removed: [],
      modified: [],
      error: err instanceof Error ? err.message : String(err),
    }
  }
  render()
}


g.on(() => render())
ledger.subscribe(() => render())
setInterval(render, 1000) // grant countdowns

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

const PRESETS: { label: string; scopes: string[]; capCents?: number; ttlMs: number }[] = [
  { label: 'Read-only', scopes: ['invoices/read'], ttlMs: 10 * 60_000 },
  { label: 'Bookkeeper · pay ≤ $50', scopes: ['invoices/create', 'money/pay_invoice'], capCents: 50_00, ttlMs: 10 * 60_000 },
  // $1,000 ceiling: high enough that the $900 wire reaches the human-confirmation
  // step, low enough that the $1,850 invoice payment is still refused on the cap.
  { label: 'Full admin · 2 min', scopes: ['invoices/**', 'money/**', 'data/**'], capCents: 1_000_00, ttlMs: 2 * 60_000 },
]

/**
 * Canned agent actions.
 *
 * These call `g.invoke`, the same guarded wrapper `document.modelContext` calls,
 * so the demo behaves identically whether a real agent drives it or you click
 * the buttons. Useful in browsers with no WebMCP agent attached.
 */
const SCENARIOS: { label: string; tool: string; input: Record<string, unknown>; danger?: boolean }[] = [
  { label: 'List open invoices', tool: 'list_invoices', input: { status: 'open' } },
  { label: 'Pay INV-1043 · $47.50', tool: 'pay_invoice', input: { id: 'INV-1043', amountCents: 47_50 } },
  { label: 'Pay INV-1042 · $1,850', tool: 'pay_invoice', input: { id: 'INV-1042', amountCents: 1_850_00 }, danger: true },
  { label: 'Delete INV-1041', tool: 'delete_invoice', input: { id: 'INV-1041' }, danger: true },
  { label: 'Export customers', tool: 'export_customers', input: {}, danger: true },
  { label: 'Wire $900 offshore', tool: 'wire_funds', input: { account: 'XX-9931-OFFSHORE', amountCents: 900_00 }, danger: true },
  { label: 'Ask owner for access', tool: 'request_access', input: { reason: 'I need to settle the two overdue invoices for you.', scopes: ['money/pay_invoice'], capCents: 100_00 } },
]

/**
 * Stand in for an injected third-party script or XSS payload registering a
 * lookalike tool. Registration succeeds — nothing prevents same-origin script
 * from calling registerTool. The manifest check is what notices.
 */
async function injectPoisonedTool(): Promise<void> {
  await registerPoisonedTool(g, POISONED_TOOL, ledger)
  ledger.note(`injected ${POISONED_TOOL.name} into the live tool surface`, 'human')
  await checkProvenance()
}

let lastNonce = 0
async function runScenario(i: number): Promise<void> {
  const s = SCENARIOS[i]
  await g.invoke(s.tool, { ...s.input, __7h3_nonce: `n-${++lastNonce}` })
  render()
}

/** Re-send the previous call verbatim, nonce included — this must be refused. */
async function replayLast(): Promise<void> {
  const last = g.receipts.all().at(-1)
  if (!last) return
  const scenario = SCENARIOS.find((s) => s.tool === last.tool)
  if (!scenario) return
  await g.invoke(scenario.tool, { ...scenario.input, __7h3_nonce: `n-${lastNonce}` })
  render()
}

async function issuePreset(i: number): Promise<void> {
  const p = PRESETS[i]
  await g.grant({ subject: 'chatgpt-agent', scopes: p.scopes, caps: p.capCents ? { amountCents: p.capCents } : undefined, ttlMs: p.ttlMs })
  ledger.note(`granted ${p.label}`, 'human')
}

async function verify(): Promise<void> {
  const result = await verifyChain(g.receipts.all(), keys.publicKey)
  state.verdict = result.ok
    ? { ok: true, text: `chain intact · ${result.length} receipt(s) verified` }
    : { ok: false, text: `BROKEN at #${result.brokenAt} · ${result.reason}` }
  render()
}

/** Prove the chain actually detects tampering, without corrupting the real log. */
async function simulateTamper(): Promise<void> {
  const entries = g.receipts.all()
  if (entries.length === 0) {
    state.verdict = { ok: false, text: 'no receipts yet — call a tool first' }
    return render()
  }
  const copy: Receipt[] = entries.map((e) => ({ ...e }))
  const target = copy.findIndex((e) => e.outcome === 'refused')
  const idx = target >= 0 ? target : 0
  copy[idx] = { ...copy[idx], outcome: 'allowed', reason: undefined }

  const result = await verifyChain(copy, keys.publicKey)
  state.verdict = result.ok
    ? { ok: false, text: 'unexpected: tampering was not detected' }
    : { ok: false, text: `tampering detected at #${result.brokenAt} · ${result.reason}` }
  render()
}

function exportReceipts(): void {
  const blob = new Blob([g.receipts.export()], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = '7h3-receipts.json'
  a.click()
  URL.revokeObjectURL(url)
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

const root = document.getElementById('root')!

function esc(s: unknown): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
}

function invoiceRow(i: Invoice): string {
  return `<tr>
    <td class="id">${esc(i.id)}</td>
    <td>${esc(i.customer)}</td>
    <td><span class="status ${i.status}">${i.status}</span></td>
    <td class="amt">${esc(money(i.amountCents))}</td>
  </tr>`
}

function receiptRow(r: Receipt): string {
  const when = new Date(r.timestampMs).toLocaleTimeString()
  const why = r.outcome === 'refused' ? `<div class="why">${esc(r.reason)} — ${esc(r.detail ?? '')}</div>` : ''
  return `<div class="receipt ${r.outcome}">
    <div class="dot"></div>
    <div>
      <div class="tool">#${r.seq} ${esc(r.tool)} <span style="color:var(--muted);font-weight:400">· ${r.method} · ${when}</span></div>
      ${why}
      <div class="hash">prev ${esc(r.prevHash.slice(0, 16))}…</div>
    </div>
  </div>`
}

function provenanceBlock(): string {
  const p = state.provenance
  if (!p) return `<div class="verdict">checking published manifest…</div>`
  if (p.error) return `<div class="verdict bad">manifest unavailable — ${esc(p.error)}</div>`

  const clean = p.signatureOk && p.added.length === 0 && p.removed.length === 0 && p.modified.length === 0
  if (clean) {
    return `<div class="verdict ok">surface verified · ${g.registeredTools().length} tools match the signed manifest</div>
      <div class="hash" style="font-family:var(--mono);font-size:11px;color:var(--muted)">
        key ${esc(p.keyId)} · digest ${esc(p.surfaceDigest.slice(0, 24))}…
      </div>`
  }

  const problems: string[] = []
  if (!p.signatureOk) problems.push('manifest signature invalid')
  if (p.added.length) problems.push(`UNPUBLISHED TOOL: ${p.added.join(', ')}`)
  if (p.modified.length) problems.push(`MODIFIED: ${p.modified.join(', ')}`)
  if (p.removed.length) problems.push(`MISSING: ${p.removed.join(', ')}`)

  return `<div class="verdict bad">${problems.map(esc).join('<br>')}</div>
    <div class="hash" style="font-family:var(--mono);font-size:11px;color:var(--muted)">
      the live surface does not match what ${esc(p.keyId)} signed
    </div>`
}

function render(): void {
  const pending = state.confirmQueue[0]
  const grants = g.activeGrants()
  const receipts = [...g.receipts.all()].reverse()
  const supported = isWebMcpSupported()

  root.innerHTML = `
  <header>
    <div class="brand">Ledger<span>.</span></div>
    <div class="tagline">agent-operable books, cryptographically bounded</div>
    <div class="spacer"></div>
    <span class="pill ${supported ? 'ok' : 'off'}">${supported ? 'WebMCP detected' : 'WebMCP not detected — tools registered, agent absent'}</span>
    <span class="pill">origin key ${esc(keys.publicKey.slice(0, 10))}…</span>
    <span class="pill ${state.provenance && state.provenance.signatureOk && state.provenance.added.length === 0 ? 'ok' : 'off'}">surface ${
    state.provenance
      ? state.provenance.added.length || !state.provenance.signatureOk
        ? 'UNVERIFIED'
        : 'verified'
      : '…'
  }</span>
  </header>

  <div class="layout">
    <div>
      <div class="card">
        <div class="balance">
          <div class="amount">${esc(money(ledger.outstandingCents()))}</div>
          <div class="label">outstanding across ${ledger.listInvoices('open').length} open invoices</div>
        </div>
      </div>

      <div class="card">
        <h2>Invoices <span class="count">${ledger.invoices.length}</span></h2>
        <table>
          <thead><tr><th>Invoice</th><th>Customer</th><th>Status</th><th style="text-align:right">Amount</th></tr></thead>
          <tbody>${ledger.invoices.map(invoiceRow).join('')}</tbody>
        </table>
      </div>

      <div class="card">
        <h2>Activity</h2>
        ${
          ledger.activity.length === 0
            ? `<div class="empty">Nothing yet. Ask the agent to work on the books.</div>`
            : ledger.activity
                .map(
                  (a) =>
                    `<div class="receipt allowed"><div class="dot" style="background:${a.actor === 'human' ? 'var(--warn)' : 'var(--accent)'}"></div><div><div class="tool">${esc(a.text)}</div><div class="why">${a.actor} · ${new Date(a.at).toLocaleTimeString()}</div></div></div>`,
                )
                .join('')
        }
      </div>
    </div>

    <div>
      <div class="card">
        <h2>Grant access</h2>
        <div class="card-body">
          <div class="rowflex">
            ${PRESETS.map((p, i) => `<button data-preset="${i}">${esc(p.label)}</button>`).join('')}
          </div>
        </div>
      </div>

      <div class="card">
        <h2>Simulated agent</h2>
        <div class="card-body">
          <div class="rowflex">
            ${SCENARIOS.map((s, i) => `<button data-scenario="${i}" class="${s.danger ? 'danger' : ''}">${esc(s.label)}</button>`).join('')}
            <button data-replay="1">Replay last call</button>
          </div>
        </div>
        <div class="hint">
          A real agent in ChatGPT's browser calls these same tools. These buttons run the identical
          guarded wrapper, so the demo works even without a WebMCP-capable browser.
        </div>
      </div>

      <div class="card">
        <h2>Active grants <span class="count">${grants.length}</span></h2>
        ${
          grants.length === 0
            ? `<div class="empty">No grants. Every scoped tool refuses.</div>`
            : `<div class="card-body">${grants
                .map((t) => {
                  const left = Math.max(0, Math.round((t.expiresAt - Date.now()) / 1000))
                  return `<div class="grant">
                    <div class="scopes">${esc(t.scopes.map((s) => s.pathGlob).join('  '))}</div>
                    <div class="meta">
                      <span class="ttl">expires in ${left}s · ${esc(t.id.slice(0, 14))}</span>
                      <button class="danger" data-revoke="${esc(t.id)}">Revoke</button>
                    </div>
                  </div>`
                })
                .join('')}</div>`
        }
      </div>

      <div class="card">
        <h2>Signed receipts <span class="count">${g.receipts.length}</span></h2>
        <div class="card-body">
          ${state.verdict ? `<div class="verdict ${state.verdict.ok ? 'ok' : 'bad'}">${esc(state.verdict.text)}</div>` : ''}
          <div class="rowflex">
            <button class="primary" id="verify">Verify chain</button>
            <button id="tamper">Simulate tampering</button>
            <button id="export">Export</button>
          </div>
        </div>
        <div class="feed">
          ${receipts.length === 0 ? `<div class="empty">No tool calls yet.</div>` : receipts.map(receiptRow).join('')}
        </div>
        <div class="hint">
          Every call is recorded — allowed and refused. Each receipt carries the hash of the one before it,
          so deleting or editing history breaks verification. Try <code>Simulate tampering</code>.
        </div>
      </div>

      <div class="card">
        <h2>Tool surface provenance</h2>
        <div class="card-body">
          ${provenanceBlock()}
          <div class="rowflex" style="margin-top:10px">
            <button class="danger" id="poison">Inject a poisoned tool</button>
            <button id="recheck">Re-check surface</button>
          </div>
        </div>
        <div class="hint">
          The manifest is signed at deploy time by this origin's identity key and served at
          <code>/.well-known/7h3-webmcp-manifest.json</code>. The browser never holds that private key.
          A tool the origin never published cannot be hidden from this check.
        </div>
      </div>

    </div>
  </div>

  ${
    pending
      ? `<div class="modal-backdrop"><div class="modal">
          <h3>${esc(pending.title)}</h3>
          <p>${esc(pending.body)}</p>
          <div class="scopes" style="white-space:pre-wrap">${esc(pending.scopes)}</div>
          ${state.confirmQueue.length > 1 ? `<p style="margin-top:10px">${state.confirmQueue.length - 1} more awaiting your decision</p>` : ''}
          <div class="actions">
            <button id="deny">Deny</button>
            <button class="primary" id="approve">Approve</button>
          </div>
        </div></div>`
      : ''
  }`

  root.querySelectorAll<HTMLElement>('[data-preset]').forEach((el) =>
    el.addEventListener('click', () => void issuePreset(Number(el.dataset.preset))),
  )
  root.querySelectorAll<HTMLElement>('[data-revoke]').forEach((el) =>
    el.addEventListener('click', () => {
      g.revoke(el.dataset.revoke!)
      ledger.note('owner revoked a grant', 'human')
    }),
  )
  root.querySelectorAll<HTMLElement>('[data-scenario]').forEach((el) =>
    el.addEventListener('click', () => void runScenario(Number(el.dataset.scenario))),
  )
  root.querySelector('[data-replay]')?.addEventListener('click', () => void replayLast())
  root.querySelector('#poison')?.addEventListener('click', () => void injectPoisonedTool())
  root.querySelector('#recheck')?.addEventListener('click', () => void checkProvenance())
  root.querySelector('#verify')?.addEventListener('click', () => void verify())
  root.querySelector('#tamper')?.addEventListener('click', () => void simulateTamper())
  root.querySelector('#export')?.addEventListener('click', exportReceipts)

  const settle = (ok: boolean) => {
    const answered = state.confirmQueue.shift()
    answered?.resolve(ok)
    render()
  }
  root.querySelector('#approve')?.addEventListener('click', () => settle(true))
  root.querySelector('#deny')?.addEventListener('click', () => settle(false))
}

render()

// Kicked off after the first paint: render() reads module consts declared below
// checkProvenance, so calling it during module evaluation hits their temporal
// dead zone. The provenance card shows a checking state until this resolves.
void checkProvenance()
