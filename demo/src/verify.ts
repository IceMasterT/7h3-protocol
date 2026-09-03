/**
 * "Verify it yourself."
 *
 * The other two demos ask you to believe a UI. This one hands you the actual
 * bytes: the signed grant, the hash-chained receipts, and the manifest the
 * origin published — and lets you edit any of them and watch verification fail
 * at exactly the point you changed.
 */

import { generateEd25519KeypairBase64Url } from '@7h3/protocol'
import {
  guard,
  verifyChain,
  verifyManifest,
  type Receipt,
  type SignedManifest,
} from '@7h3/protocol-webmcp'
import { Ledger } from './ledger'
import './styles.css'

const keys = await generateEd25519KeypairBase64Url()
const ledger = new Ledger()
const g = guard({ origin: 'verify.demo', privateKey: keys.privateKey, publicKey: keys.publicKey })

await g.registerTool({
  name: 'pay_invoice',
  description: 'Pay an open invoice',
  annotations: { destructiveHint: true },
  scope: 'money/pay_invoice',
  limit: { field: 'amountCents', max: 2_000_00 },
  execute: async ({ id }) => ledger.payInvoice(String(id)),
})
await g.registerTool({
  name: 'delete_invoice',
  description: 'Permanently delete an invoice',
  annotations: { destructiveHint: true },
  scope: 'invoices/delete',
  execute: async ({ id }) => ledger.deleteInvoice(String(id)),
})

const grant = await g.grant({
  subject: 'demo-agent',
  scopes: ['money/pay_invoice'],
  caps: { amountCents: 50_00 },
  ttlMs: 10 * 60_000,
})

// A realistic mix: one allowed, one over the ceiling, one out of scope.
await g.invoke('pay_invoice', { id: 'INV-1043', amountCents: 47_50 })
await g.invoke('pay_invoice', { id: 'INV-1042', amountCents: 1_850_00 })
await g.invoke('delete_invoice', { id: 'INV-1041' })

const state: {
  edited: string
  result: { ok: boolean; brokenAt: number | null; reason?: string; length: number } | null
  manifest: SignedManifest | null
  manifestOk: boolean | null
  manifestNote: string
} = {
  edited: JSON.stringify(g.receipts.all(), null, 2),
  result: null,
  manifest: null,
  manifestOk: null,
  manifestNote: 'not checked yet',
}

async function checkChain(): Promise<void> {
  let parsed: Receipt[]
  try {
    parsed = JSON.parse(state.edited) as Receipt[]
  } catch (err) {
    state.result = { ok: false, brokenAt: null, reason: `not valid JSON — ${(err as Error).message}`, length: 0 }
    return render()
  }
  state.result = await verifyChain(parsed, keys.publicKey)
  render()
}

function tamperForMe(): void {
  const parsed = JSON.parse(state.edited) as Receipt[]
  const target = parsed.findIndex((r) => r.outcome === 'refused')
  const i = target >= 0 ? target : 0
  // The classic cover-up: turn a refusal into an approval.
  parsed[i] = { ...parsed[i], outcome: 'allowed', reason: undefined }
  state.edited = JSON.stringify(parsed, null, 2)
  void checkChain()
}

function deleteForMe(): void {
  const parsed = JSON.parse(state.edited) as Receipt[]
  const target = parsed.findIndex((r) => r.outcome === 'refused')
  parsed.splice(target >= 0 ? target : 0, 1)
  state.edited = JSON.stringify(parsed, null, 2)
  void checkChain()
}

function reset(): void {
  state.edited = JSON.stringify(g.receipts.all(), null, 2)
  state.result = null
  render()
}

async function checkManifest(): Promise<void> {
  try {
    const [mRes, kRes] = await Promise.all([
      fetch('/.well-known/7h3-webmcp-manifest.json'),
      fetch('/.well-known/7h3-keys.json'),
    ])
    if (!mRes.ok || !kRes.ok) throw new Error('manifest or key document unavailable')
    const manifest = (await mRes.json()) as SignedManifest
    const keyDoc = (await kRes.json()) as { keys: { keyId: string; publicKey: string }[] }
    const key = keyDoc.keys.find((k) => k.keyId === manifest.keyId)
    if (!key) throw new Error(`no published key for ${manifest.keyId}`)

    state.manifest = manifest
    const verified = await verifyManifest(manifest, key.publicKey)
    state.manifestOk = verified.ok
    state.manifestNote = verified.ok
      ? `verified under ${manifest.keyId} — ${manifest.tools.length} tools`
      : `FAILED: ${'reason' in verified ? verified.reason : 'unknown'}`
  } catch (err) {
    state.manifestOk = false
    state.manifestNote = (err as Error).message
  }
  render()
}

// ── render ──────────────────────────────────────────────────────────────────

const root = document.getElementById('root')!
const esc = (s: unknown) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)

function render(): void {
  const r = state.result
  const verdict = r
    ? `<div class="verdict ${r.ok ? 'ok' : 'bad'}">${
        r.ok
          ? `chain intact · ${r.length} receipt(s) verified`
          : r.brokenAt === null
            ? esc(r.reason)
            : `BROKEN at receipt #${r.brokenAt} · ${esc(r.reason)}`
      }</div>`
    : ''

  root.innerHTML = `
  <header>
    <div class="brand">Verify it<span> yourself</span></div>
    <div class="tagline">the real bytes — edit any of them and watch it break</div>
    <div class="spacer"></div>
    <a class="pill" href="/">← all demos</a>
  </header>

  <div class="layout" style="grid-template-columns: minmax(0,1fr) minmax(0,1fr)">
    <div>
      <div class="card">
        <h2>1 · The signed grant</h2>
        <div class="card-body">
          <div class="hint" style="padding:0 0 8px">
            This is what the owner actually authorized. Note <code>caps/amountCents/5000</code> —
            the $50 ceiling is a scope <em>inside the signed token</em>, not a number held in page state,
            so it cannot be raised without invalidating the signature.
          </div>
          <div class="scopes" style="white-space:pre-wrap;font-size:11px;max-height:230px;overflow:auto">${esc(
            JSON.stringify(grant, null, 2),
          )}</div>
        </div>
      </div>

      <div class="card">
        <h2>3 · The published manifest</h2>
        <div class="card-body">
          <div class="hint" style="padding:0 0 8px">
            Signed at deploy time by a key the browser never holds, and served as a static file.
            Fetched live and checked against the published public key.
          </div>
          <div class="verdict ${state.manifestOk === null ? '' : state.manifestOk ? 'ok' : 'bad'}">${esc(state.manifestNote)}</div>
          <div class="rowflex"><button class="primary" id="mf">Fetch and verify the manifest</button></div>
          ${
            state.manifest
              ? `<div class="hash" style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:10px">
                   surfaceDigest ${esc(state.manifest.surfaceDigest)}<br>
                   signature ${esc(state.manifest.signature.slice(0, 64))}…
                 </div>`
              : ''
          }
        </div>
      </div>
    </div>

    <div>
      <div class="card">
        <h2>2 · The receipt chain <span class="count">${g.receipts.length} entries</span></h2>
        <div class="card-body">
          <div class="hint" style="padding:0 0 8px">
            Every call is here — the one that succeeded and the two that were refused. Each entry carries
            <code>prevHash</code>, the SHA-256 of the entry before it, so removing or editing history
            invalidates everything after it. Edit the JSON below by hand, or use a button.
          </div>
          ${verdict}
          <textarea id="ta" spellcheck="false"
            style="width:100%;height:280px;background:var(--panel-2);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:10px;font-family:var(--mono);font-size:11px;line-height:1.45">${esc(
              state.edited,
            )}</textarea>
          <div class="rowflex" style="margin-top:10px">
            <button class="primary" id="verify">Verify chain</button>
            <button class="danger" id="tamper">Flip a refusal to allowed</button>
            <button class="danger" id="del">Delete a receipt</button>
            <button id="reset">Reset</button>
          </div>
          <div class="hint" style="padding:10px 0 0">
            Deleting is the interesting one: each surviving entry still verifies <em>on its own</em>.
            Only the chain notices the gap.
          </div>
        </div>
      </div>
    </div>
  </div>`

  const ta = root.querySelector<HTMLTextAreaElement>('#ta')
  ta?.addEventListener('input', () => { state.edited = ta.value })
  root.querySelector('#verify')?.addEventListener('click', () => void checkChain())
  root.querySelector('#tamper')?.addEventListener('click', tamperForMe)
  root.querySelector('#del')?.addEventListener('click', deleteForMe)
  root.querySelector('#reset')?.addEventListener('click', reset)
  root.querySelector('#mf')?.addEventListener('click', () => void checkManifest())
}

render()
