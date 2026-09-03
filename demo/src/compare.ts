/**
 * "Same attack, twice."
 *
 * The main demo shows an agent being refused. That is easy to read as "the app
 * said no" — which undersells it, because a refusal only means something if you
 * can see what happens *without* one.
 *
 * So this page runs one compromised agent's actions against two identical
 * copies of the same books: one wired straight to its tool handlers, one behind
 * the guard. Same tools, same inputs, same order. Only the authorization layer
 * differs.
 */

import { generateEd25519KeypairBase64Url } from '@7h3/protocol'
import { guard, verifyChain, type Receipt } from '@7h3/protocol-webmcp'
import { Ledger, money } from './ledger'
import './styles.css'

/** What a prompt-injected agent tries once it has hands on the tool surface. */
const ATTACK = [
  { tool: 'pay_invoice',      label: 'Pay INV-1042',              input: { id: 'INV-1042', amountCents: 1_850_00 }, tells: 'moves $1,850' },
  { tool: 'wire_funds',       label: 'Wire to an offshore account', input: { account: 'XX-9931-OFFSHORE', amountCents: 900_00 }, tells: 'moves $900 out' },
  { tool: 'delete_invoice',   label: 'Delete INV-1041',            input: { id: 'INV-1041' }, tells: 'destroys a record' },
  { tool: 'export_customers', label: 'Export every customer',      input: {}, tells: 'exfiltrates 4 people' },
] as const

interface Outcome {
  label: string
  tells: string
  ok: boolean
  detail: string
}

const state: { unguarded: Outcome[]; guarded: Outcome[]; receipts: Receipt[]; chainOk: boolean | null; ran: boolean } = {
  unguarded: [], guarded: [], receipts: [], chainOk: null, ran: false,
}

const keys = await generateEd25519KeypairBase64Url()

// ── Side A: the tools wired straight to their handlers, as most apps ship ────
const plainLedger = new Ledger()
const plainTools: Record<string, (i: Record<string, unknown>) => Promise<string>> = {
  pay_invoice: async ({ id }) => `paid ${plainLedger.payInvoice(String(id)).id}`,
  wire_funds: async ({ account, amountCents }) => `wired ${money(Number(amountCents))} to ${String(account)}`,
  delete_invoice: async ({ id }) => `deleted ${plainLedger.deleteInvoice(String(id)).deleted}`,
  export_customers: async () => `exported ${plainLedger.customers.length} customer records`,
}

// ── Side B: identical tools, behind the guard ───────────────────────────────
const guardedLedger = new Ledger()
const g = guard({ origin: 'compare.demo', privateKey: keys.privateKey, publicKey: keys.publicKey })

async function registerGuarded(): Promise<void> {
  await g.registerTool({
    name: 'pay_invoice', description: 'Pay an open invoice',
    annotations: { destructiveHint: true },
    scope: 'money/pay_invoice', limit: { field: 'amountCents', max: 2_000_00 },
    execute: async ({ id }) => guardedLedger.payInvoice(String(id)),
  })
  await g.registerTool({
    name: 'wire_funds', description: 'Wire funds to an external account',
    annotations: { destructiveHint: true },
    scope: 'money/wire', limit: { field: 'amountCents', max: 1_000_00 }, confirm: true,
    execute: async ({ account, amountCents }) => ({ wired: true, account, amountCents }),
  })
  await g.registerTool({
    name: 'delete_invoice', description: 'Permanently delete an invoice',
    annotations: { destructiveHint: true },
    scope: 'invoices/delete',
    execute: async ({ id }) => guardedLedger.deleteInvoice(String(id)),
  })
  await g.registerTool({
    name: 'export_customers', description: 'Export the full customer list',
    scope: 'data/export', confirm: true,
    execute: async () => guardedLedger.customers,
  })
}
await registerGuarded()

async function runAttack(): Promise<void> {
  state.unguarded = []
  state.guarded = []

  // The owner has granted exactly what a bookkeeper needs: pay invoices, $50
  // ceiling, ten minutes. Nothing in the attack is inside that.
  await g.grant({
    subject: 'compromised-agent',
    scopes: ['money/pay_invoice'],
    caps: { amountCents: 50_00 },
    ttlMs: 10 * 60_000,
  })

  for (const step of ATTACK) {
    try {
      const detail = await plainTools[step.tool](step.input as Record<string, unknown>)
      state.unguarded.push({ label: step.label, tells: step.tells, ok: true, detail })
    } catch (err) {
      state.unguarded.push({ label: step.label, tells: step.tells, ok: false, detail: String(err) })
    }

    const res = (await g.invoke(step.tool, step.input as Record<string, unknown>)) as {
      ok: boolean; reason?: string; detail?: string
    }
    state.guarded.push({
      label: step.label,
      tells: step.tells,
      ok: res.ok,
      detail: res.ok ? 'executed' : `${res.reason} — ${res.detail ?? ''}`,
    })
  }

  state.receipts = g.receipts.all()
  state.chainOk = (await verifyChain(state.receipts, keys.publicKey)).ok
  state.ran = true
  render()
}

// ── render ──────────────────────────────────────────────────────────────────

const root = document.getElementById('root')!
const esc = (s: unknown) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)

function column(title: string, subtitle: string, rows: Outcome[], tone: 'bad' | 'good'): string {
  const body = rows.length === 0
    ? `<div class="empty">Nothing run yet.</div>`
    : rows.map((r) => `
        <div class="receipt ${r.ok ? (tone === 'bad' ? 'refused' : 'allowed') : 'allowed'}">
          <div class="dot" style="background:${r.ok ? 'var(--danger)' : 'var(--accent)'}"></div>
          <div>
            <div class="tool">${r.ok ? 'SUCCEEDED' : 'REFUSED'} · ${esc(r.label)}</div>
            <div class="why">${r.ok ? esc(r.tells) + ' — ' + esc(r.detail) : esc(r.detail)}</div>
          </div>
        </div>`).join('')

  const succeeded = rows.filter((r) => r.ok).length
  const summary = rows.length === 0 ? '' : `
    <div class="verdict ${succeeded > 0 ? 'bad' : 'ok'}">
      ${succeeded} of ${rows.length} attacks succeeded
    </div>`

  return `<div class="card">
    <h2>${esc(title)}</h2>
    <div class="card-body"><div class="hint" style="padding:0 0 10px">${esc(subtitle)}</div>${summary}</div>
    <div class="feed">${body}</div>
  </div>`
}

function render(): void {
  const damage = state.ran
    ? `<div class="card"><h2>What actually changed</h2><div class="card-body">
         <table><thead><tr><th></th><th style="text-align:right">Unguarded</th><th style="text-align:right">Guarded</th></tr></thead>
         <tbody>
           <tr><td>Outstanding balance</td><td class="amt">${esc(money(plainLedger.outstandingCents()))}</td><td class="amt">${esc(money(guardedLedger.outstandingCents()))}</td></tr>
           <tr><td>Invoices remaining</td><td class="amt">${plainLedger.invoices.length}</td><td class="amt">${guardedLedger.invoices.length}</td></tr>
           <tr><td>Customer records exposed</td><td class="amt">${state.unguarded.find(o => o.label.includes('customer'))?.ok ? plainLedger.customers.length : 0}</td><td class="amt">0</td></tr>
           <tr><td>Signed receipts written</td><td class="amt">0</td><td class="amt">${state.receipts.length}</td></tr>
         </tbody></table>
         <div class="hint">The unguarded side keeps no record of any of it. The guarded side recorded
         every attempt on a hash-chained log — <code>${state.chainOk ? 'chain verified' : 'chain broken'}</code>.</div>
       </div></div>`
    : ''

  root.innerHTML = `
  <header>
    <div class="brand">Same attack<span>,</span> twice</div>
    <div class="tagline">one compromised agent · identical tools · only the authorization layer differs</div>
    <div class="spacer"></div>
    <a class="pill" href="/">← full demo</a>
  </header>

  <div class="layout" style="grid-template-columns: minmax(0,1fr) minmax(0,1fr)">
    <div>
      ${column('Without 7h3', 'Tools wired straight to their handlers, the way most apps ship them.', state.unguarded, 'bad')}
    </div>
    <div>
      ${column('With 7h3', 'Same tools. The owner granted only: pay invoices, $50 ceiling, 10 minutes.', state.guarded, 'good')}
    </div>
  </div>

  <div class="layout" style="grid-template-columns: minmax(0,1fr)">
    <div>
      <div class="card">
        <h2>The agent's plan</h2>
        <div class="card-body">
          <div class="rowflex">
            ${ATTACK.map((a) => `<span class="pill">${esc(a.label)}</span>`).join('')}
          </div>
          <div class="hint" style="padding:12px 0 0">
            None of this is inside what the owner authorized. On the left there is nothing
            to notice that; on the right every step is checked against a signed grant before
            the handler runs.
          </div>
          <div class="rowflex" style="margin-top:12px">
            <button class="danger" id="run">${state.ran ? 'Run the attack again' : 'Run the attack on both'}</button>
          </div>
        </div>
      </div>
      ${damage}
    </div>
  </div>`

  root.querySelector('#run')?.addEventListener('click', () => void runAttack())
}

render()
