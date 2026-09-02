/**
 * Binding handlers to the declared tool surface.
 *
 * The surface lives in `tool-defs.ts`; this file supplies the `execute` for each
 * name and registers the pair through `guard.registerTool`, which has the same
 * signature as `document.modelContext.registerTool` plus `scope`, `limit` and
 * `confirm`.
 *
 * Every handler below is an untouched `Ledger` method. Adding 7h3 changed no
 * domain logic — which is what "drop it into an existing app" has to mean.
 */

import type { ToolGuard, ToolSurface } from '@7h3/protocol-webmcp'
import { money, type Ledger } from './ledger'
import { TOOL_DEFS } from './tool-defs'

type Executor = (input: Record<string, unknown>) => Promise<unknown>

/** Resolves when the human answers an in-page access request. */
export type AccessRequester = (reason: string, scopes: string[], capCents?: number) => Promise<boolean>

function executors(ledger: Ledger, requestAccess: AccessRequester): Record<string, Executor> {
  return {
    list_invoices: async ({ status }) => ledger.listInvoices(status as 'open' | undefined),

    get_invoice: async ({ id }) => ledger.getInvoice(String(id)) ?? { error: 'not found' },

    get_outstanding_balance: async () => {
      const cents = ledger.outstandingCents()
      return { outstandingCents: cents, formatted: money(cents) }
    },

    create_invoice: async ({ customer, amountCents, due }) =>
      ledger.createInvoice(String(customer), Number(amountCents), String(due ?? '2026-09-30')),

    pay_invoice: async ({ id }) => ledger.payInvoice(String(id)),

    issue_refund: async ({ id, amountCents }) => ledger.refundInvoice(String(id), Number(amountCents)),

    delete_invoice: async ({ id }) => ledger.deleteInvoice(String(id)),

    export_customers: async () => ledger.customers,

    wire_funds: async ({ account, amountCents }) => {
      ledger.note(`wired ${money(Number(amountCents))} to ${String(account)}`)
      return { wired: true, account, amountCents }
    },

    request_access: async ({ reason, scopes, capCents }) => {
      const requested = (scopes as string[]) ?? []
      const approved = await requestAccess(String(reason), requested, capCents ? Number(capCents) : undefined)
      return approved
        ? { approved: true, scopes: requested, note: 'Grant issued. Retry your call.' }
        : { approved: false, note: 'The account owner denied this request. Do not retry.' }
    },
  }
}

export async function registerLedgerTools(
  guard: ToolGuard,
  ledger: Ledger,
  requestAccess: AccessRequester,
): Promise<void> {
  const handlers = executors(ledger, requestAccess)

  for (const def of TOOL_DEFS) {
    const execute = handlers[def.name]
    if (!execute) throw new Error(`no handler bound for declared tool: ${def.name}`)
    await guard.registerTool({ ...def, execute })
  }
}

/**
 * Register a tool that is *not* in the signed manifest, standing in for an
 * injected third-party script or an XSS payload.
 *
 * It registers successfully — nothing stops a script on your own origin from
 * calling `registerTool`. The point is that the manifest check then notices.
 */
export async function registerPoisonedTool(guard: ToolGuard, def: ToolSurface, ledger: Ledger): Promise<void> {
  await guard.registerTool({
    ...def,
    execute: async () => {
      ledger.note(`${def.name} executed — this tool was never in the signed manifest`)
      return ledger.listInvoices()
    },
  })
}
