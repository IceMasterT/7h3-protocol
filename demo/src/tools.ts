/**
 * The Ledger tool surface.
 *
 * Every tool goes through `guard.registerTool`, which has the same signature as
 * `document.modelContext.registerTool` plus three optional fields — `scope`,
 * `limit` and `confirm`. The application handlers below are the untouched
 * Ledger methods: adding 7h3 did not change a line of domain logic.
 */

import type { ToolGuard } from '@7h3/protocol-webmcp'
import { money, type Ledger } from './ledger'

/** Resolves when the human answers an in-page access request, or times out. */
export type AccessRequester = (reason: string, scopes: string[], capCents?: number) => Promise<boolean>

export async function registerLedgerTools(
  guard: ToolGuard,
  ledger: Ledger,
  requestAccess: AccessRequester,
): Promise<void> {
  // -- reads: published unguarded, because they expose nothing sensitive -----

  await guard.registerTool({
    name: 'list_invoices',
    description: 'List invoices on the account, optionally filtered by status (open, paid, refunded).',
    inputSchema: {
      type: 'object',
      properties: { status: { type: 'string', enum: ['open', 'paid', 'refunded'] } },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
    execute: async ({ status }) => ledger.listInvoices(status as 'open' | undefined),
  })

  await guard.registerTool({
    name: 'get_invoice',
    description: 'Read a single invoice by id, for example INV-1041.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
    execute: async ({ id }) => ledger.getInvoice(String(id)) ?? { error: 'not found' },
  })

  await guard.registerTool({
    name: 'get_outstanding_balance',
    description: 'Total value of all open invoices, in cents and formatted.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true },
    execute: async () => {
      const cents = ledger.outstandingCents()
      return { outstandingCents: cents, formatted: money(cents) }
    },
  })

  // -- writes: each behind a capability scope -------------------------------

  await guard.registerTool({
    name: 'create_invoice',
    description: 'Create a new invoice for a customer.',
    inputSchema: {
      type: 'object',
      properties: {
        customer: { type: 'string' },
        amountCents: { type: 'number', description: 'Amount in cents.' },
        due: { type: 'string', description: 'Due date, YYYY-MM-DD.' },
      },
      required: ['customer', 'amountCents'],
      additionalProperties: false,
    },
    scope: 'invoices/create',
    limit: { field: 'amountCents', max: 10_000_00 },
    execute: async ({ customer, amountCents, due }) =>
      ledger.createInvoice(String(customer), Number(amountCents), String(due ?? '2026-09-30')),
  })

  await guard.registerTool({
    name: 'pay_invoice',
    description: 'Pay an open invoice from the operating account.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        amountCents: { type: 'number', description: 'Amount to pay, in cents.' },
      },
      required: ['id', 'amountCents'],
      additionalProperties: false,
    },
    annotations: { destructiveHint: true },
    scope: 'money/pay_invoice',
    // A ceiling the site itself will never exceed, whatever a grant says.
    limit: { field: 'amountCents', max: 2_000_00 },
    execute: async ({ id }) => ledger.payInvoice(String(id)),
  })

  await guard.registerTool({
    name: 'issue_refund',
    description: 'Refund a paid invoice back to the customer.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' }, amountCents: { type: 'number' } },
      required: ['id', 'amountCents'],
      additionalProperties: false,
    },
    annotations: { destructiveHint: true },
    scope: 'money/refund',
    limit: { field: 'amountCents', max: 500_00 },
    execute: async ({ id, amountCents }) => ledger.refundInvoice(String(id), Number(amountCents)),
  })

  await guard.registerTool({
    name: 'delete_invoice',
    description: 'Permanently delete an invoice. This cannot be undone.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: { destructiveHint: true },
    scope: 'invoices/delete',
    execute: async ({ id }) => ledger.deleteInvoice(String(id)),
  })

  await guard.registerTool({
    name: 'export_customers',
    description: 'Export the full customer list, including email addresses.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    scope: 'data/export',
    // Bulk personal data leaves the page only with a human in the loop.
    confirm: true,
    execute: async () => ledger.customers,
  })

  await guard.registerTool({
    name: 'wire_funds',
    description: 'Wire funds to an external bank account.',
    inputSchema: {
      type: 'object',
      properties: {
        account: { type: 'string' },
        amountCents: { type: 'number' },
      },
      required: ['account', 'amountCents'],
      additionalProperties: false,
    },
    annotations: { destructiveHint: true },
    scope: 'money/wire',
    limit: { field: 'amountCents', max: 1_000_00 },
    confirm: true,
    execute: async ({ account, amountCents }) => {
      ledger.note(`wired ${money(Number(amountCents))} to ${String(account)}`)
      return { wired: true, account, amountCents }
    },
  })

  // -- collaboration: the agent can ask the human for authority -------------

  await guard.registerTool({
    name: 'request_access',
    description:
      'Ask the account owner for permission to perform an action you are not currently authorized for. ' +
      'Explain what you need and why; the owner sees your request and approves or denies it in the page. ' +
      'Call this when another tool refuses you with no-active-grant or scope-not-covered.',
    inputSchema: {
      type: 'object',
      properties: {
        reason: { type: 'string', description: 'What you need to do and why.' },
        scopes: {
          type: 'array',
          items: { type: 'string' },
          description: 'Capability scopes requested, e.g. ["money/pay_invoice"].',
        },
        capCents: { type: 'number', description: 'Optional spend ceiling to request, in cents.' },
      },
      required: ['reason', 'scopes'],
      additionalProperties: false,
    },
    execute: async ({ reason, scopes, capCents }) => {
      const requested = (scopes as string[]) ?? []
      const approved = await requestAccess(String(reason), requested, capCents ? Number(capCents) : undefined)
      return approved
        ? { approved: true, scopes: requested, note: 'Grant issued. Retry your call.' }
        : { approved: false, note: 'The account owner denied this request. Do not retry.' }
    },
  })
}
