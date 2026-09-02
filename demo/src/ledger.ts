/**
 * The Ledger domain: a small, believable business console.
 *
 * Deliberately plain application code with no awareness of agents, WebMCP or
 * 7h3. That separation is the point — the guard wraps this logic without it
 * changing, which is what "drop 7h3 into an existing app" actually means.
 */

export interface Invoice {
  id: string
  customer: string
  amountCents: number
  status: 'open' | 'paid' | 'refunded'
  due: string
}

export interface Customer {
  id: string
  name: string
  email: string
  since: string
}

export interface ActivityEntry {
  at: number
  text: string
  actor: 'human' | 'agent'
}

function money(cents: number): string {
  return `$${(cents / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
}

export { money }

export class Ledger {
  invoices: Invoice[] = [
    { id: 'INV-1041', customer: 'Northwind Trading', amountCents: 420_00, status: 'open', due: '2026-09-12' },
    { id: 'INV-1042', customer: 'Ferro Logistics', amountCents: 1_850_00, status: 'open', due: '2026-09-18' },
    { id: 'INV-1043', customer: 'Bellweather Studio', amountCents: 47_50, status: 'open', due: '2026-09-05' },
    { id: 'INV-1039', customer: 'Northwind Trading', amountCents: 320_00, status: 'paid', due: '2026-08-28' },
    { id: 'INV-1038', customer: 'Cinder & Co', amountCents: 96_00, status: 'paid', due: '2026-08-21' },
  ]

  customers: Customer[] = [
    { id: 'CUS-01', name: 'Northwind Trading', email: 'ap@northwind.test', since: '2024-03-11' },
    { id: 'CUS-02', name: 'Ferro Logistics', email: 'billing@ferro.test', since: '2025-01-06' },
    { id: 'CUS-03', name: 'Bellweather Studio', email: 'hello@bellweather.test', since: '2025-07-22' },
    { id: 'CUS-04', name: 'Cinder & Co', email: 'accounts@cinder.test', since: '2023-11-02' },
  ]

  activity: ActivityEntry[] = []

  private listeners = new Set<() => void>()

  subscribe(fn: () => void): () => void {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }

  private changed(): void {
    for (const fn of this.listeners) fn()
  }

  note(text: string, actor: ActivityEntry['actor'] = 'agent'): void {
    this.activity.unshift({ at: Date.now(), text, actor })
    this.activity = this.activity.slice(0, 40)
    this.changed()
  }

  // -- reads ----------------------------------------------------------------

  listInvoices(status?: Invoice['status']): Invoice[] {
    return status ? this.invoices.filter((i) => i.status === status) : this.invoices
  }

  getInvoice(id: string): Invoice | undefined {
    return this.invoices.find((i) => i.id.toLowerCase() === id.toLowerCase())
  }

  outstandingCents(): number {
    return this.invoices.filter((i) => i.status === 'open').reduce((sum, i) => sum + i.amountCents, 0)
  }

  // -- writes ---------------------------------------------------------------

  createInvoice(customer: string, amountCents: number, due: string): Invoice {
    const n = 1044 + this.invoices.filter((i) => i.id.startsWith('INV-10')).length
    const invoice: Invoice = { id: `INV-${n}`, customer, amountCents, status: 'open', due }
    this.invoices.unshift(invoice)
    this.note(`created ${invoice.id} for ${customer} (${money(amountCents)})`)
    return invoice
  }

  payInvoice(id: string): Invoice {
    const invoice = this.requireInvoice(id)
    invoice.status = 'paid'
    this.note(`paid ${invoice.id} (${money(invoice.amountCents)})`)
    return invoice
  }

  refundInvoice(id: string, amountCents: number): Invoice {
    const invoice = this.requireInvoice(id)
    invoice.status = 'refunded'
    this.note(`refunded ${money(amountCents)} on ${invoice.id}`)
    return invoice
  }

  deleteInvoice(id: string): { deleted: string } {
    const invoice = this.requireInvoice(id)
    this.invoices = this.invoices.filter((i) => i.id !== invoice.id)
    this.note(`deleted ${invoice.id}`)
    return { deleted: invoice.id }
  }

  private requireInvoice(id: string): Invoice {
    const invoice = this.getInvoice(id)
    if (!invoice) throw new Error(`no such invoice: ${id}`)
    return invoice
  }
}
