# Devpost submission copy

Paste-ready. Live URL: **https://7h3-webmcp-ledger.tech-b1a.workers.dev**
Repo: **https://github.com/IceMasterT/7h3-protocol** (branch `feat/webmcp-hackathon`)

---

## Tagline

WebMCP gives agents hands. 7h3 gives those hands a signature, a scope, and a receipt.

---

## Why this use case is a strong fit for WebMCP

WebMCP is the first time a web page can hand an agent *real* capability on a
live, signed-in session — not scraped DOM, but declared tools with the user's
actual authority behind them. That is exactly what makes it valuable, and
exactly what makes authorization the unsolved half of the problem.

The guidance around WebMCP says so directly. Chrome's agent security page is
entirely **probabilistic** — prompt-injection classifiers, spotlighting, critic
LLMs — and is silent on authentication, authorization and provenance. OpenAI's
site-tools documentation is blunter still:

> Website-provided tool definitions and results are untrusted content. A tool's
> name or claim that it only reads data isn't proof of what it does.

> Use your application's existing authentication, authorization, and input validation.

But no site has an *existing* authorization model for delegated agent action —
"this agent, these tools, this ceiling, for the next ten minutes." The advice
bottoms out on something that doesn't exist yet.

So we built it. **A refusal in our layer is a failed signature or an uncovered
scope, not a judgement call. You cannot prompt-inject your way past a signature
check.** It doesn't replace the probabilistic defenses — those decide what an
agent *should* do; this bounds what it *can* do.

## How it creates a better user experience

Today the only honest answer to "can I let an agent touch my books?" is to
supervise every action or not use it. Both are bad. Confirmation fatigue trains
people to click *approve* without reading, which is worse than no prompt at all.

Ledger replaces per-click approval with **one informed decision up front**:
*Bookkeeper · pay ≤ $50 · 10 minutes.* Then you can walk away. The agent works
freely inside the boundary and cannot leave it, because leaving it requires a
signature it does not have.

And when it hits the boundary, it doesn't just fail — refusals are structured,
so the agent can read *why* and call `request_access` to ask you for authority,
explaining what it needs and why. You approve or deny in the page. That is a
negotiation between a human and an agent over scope, which is a genuinely new
interaction.

Underneath, every call — allowed and refused — lands on a hash-chained,
signed receipt log you can verify and export. You get an answer to "what did it
actually do on my behalf, and can I prove it?"

## What people and agents can do together that was difficult or impossible before

- **Delegate money movement with a cryptographic ceiling.** Not a UI limit a
  hijacked agent argues around — a cap bound *inside* a signed token. Ask it to
  pay a $1,850 invoice under a $50 grant and it is refused with the exact ceiling.
- **Walk away from a running agent.** Grants expire on their own and revoke
  instantly. Authority that lapses by default is authority you can safely give.
- **Prove what happened.** A tamper-evident chain where deleting or reordering
  history breaks verification — so a receipt is evidence, not a log line.
- **Verify the tool surface itself.** The origin signs its own tools at deploy
  time and serves the manifest at `/.well-known/7h3-webmcp-manifest.json`. Click
  **Inject a poisoned tool** in the demo and a lookalike registers successfully —
  nothing stops same-origin script from doing that — but the page immediately
  reports `UNPUBLISHED TOOL: list_invoices_fast`. That is the tool-surface
  poisoning attack, caught, and it is why "a tool's claim isn't proof" needed an
  answer. You can run the check yourself with `curl`; the origin's private key
  never reaches the browser.
- **Let the agent ask for permission.** Not fail, not over-request up front —
  ask, in context, for exactly what it needs.

## How we implemented WebMCP

Nineteen tools across four routes, all registered via
`document.modelContext.registerTool` on the top-level page — including the
landing page, so an agent has something to call wherever it lands. The Ledger
carries ten of them
— 3 read, 7 write — each wrapped by `guard.registerTool`, which keeps the exact
WebMCP signature and adds three optional fields: `scope`, `limit`, `confirm`.

```js
await g.registerTool({
  name: 'pay_invoice',
  description: 'Pay an open invoice from the operating account.',
  inputSchema: { /* ... */ },
  annotations: { destructiveHint: true },
  scope: 'money/pay_invoice',
  limit: { field: 'amountCents', max: 2_000_00 },
  execute: async ({ id }) => ledger.payInvoice(id),
})
```

The wrapper runs before `execute`: it verifies the Ed25519 grant signature,
checks scope coverage, enforces the ceiling, checks the nonce against a replay
store, and asks for human confirmation where the tool demands it — then appends
a signed receipt whichever way it went.

Three primitives, all built on 7h3 Protocol's existing capability, signing and
replay code (a 478-test protocol, not hackathon glue):

1. **Signed tool manifests** — the origin signs name, description, schema and
   annotations of every tool at deploy time, from a declarative tool table with
   no handlers in scope. Two keys, deliberately: a long-lived *origin identity
   key* that never reaches the browser and signs the manifest, and a per-visitor
   *session key* that signs grants and receipts. `diffAgainstManifest` detects
   injected, modified or removed tools.
2. **Capability-scoped execution** — scoped, expiring, revocable grants. Held
   page-side by default, so the token never passes through the agent and cannot
   be exfiltrated by a prompt-injected one. Ceilings ride inside the signed token
   as reserved `caps/<field>/<max>` scopes.
3. **Hash-chained receipts** — each entry carries its predecessor's hash. Inputs
   are hashed, not stored, so a receipt proves what happened without leaking the
   payload.

46 new tests cover every refusal path, expiry, revocation, ceiling tightening,
replay, receipt tampering (edit / delete / reorder / forge) and surface poisoning.

**We are explicit about the limits.** This cannot stop a compromised agent acting
*inside* a scope it was legitimately granted — grant narrowly and briefly. It is
not an anti-prompt-injection system; it is what makes a successful injection
bounded and auditable instead of unbounded and invisible. The full threat model,
including what it does *not* protect against, is in `sdk/webmcp/README.md`.

## Try it

Open the live URL in the **ChatGPT desktop app's built-in browser** (GPT-5.6 Sol
or Terra — Luna has WebMCP disabled), or Chrome 149+ with
`chrome://flags/#enable-webmcp-testing`. Then:

> Pay invoice INV-1043 for me.

Refused — no grant. Click **Bookkeeper · pay ≤ $50**, ask again — it works. Then
ask it to pay INV-1042 ($1,850) and watch the cap refuse it.

Then navigate to `/compare` (4 more registered tools) and ask the agent to run
the whole attack — every action refused, each naming its own reason.

**If your browser won't cooperate**, no judge is blocked. These pages register
the same WebMCP tools; the in-page controls call the identical guarded wrapper:

| | |
|---|---|
| [`/compare`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/compare) | One click. The same four hostile actions against two identical copies of the books — **4 of 4 succeed unguarded, 0 of 4 guarded.** $2,750 moved versus nothing, and 0 receipts versus 4. |
| [`/verify`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/verify) | The real grant, receipt chain and manifest, editable by hand. Break a byte, and verification names the exact receipt that failed. |

On `/ledger`, the **Simulated agent** panel drives the same tools through the
identical guarded wrapper — there is no code path that skips `decide()`.

Full walkthrough with the exact expected strings: [`docs/TESTING.md`](./docs/TESTING.md).

---

# Video script (2:55)

Four screens, three navigations: **`/` → `/ledger` → `/compare` → `/verify`.**
Everything on `/ledger` happens without leaving the page.

Drive the first two-thirds with a **real agent** in the ChatGPT desktop
browser — an agent calling these tools is the submission, and it is what the
first judging criterion scores. The last two screens are one click each.

### Before you hit record

- ChatGPT desktop, **GPT-5.6 Sol or Terra**, site tools enabled.
- Hard-reload every page — all state is in memory, so a reload is a clean slate.
- Grant **only** Bookkeeper. If Full admin is also live, the refusal at 1:00
  correctly cites the $1,000 ceiling instead of $50 and the beat lands softer.
- Have `/compare` and `/verify` open in tabs so the cuts are instant.

---

**0:00–0:18 — The problem.**
On screen: Chrome's agent-security page, then OpenAI's line — *"a tool's name or
claim that it only reads data isn't proof of what it does."*

> "WebMCP lets a website hand an AI agent real capability on your signed-in
> session. Every defense proposed for it is probabilistic — classifiers guessing
> at intent. Nobody shipped the deterministic half."

**0:18–0:36 — The agent finds its own way in.**
On `/`, open **Site tools**: 3 tools. Ask: *"What demos are on this page, and
open the one that shows the attack."* It calls `list_demos`, then `open_demo`,
and the page navigates.

> "Every route here registers tools on `document.modelContext` — nineteen of
> them. Even the landing page, so the agent can tour the site unaided. I never
> typed a URL."

*(Come back to `/ledger` for the next beat.)*

**0:36–1:00 — Ten tools, and a refusal.**
Open **Site tools** on `/ledger`: 10 tools, 3 read / 7 write. Ask:
*"Pay invoice INV-1043."*

> "Real invoices, real money, ten WebMCP tools. And the agent is allowed to do
> exactly nothing — so it's refused. `no-active-grant`. That's a signature
> check, not a model deciding to behave."

**1:00–1:22 — The boundary holds.** ← money shot
Click **Bookkeeper · pay ≤ $50**; point at `caps/amountCents/5000` in the grant.
Ask again — it pays. Then: *"Also pay INV-1042"* ($1,850) → `limit-exceeded`.
Then: *"Delete invoice INV-1041"* → `scope-not-covered`.

> "One informed decision: these tools, this ceiling, ten minutes — and the cap is
> signed *into* the token, not held in page state. Now it has a valid grant and
> still cannot exceed it. There is no prompt that produces a valid signature."

**1:22–1:38 — It asks instead of failing.**
Ask: *"Ask the owner for permission to settle the overdue invoices."* The
approval appears in the page; approve; its retry succeeds.

> "When it hits the boundary it doesn't just fail — it asks. And I decide, on the
> same page it's working in."

**1:38–1:52 — Poisoning the tool surface.**
Point at `surface verified · 10 tools match the signed manifest`. Click **Inject
a poisoned tool** → `UNPUBLISHED TOOL: list_invoices_fast`.

> "A tool's name isn't proof of what it does — so this origin signs its whole
> tool surface at deploy time. An injected lookalike still registers. It just
> can't hide."

**1:52–2:16 — The same attack, twice.** ← money shot
Cut to `/compare`. Click **Run the attack on both**.

> "A refusal only means something if you can see what happens without one. Same
> four hostile actions, two identical copies of the books — one behind the guard,
> one wired straight to its handlers, the way most apps ship."

Let the table land, then read it:

> "Four of four succeed. Zero of four guarded. Twenty-seven hundred dollars moved,
> an invoice destroyed, four customer records exported — and zero receipts. The
> unguarded side keeps no record any of it happened."

**2:16–2:40 — Don't take my word for it.**
Cut to `/verify`. **Verify chain** → `chain intact · 3 receipt(s) verified`.
Click **Flip a refusal to allowed** → `BROKEN at receipt #1 · bad-signature`.
Click **Delete a receipt** → `BROKEN at receipt #1 · seq-mismatch`.

> "These are the real bytes — the signed grant, the receipts, the manifest, all
> editable. Rewrite a refusal into an approval, it breaks. Delete a receipt and
> every surviving one still verifies on its own — only the chain notices the
> gap."

**2:40–2:55 — Close.**

> "Deterministic, not probabilistic. A refusal here is a failed signature or an
> uncovered scope — never a judgement call. WebMCP gives agents hands. This gives
> those hands a signature, a scope, and a receipt. It's on npm today."

---

### If the agent won't cooperate on camera

Models sometimes decline to call a tool. Ask directly — *"Use the pay_invoice
tool to pay INV-1043"* — rather than re-recording. Failing that, `/ledger`'s
**Simulated agent** panel calls the identical guarded wrapper, so the refusals
and receipts are the real ones; only the asking is manual. Keep the Site tools
list on camera in that case, so the WebMCP registration is still visible.
