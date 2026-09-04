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
