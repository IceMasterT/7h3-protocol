# Testing the live demo

**Start here:** <https://7h3-webmcp-ledger.tech-b1a.workers.dev>

Three demos, because "it works" means different things to different people.
Some want to see a product; some want to see what the guard actually prevents;
some want to check the cryptography themselves.

| Route | WebMCP tools | Answers | Setup |
|---|---|---|---|
| [`/`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/) — Hub | **3** read-only | *What is this, and where do I go?* | none |
| [`/compare`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/compare) — Same attack, twice | **4** all guarded | *What does the guard actually prevent?* | none |
| [`/verify`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/verify) — Verify it yourself | **2** | *Why should I believe the UI?* | none |
| [`/ledger`](https://7h3-webmcp-ledger.tech-b1a.workers.dev/ledger) — Ledger | **10** (3 read, 7 write) | *What does this look like in a real app?* | none — WebMCP optional |

**Every route registers tools on `document.modelContext`, including the landing
page** — 19 across the four. Land anywhere and an agent has something to call.

**Nothing here requires WebMCP.** Every demo runs in any browser, because each
one drives the identical guarded wrapper (`guard.invoke`) that a real agent
would hit. There is no code path that skips `decide()`. Sections A and B below
are for driving the tools with an actual agent, which is what the submission is
about — but you can evaluate the whole thing without one.

> **There is no WebMCP Chrome extension.** WebMCP is built into Chrome 149+
> behind a flag, and into the ChatGPT desktop app's browser as "site tools".
> Nothing is installed from the Web Store.

---

# Part 1 — The three demos (no setup)

## 1. `/compare` — Same attack, twice

**The fastest proof, and the one to look at first.** One click, about two
seconds.

A refusal only means something if you can see what happens *without* one. This
page runs one compromised agent's four actions against **two identical copies of
the same books** — one wired straight to its handlers the way most apps ship,
one behind the guard. Same tools, same inputs, same order. The only difference
is the authorization layer.

**Do this:** click **Run the attack on both**.

The four actions are `pay_invoice` ($1,850), `wire_funds` ($900 to
`XX-9931-OFFSHORE`), `delete_invoice`, and `export_customers`.

**Expect exactly this:**

| | Unguarded | Guarded |
|---|---|---|
| Attacks succeeded | **4 of 4** | **0 of 4** |
| Outstanding balance | $2,317.50 → **$47.50** | $2,317.50 |
| Invoices remaining | 5 → **4** | 5 |
| Customer records exposed | **4** | 0 |
| Signed receipts written | **0** | 4 |

Each guarded refusal names its own reason — `no-active-grant`,
`scope-not-covered`, `limit-exceeded` — and each is a signature or scope check,
not a model deciding to behave.

The last row is the quiet one. The unguarded side keeps **no record that any of
it happened**.

---

## 2. `/verify` — Verify it yourself

For anyone who shouldn't have to trust a UI. This page shows the real bytes and
lets you break them by hand.

**Section 1 — the signed grant.** The actual capability token. Note
`caps/amountCents/5000` sitting in the scope list: the $50 ceiling is signed
*into* the token, not held in page state, so raising it invalidates the
signature.

**Section 2 — the receipt chain.** Three entries: one call that succeeded and
two that were refused. Each carries `prevHash`, the SHA-256 of the entry before
it. The chain is an **editable textarea** — hand-edit it, or use the buttons.

| Click | Expect |
|---|---|
| **Verify chain** (unmodified) | `chain intact · 3 receipt(s) verified` |
| **Flip a refusal to allowed** | `BROKEN at receipt #1 · bad-signature` |
| **Delete a receipt** | `BROKEN at receipt #1 · seq-mismatch: expected 1, got 2` |
| **Reset** | back to intact |

Deletion is the instructive case: **each surviving receipt still verifies on its
own.** Only the chain notices the gap. That is the whole reason receipts are
linked rather than merely signed.

**Section 3 — the published manifest.** Click **Fetch and verify the manifest**:

```
verified under 7h3-webmcp-ledger-origin-k1 — 10 tools
```

It is fetched live from `/.well-known/` and checked against the published public
key. It was signed at deploy time by a key the browser never holds.

---

## 3. `/ledger` — the product

The full business console — invoices, customers, payments — with ten tools an
agent can drive. This is the one that shows what adopting the guard looks like
in a real app.

Without a WebMCP browser, use the **Simulated agent** panel; it calls the same
guarded wrapper. With one, drive it for real via Part 2 below.

**The script**, in order:

**1.** `pay_invoice` on `INV-1043`
→ Refused: **`no-active-grant`**. Nothing authorizes `money/pay_invoice` yet.

**2.** Click **Bookkeeper · pay ≤ $50**, then retry
→ Succeeds. The grant now shows `caps/amountCents/5000`.

**3.** `pay_invoice` on `INV-1042` *(that one is $1,850)*
→ Refused: **`limit-exceeded — amountCents=185000 exceeds the authorized ceiling of 5000`**

**4.** `delete_invoice` on `INV-1041`
→ Refused: **`scope-not-covered`**. The grant covers payments, not deletions.

**5.** `request_access`
→ The agent asks; you approve or deny **in the page**. Approve, and its retry
succeeds. This is the human-in-the-loop path, and the approval is what mints the
grant.

**6.** Click **Verify chain**, then **Simulate tampering**, then **Inject a
poisoned tool** → `UNPUBLISHED TOOL: list_invoices_fast`. A lookalike registered
at runtime fails the diff against the signed manifest.

### Tips

- Grant **only** Bookkeeper for step 3. If Full admin is also active the refusal
  correctly reports the $1,000 ceiling instead of $50 — accurate, but it muddies
  the beat.
- **Reload between runs.** All state is in memory, so a refresh is a clean slate.
- Do the poisoned-tool step **last**; the injected tool stays registered until
  you reload.
- **Replay last call** only reports `replayed-call` after a call that
  *succeeded* — scope and limit checks run before the replay check.

---

# Part 2 — Driving it with a real agent

## A. ChatGPT desktop app (site tools)

### Requirements

| | |
|---|---|
| App | **ChatGPT desktop**, latest version |
| Model | **GPT-5.6 Sol** or **GPT-5.6 Terra** — *Luna has WebMCP disabled* |
| Workspace | **Not** Enterprise or Edu |
| Setting | Settings → Browser → Permissions → **Enable site tools** = on |

### Steps

1. Open the ChatGPT desktop app.
2. Open **<https://7h3-webmcp-ledger.tech-b1a.workers.dev/>** in the app's
   built-in browser — not an external one.
3. Click **Site tools** in the address bar → **Available site tools**.
   You should see **3 tools**: `list_demos`, `explain_7h3`, `open_demo`.
4. Ask: *"What demos are on this page, and open the one that shows the attack."*
   → The agent calls `list_demos`, then `open_demo`, and you land on `/compare`
   without having typed a URL. `open_demo` accepts only the three published
   paths; anything else throws instead of navigating.
5. Navigate to **`/ledger`** and re-open **Site tools** — now **10 tools**,
   3 read / 7 write.
6. Run the script from demo 3 above by asking in plain language, e.g.
   *"Pay invoice INV-1043 for me."*

## B. Chrome 149+ (flag)

1. Check `chrome://version` — you need **149 or later**.
2. Go to `chrome://flags/#enable-webmcp-testing`, set **Enabled**, relaunch.
3. Open **<https://7h3-webmcp-ledger.tech-b1a.workers.dev/>**. The hub
   registers 3 tools, so you can confirm the API is live before going deeper;
   then open **`/ledger`** for the full 10-tool surface.

### Confirm the API is present

```js
typeof document.modelContext                // 'object'
typeof document.modelContext.registerTool   // 'function'
window.isSecureContext                      // true
```

The header pill should read **"WebMCP detected"**. If it says *"no WebMCP agent
here"*, the flag isn't active — the tools are still registered, but nothing is
attached to call them.

### Driving tools without an agent

Chrome can expose a testing surface so you can invoke tools from the console.
Launch Chrome with:

```
--enable-features=WebMCPTesting,DevToolsWebMCPSupport
```

which exposes `navigator.modelContextTesting` for listing and invoking the
registered tools.

Failing that, every page's own panel drives the same guarded wrapper.

---

# Part 3 — Verifying provenance from outside the page

The manifest is signed at deploy time by a key the browser never holds, and
served as a static file:

```bash
curl https://7h3-webmcp-ledger.tech-b1a.workers.dev/.well-known/7h3-webmcp-manifest.json
curl https://7h3-webmcp-ledger.tech-b1a.workers.dev/.well-known/7h3-keys.json
```

The manifest covers the Ledger's ten tools — 3 read, 7 write — with a
`surfaceDigest` over the per-tool digests, signed under
`7h3-webmcp-ledger-origin-k1`. The key document publishes the matching public
key, so the signature can be checked without trusting the page that served it.

To check that signature yourself, against the published package rather than
anything in this repo:

```bash
npm i @7h3/protocol-webmcp
```

```js
// check.mjs
import { verifyManifest } from '@7h3/protocol-webmcp'
const B = 'https://7h3-webmcp-ledger.tech-b1a.workers.dev'
const m = await (await fetch(`${B}/.well-known/7h3-webmcp-manifest.json`)).json()
const kd = await (await fetch(`${B}/.well-known/7h3-keys.json`)).json()
const k = kd.keys.find((x) => x.keyId === m.keyId)
console.log(m.tools.length, 'tools →', await verifyManifest(m, k.publicKey))
```

```bash
node check.mjs
```

Expected output:

```
10 tools → { ok: true }
```

---

## What to look for

| Signal | Where |
|---|---|
| `4 of 4` vs `0 of 4` | `/compare` |
| `chain intact · 3 receipt(s) verified` | `/verify` → **Verify chain** |
| `BROKEN at receipt #1 · bad-signature` | `/verify` → **Flip a refusal to allowed** |
| `BROKEN at receipt #1 · seq-mismatch` | `/verify` → **Delete a receipt** |
| `verified under 7h3-webmcp-ledger-origin-k1 — 10 tools` | `/verify` → manifest |
| `caps/amountCents/5000` inside the grant | `/verify` §1, `/ledger` active grants |
| `limit-exceeded`, `scope-not-covered`, `no-active-grant` | receipt feeds |
| `UNPUBLISHED TOOL: list_invoices_fast` | `/ledger` → **Inject a poisoned tool** |

Every call — allowed **and** refused — is appended to a hash-chained,
Ed25519-signed receipt log. Inputs are hashed, not stored.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| No **Site tools** entry in ChatGPT | Wrong model (use Sol or Terra), site tools disabled in Settings, or an Enterprise/Edu workspace |
| Site tools empty on `/ledger` | The page hadn't finished loading; registration is async. Reload |
| "no WebMCP agent here" in Chrome | Flag not enabled, or Chrome older than 149. Tools are still registered |
| Tools listed but never called | The agent chose not to. Ask directly: *"Use the pay_invoice tool to pay INV-1043."* |
| Everything refused on `/ledger` | No grant is active — click a preset under **Grant access** |
| Nothing works after a while | Grants expire (2–10 min by design). Issue a new one |
| `/compare` shows `3 of 4` unguarded | You ran it twice. The first run already paid and deleted those records, so the repeats fail on their own. Reload for a clean `4 of 4` |
| Looking for an extension to install | There isn't one. WebMCP is a browser flag, not an add-on |
