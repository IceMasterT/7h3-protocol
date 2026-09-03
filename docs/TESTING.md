# Testing the live demo

**Live URL:** <https://7h3-webmcp-ledger.tech-b1a.workers.dev>

Two ways to drive it. The **Simulated agent** panel works in any browser and
needs no setup — it calls the identical guarded wrapper, so judges can evaluate
without a WebMCP-capable browser. The sections below are for driving it with a
**real agent**, which is what the submission is actually about.

> There is **no WebMCP Chrome extension**. WebMCP is built into Chrome 149+
> behind a flag (origin trial), and into the ChatGPT desktop app's browser as
> "site tools". Nothing is installed from the Web Store.

---

## A. ChatGPT desktop app (site tools)

### Requirements

| | |
|---|---|
| App | **ChatGPT desktop**, updated to the latest version |
| Model | **GPT-5.6 Sol** or **GPT-5.6 Terra** — *Luna has WebMCP disabled* |
| Workspace | **Not** Enterprise or Edu |
| Setting | Settings → Browser → Permissions → **Enable site tools** = on |

### Steps

1. Open the ChatGPT desktop app.
2. Open the live URL **in the app's built-in browser** (not an external browser).
3. Click **Site tools** in the address bar → **Available site tools**.
   You should see **10 tools — 3 read, 7 write**.

### The demo script

Ask, in order:

**1.** `Pay invoice INV-1043 for me.`
→ Refused: **`no-active-grant`**. Nothing authorizes `money/pay_invoice` yet.
That refusal is a signature check, not the model choosing to behave.

**2.** Click **Bookkeeper · pay ≤ $50** in the page, then ask again.
→ Succeeds. Note `caps/amountCents/5000` in the grant — the ceiling is signed
*into* the token, not held in page state.

**3.** `Also pay INV-1042.` *(that invoice is $1,850)*
→ Refused: **`limit-exceeded — amountCents=185000 exceeds the authorized ceiling of 5000`**.

**4.** `Delete invoice INV-1041.`
→ Refused: **`scope-not-covered`**. The grant covers payments, not deletions.

**5.** `Ask the owner for permission to settle the overdue invoices.`
→ The agent calls `request_access`; you approve or deny **in the page**.
Approve, and its retry succeeds.

**6.** Click **Verify chain** → *chain intact · N receipts verified*.
Click **Simulate tampering** → *tampering detected at #N · bad-signature*.
Click **Inject a poisoned tool** → *UNPUBLISHED TOOL: list_invoices_fast*.

### Tips

- Grant **only** Bookkeeper for step 3. If Full admin is also active, the
  refusal correctly reports the $1,000 ceiling instead of $50 — accurate, but it
  muddies the beat.
- **Reload between runs.** All state is in memory, so a refresh is a clean slate.
- Do the poisoned-tool step **last**; the injected tool stays registered until
  you reload.
- **Replay last call** only shows `replayed-call` after a call that *succeeded* —
  scope and limit checks run before the replay check.

---

## B. Chrome 149+ (flag)

### Enable it

1. Check your version at `chrome://version` — you need **149 or later**.
2. Go to `chrome://flags/#enable-webmcp-testing`, set **Enabled**, relaunch.
3. Open the live URL.

### Confirm the API is present

Open DevTools console:

```js
typeof document.modelContext            // 'object'
typeof document.modelContext.registerTool  // 'function'
window.isSecureContext                  // true
```

The header pill should read **"WebMCP detected"**. If it says *"WebMCP not
detected — tools registered, agent absent"*, the flag isn't active.

### Driving tools without an agent

Chrome can expose a testing surface, so you can call tools directly rather than
needing an agent attached. Launch Chrome with:

```
--enable-features=WebMCPTesting,DevToolsWebMCPSupport
```

which exposes `navigator.modelContextTesting` for listing and invoking the
registered tools from the console.

Failing that, the page's own **Simulated agent** panel drives the same guarded
wrapper (`guard.invoke`) — there is no code path that skips `decide()`.

---

## What to look for

| Signal | Where |
|---|---|
| `surface verified · 10 tools match the signed manifest` | Tool surface provenance |
| Refusal reasons in red on the receipt feed | Signed receipts |
| `caps/amountCents/5000` inside the grant | Active grants |
| `chain intact · N receipts verified` | **Verify chain** |
| `UNPUBLISHED TOOL: list_invoices_fast` | **Inject a poisoned tool** |

Every call — allowed **and** refused — is appended to a hash-chained,
Ed25519-signed receipt log. Inputs are hashed, not stored.

---

## Verifying provenance from outside the page

The manifest is signed at deploy time by a key the browser never holds:

```bash
curl https://7h3-webmcp-ledger.tech-b1a.workers.dev/.well-known/7h3-webmcp-manifest.json
curl https://7h3-webmcp-ledger.tech-b1a.workers.dev/.well-known/7h3-keys.json
```

Ten tools, 3 read / 7 write, with a `surfaceDigest` over the per-tool digests.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| No **Site tools** entry in ChatGPT | Wrong model (use Sol or Terra), site tools disabled in Settings, or Enterprise/Edu workspace |
| "WebMCP not detected" in Chrome | Flag not enabled, or Chrome older than 149 |
| Tools listed but never called | The agent chose not to; ask more directly, e.g. *"Use the pay_invoice tool to pay INV-1043."* |
| Everything refused | No grant is active — click a preset in **Grant access** |
| Nothing works after a while | Grants expire (2–10 min by design). Issue a new one |
