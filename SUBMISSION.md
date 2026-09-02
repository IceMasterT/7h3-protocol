# WebMCP Hackathon Submission — 7h3 Protocol × WebMCP

**Project:** `@7h3/protocol-webmcp` — signed, capability-scoped, receipted WebMCP tools
**Demo:** Ledger, an agent-operable business console
**Live URL:** _see the Devpost submission_
**License:** Apache-2.0 (repository root `LICENSE`, detectable in the GitHub About section)

---

## Prior work vs. new work

The contest rules require that a pre-existing project document what is new, with
timestamped evidence, and state that judging covers **only work added during the
Submission Period** (from 2026-08-25).

### This is new — built entirely inside the Submission Period

| Path | What it is |
|---|---|
| `sdk/webmcp/` | The `@7h3/protocol-webmcp` package: the guard, signed manifests, hash-chained receipts, 46 tests |
| `demo/` | Ledger — the WebMCP demo app, its tool surface and trust panel |
| `SUBMISSION.md` | This file |

Commit evidence — every line of WebMCP work lands in these two commits:

```
458cd2d  2026-09-02 01:28:34 -0700  feat(demo): add Ledger — an agent-operable business console
59985e5  2026-09-02 01:21:51 -0700  feat(webmcp): add @7h3/protocol-webmcp
```

The branch also carries one unrelated housekeeping commit that is **not** part of
this submission and should not be judged:

```
49d9cd8  2026-09-02 01:01:12 -0700  docs: catch CHANGELOG up to v0.5.6
```

Verify the boundary yourself:

```bash
git log --format='%h %ci %s' 7cf9d26..HEAD     # everything after the last pre-contest commit
git diff --stat 7cf9d26..HEAD -- sdk/webmcp demo
```

### This existed before — the foundation, not the submission

7h3 Protocol is a pre-existing cryptographic messaging layer, last touched
**2026-08-08** (`7cf9d26`), well before the Submission Period. The new package
builds on its shipped primitives rather than reimplementing them:

- `src/capability.ts` — capability tokens, delegation chains, glob scope matching
- `src/protocol.ts` — Ed25519 signing over canonical payloads, CSPRNG nonces
- `src/replayStores.ts` — the replay-store interface
- `src/auditLog.ts` — the audit logger the new receipt chain deliberately strengthens

Reusing a 478-test protocol is the point: this is not hackathon glue, it is a
production signing layer retargeted at a new transport.

---

## What it does

WebMCP hands agents real capability on a live, signed-in page. Chrome's
[agent security guidance](https://developer.chrome.com/docs/agents/security) is
entirely probabilistic — classifiers, spotlighting, critic LLMs — and explicitly
silent on authentication, authorization and provenance. OpenAI's guidance says
plainly that "a tool's name or claim that it only reads data isn't proof of what
it does", then tells sites to use "your application's existing authentication,
authorization, and input validation" — which, for *delegated agent action*, no
site actually has.

This adds the deterministic layer underneath. **A refusal is a failed signature
or an uncovered scope, not a judgement call.**

1. **Signed tool manifests** — the origin signs its own tool surface, so injected
   lookalike tools and silently reworded descriptions become detectable.
2. **Capability-scoped execution** — scoped, expiring, revocable grants, with
   spend ceilings bound *inside* the signed token. Grants are page-held by
   default, so the token never passes through the agent.
3. **Hash-chained receipts** — every call recorded, allowed and refused, on a
   chain where deletion and reordering break verification.

Plus `request_access`: a refused agent can ask the owner for authority in-page
and retry — agent and human negotiating scope, rather than the agent just failing.

---

## How to test it

### With a real agent (the intended path)

- **ChatGPT desktop app** → built-in browser → open the live URL.
  Requires **GPT-5.6 Sol or Terra** (Luna has WebMCP disabled). Not available in
  Enterprise or Edu workspaces. Check **Site tools** in the address bar; you
  should see 10 tools (3 read, 7 write).
- **Chrome 149+** → enable `chrome://flags/#enable-webmcp-testing`, relaunch.

Prompts worth trying:

> Pay invoice INV-1043 for me.

Refused — `no-active-grant`. Then click **Bookkeeper · pay ≤ $50** and ask again;
it succeeds. Now:

> Also pay INV-1042.

Refused — `limit-exceeded`, because $1,850 exceeds the $50 ceiling bound inside
the grant. And:

> Delete invoice INV-1041.

Refused — `scope-not-covered`. Finally:

> Ask the owner for permission to settle the overdue invoices.

The agent calls `request_access`, and you approve or deny it in the page.

### Without a WebMCP browser

The right-hand **Simulated agent** panel drives the same tools through
`guard.invoke`, which runs the *identical* guarded wrapper — there is no code
path that skips `decide()`. Judging works on any browser.

### The security claims, end to end

Click **Verify chain** → `chain intact · N receipts verified`.
Click **Simulate tampering** → `tampering detected at #N · bad-signature`.
Click **Replay last call** → `replayed-call`.

---

## Run it locally

```bash
npm install
npm test                    # 521 tests, 46 of them for the new package
npm --prefix demo install
npm --prefix demo run dev
```

## Repository map

```
sdk/webmcp/src/guard.ts       the guard: decide(), grants, revocation, invoke()
sdk/webmcp/src/manifest.ts    signed tool manifests + poisoning detection
sdk/webmcp/src/receipts.ts    hash-chained, Ed25519-signed receipts
sdk/webmcp/src/*.test.ts      46 tests
demo/src/tools.ts             the 10-tool WebMCP surface
demo/src/ledger.ts            plain domain logic — no idea agents exist
demo/src/main.ts              app + trust panel
```

Read [`sdk/webmcp/README.md`](sdk/webmcp/README.md) for the API and the honest
threat model, including what this explicitly does **not** protect against.
