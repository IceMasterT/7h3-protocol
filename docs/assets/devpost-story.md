## Inspiration

This started as something else entirely.

I was building a symbol system called **ClickClack**, modelled on DNA — every glyph connected on its top and sides, so written text linked into a continuous strand. It looked incredible. It was also, honestly, a novelty.

But I kept trying to find it a job. The obvious one was density: if the symbols pack more meaning per character, maybe this is a fast way for AI systems to talk to each other. So I went looking at how agents actually communicate, and ended up deep in MCP — where I found a much more interesting hole than the one I'd set out to fill.

**Agents were exchanging messages with no way to prove who sent them.** No signature, no replay protection, no provenance. The transport was solved. The trust was not.

So the compression project quietly became a security project, and the DNA metaphor turned out to survive the pivot better than the glyphs did. What I actually shipped is a chain: every message carries a signature; every capability token carries its parent; every receipt carries the hash of the one before it. Break a link and the whole strand fails verification. That's the idea I started with — it just found its real form somewhere I wasn't looking.

Funny how things work out.

Then WebMCP arrived, and the same gap opened up in the browser — except now the agent has hands on your signed-in session. It was the perfect fit.

## What it does

**7h3 Protocol** is the deterministic authorization layer for agent tool calls. This submission extends it to WebMCP.

Chrome's agent-security guidance is entirely probabilistic — classifiers, prompt spotlighting, critic models. OpenAI's site-tools docs state plainly that *"a tool's name or claim that it only reads data isn't proof of what it does"* — then tell sites to use their **existing** authorization. For delegated agent action, no site has one. That's the missing half, and probabilistic defenses can't supply it, because anything a model can be persuaded into is not a boundary.

`guard.registerTool()` wraps `document.modelContext.registerTool` and gives every tool call:

- an **Ed25519-signed capability grant**, scoped per tool and expiring
- a **spend ceiling bound inside the signed token** as a reserved `caps/<field>/<max>` scope — not a number held in page state, so raising it invalidates the signature
- **delegation chains** where a child can never exceed its parent
- a **hash-chained receipt** for every call, allowed *and* refused
- a **signed tool manifest**, so a lookalike tool injected at runtime fails the diff

The result is a refusal that isn't a judgement call. It's a failed signature or an uncovered scope. **There is no prompt that produces a valid signature.**

The demo is a business ledger — real invoices, real money — plus two demos built to be checked rather than believed:

- **`/compare`** runs one compromised agent's four hostile actions against two identical copies of the books, one guarded and one wired straight to its handlers the way most apps ship. **4 of 4 succeed unguarded. 0 of 4 guarded.** $2,750 moved versus nothing — and 0 receipts versus 4, meaning the unguarded side keeps no record it happened.
- **`/verify`** shows the real grant, receipt chain and manifest in an editable box. Rewrite a refusal into an approval and it reports `bad-signature`. Delete a receipt and every surviving one still verifies on its own — only the chain notices the gap.

19 tools across 4 routes, including the landing page, so an agent has something to call wherever it lands.

## How we built it

The core is a canonical-JSON envelope signed with Ed25519 — keys sorted alphabetically so every SDK produces byte-identical payloads, verified by a cross-language conformance suite. Wire version `7h3/0.1`, immutable.

Around that: X25519 + ChaCha20-Poly1305 for E2E encryption, ML-DSA (FIPS 204) for post-quantum signatures, BLS12-381 for M-of-N threshold signing, and bindings for HTTP, WebSocket, gRPC, message queues and webhooks. TypeScript, Python, Rust and Go SDKs. Web Crypto only, zero runtime dependencies, so it runs natively on Cloudflare Workers.

The WebMCP layer is a thin guard over that foundation. Delegation is the piece I'd call out — a chain's effective ceiling is the minimum across every link, never just the leaf:

$$\text{cap}_{\text{effective}}(f) = \min_{t \in \text{chain}} \text{cap}_t(f)$$

which is the difference between delegation and privilege escalation, and I know that because I shipped it wrong first.

## Challenges we ran into

I ran five adversarial passes over my own code and found **13 real defects**. Three are worth telling you about.

**The one that scared me.** Queue verification returned the wrong field. The signature covered `envelope.body.content`, but the verifier handed back the sibling `payload` — which nothing signed. I demonstrated it end to end: a message signed as `{"job":"reindex","amount":10}` verified successfully and returned `{"job":"DROP TABLE users","amount":1000000000}`. A valid signature on content nobody ever checked. It was present in TypeScript, Python *and* Rust, because I'd made the same mistake three times in three languages.

**The one that taught me the most.** I published two packages that were completely broken — `ERR_MODULE_NOT_FOUND` on import — while every unit test passed. Vitest resolves extensionless ESM specifiers; Node does not. My tests were never testing what users install. The fix wasn't the missing `.js` extensions, it was structural: every multi-file package now has a test that packs it, installs the tarball, and imports it under plain Node. I verified each one **fails against its own broken build** before trusting it. A check you've never seen fail isn't a check.

**The one hiding in plain sight.** My README claimed the audit log was "signed and chained." It was signed. It wasn't chained. Entries were independently signed, which detects modification but not *deletion* — an attacker who could write to the log could remove entries and every survivor still verified perfectly. That's exactly why receipts here carry `prevHash`, and it's the single most useful thing on the `/verify` page: delete a receipt, and each remaining one still passes on its own. Only the chain notices.

There was also a full day lost to a Rust fix that was correct the entire time and looked broken because of a stale incremental build artifact. `cargo clean` and it passed immediately. And a bug I'd fixed a month earlier came back in a doc rewrite, which is its own lesson about where regressions actually live.

## What we learned

**Probabilistic defenses and boundaries are different things.** A classifier that's 99% accurate against prompt injection is a filter. It is not a boundary, because the attacker gets unlimited attempts and only needs one. A signature check is 100% or it's broken — and if it's broken, it's broken deterministically, which means a test can catch it.

**Test what you ship, not what you wrote.** Two packages went out broken with a green test suite. The gap between "my tests pass" and "this works when installed" was where the real bug lived.

**Write the threat model down, then audit yourself against it.** Both my worst findings were places where documentation described a stronger property than the code implemented. The docs weren't lying — they were describing what I *intended*. Reading them adversarially against the implementation is what found the gap.

**Ship the counterfactual.** "The app refused it" is unconvincing on its own; it reads as the app just saying no. Running the identical attack against an unguarded copy is what makes the refusal mean something — and building that comparison taught me more about what I'd actually built than any amount of writing about it.

## What's next

Native ML-DSA grants for WebMCP, so browser tool calls are post-quantum end to end. Threshold-signed grants, where high-value tools need M-of-N approvers rather than one. A shared receipt format agents can present across origins — proof of what they were authorized to do somewhere else.

And I'd like to see the manifest idea standardized. Signing your tool surface at deploy time is a small amount of work that makes an entire class of attack loud instead of silent, and it shouldn't require adopting my library to get.

Every package is on npm, PyPI and crates.io today. 776 tests. Zero runtime dependencies.

**WebMCP gives agents hands. This gives those hands a signature, a scope, and a receipt.**
