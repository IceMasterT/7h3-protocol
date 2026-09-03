**Yes, this builds on an existing project, and everything WebMCP is new.**

7h3 Protocol has been in development since May 2026 as a signing and replay-protection layer for agent-to-agent messages over HTTP, WebSocket, gRPC, queues and webhooks. At the start of the submission period it was at **v0.5.6**, and none of it touched the browser. It had no concept of WebMCP, no tool guard, no capability grants scoped to tool calls, no receipts, and no manifest.

**Built during the submission period:**

- **`@7h3/protocol-webmcp`**, an entirely new package. This is the whole WebMCP contribution: `guard.registerTool()` wrapping `document.modelContext.registerTool`, capability grants scoped per tool with ceilings bound inside the signed token, delegation chains, hash-chained receipts for allowed and refused calls alike, and signed tool manifests with runtime diffing to catch injected lookalike tools.
- **The live demo**, all four routes: the hub, the Ledger console, the side-by-side attack comparison, and the verification page. 19 WebMCP tools registered across them.
- **`@7h3/protocol-browser`**, finished and published so the browser SDK reaches full parity with the core.
- **13 security fixes to the pre-existing core**, found by adversarially auditing my own code once the WebMCP work made me look at it harder. The most serious was a queue verification bypass where the signature covered one field and the verifier returned a different, unsigned one, present in the TypeScript, Python and Rust SDKs. Also a privilege escalation in delegation chains, a capability-scope glob that matched too broadly, silent key corruption in threshold splitting, and an audit log the documentation called "chained" that was only signed.
- **Packaging and release integrity work.** Two packages went out broken with a green test suite, because Vitest resolves extensionless ESM specifiers and Node does not. Every multi-file package now has a test that packs it, installs the tarball and imports it under plain Node.

That is 24 commits, roughly 8,400 new lines across the WebMCP package and demo, plus 621 lines of fixes to the existing core. Version went 0.5.6 to 0.6.3, and the test suite grew to 776 across TypeScript, Python, Rust and Go.

**What was reused:** the canonical-JSON envelope, the Ed25519 signing and verification, the capability-token primitives, and the replay stores. The WebMCP guard is a new layer built on top of those, not a rename of them. The full history is public at github.com/IceMasterT/7h3-protocol, and every commit from the submission period is dated 2026-09-02 onward.
