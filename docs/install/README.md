# Installing 7h3 Protocol

Pick the surface you're integrating. Every command and code sample in these
guides was executed against this repository before being written down.

> **Want to see it before installing anything?**
> <https://7h3-webmcp-ledger.tech-b1a.workers.dev> is a live WebMCP app —
> **19 tools across four routes** on `document.modelContext`, drivable from
> ChatGPT's built-in browser or Chrome 149+.
> [Testing walkthrough →](../TESTING.md)

## Agent-facing

| Guide | For |
|---|---|
| **[WebMCP](./webmcp.md)** | Browser agents calling your page's tools. Capability-scoped, replay-protected, receipted. |
| **[ChatGPT](./chatgpt.md)** | Both paths: site tools in ChatGPT's built-in browser, and the MCP server for Codex. |
| **[MCP server](./mcp-server.md)** | Claude Code, Cursor, Windsurf, and any other MCP client. |

## Language SDKs

| Guide | Package | Registry |
|---|---|---|
| **[TypeScript / Node](./typescript.md)** | `@7h3/protocol` | npm |
| **[Python](./python.md)** | `7h3-protocol` | PyPI |
| **[Rust](./rust.md)** | `protocol-7h3` | crates.io |
| **[Go](./go.md)** | `github.com/IceMasterT/7h3-protocol/sdk/go` | Go modules |
| **[Browser](./browser.md)** | `@7h3/protocol-browser` | npm |

## Runtimes and tooling

| Guide | For |
|---|---|
| **[CLI](./cli.md)** | `npx 7h3` — keygen, sign, verify, gateway, scaffolding. |
| **[Cloudflare Workers](./cloudflare.md)** | Reverse-proxy gateway and drop-in middleware. |
| **[Docker](./docker.md)** | Running the gateway as a container. |

## Optional add-ons

| Guide | For |
|---|---|
| **[Post-quantum](./post-quantum.md)** | ML-DSA (NIST FIPS 204) signatures. |
| **[Threshold signatures](./threshold.md)** | BLS12-381 M-of-N signing. |

---

## The 30-second version

```bash
npm install @7h3/protocol
npx 7h3 keygen --output keys.json
```

```ts
import { createEnvelope, signEnvelopeEd25519, verifyEnvelopeEd25519 } from '@7h3/protocol'

const envelope = createEnvelope({ sender: 'agent@example.com', intent: 'TASK', content: 'hello' })
const signed = await signEnvelopeEd25519(envelope, privateKey, 'k1')
await verifyEnvelopeEd25519(signed, publicKey)   // → true
```

## Wire compatibility

The wire version is **`7h3/0.1`** and is immutable. Every SDK produces
byte-identical canonical payloads, so an envelope signed by any one of them
verifies under all the others. Cross-language conformance runs in CI against
shared fixture vectors.
