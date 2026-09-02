# Install: ChatGPT

There are **two different integrations**, and they solve different problems.
You can use either or both.

| | [Site tools (WebMCP)](#a-site-tools-webmcp) | [MCP server](#b-mcp-server-for-codex) |
|---|---|---|
| Where it runs | Your web page, in ChatGPT's built-in browser | ChatGPT Codex, no page required |
| Agent sees | The same live, signed-in page you see | Tools that work independently of any page |
| Install | Ship JS on your site | One command |
| Use it when | You and the agent need to look at the same thing | The agent needs 7h3 keys, signing, or scaffolding |

---

## A. Site tools (WebMCP)

ChatGPT's built-in browser implements the proposed WebMCP standard as **site
tools**. Your page offers actions; the agent discovers and calls them.

### Requirements

- **ChatGPT desktop app**, updated to the latest version
- **GPT-5.6 Sol** or **GPT-5.6 Terra** — *Luna has WebMCP disabled*
- Not available in **Enterprise** or **Edu** workspaces
- Your site must be served over **HTTPS**
- Tools must be registered in the **top-level page** — tools inside an iframe
  are not discoverable
- The declarative HTML-form API is **not** supported; use JavaScript

### Install

Follow **[the WebMCP guide](./webmcp.md)** to add signed, capability-scoped
tools to your site. The short version:

```bash
npx 7h3 add --framework webmcp --sender your-origin.example
```

### Verify it works

1. Open your site in the ChatGPT desktop app's built-in browser.
2. Click **Site tools** in the address bar.
3. Expand **Available site tools** — you should see your tools, counted as
   read vs write (driven by `annotations.readOnlyHint`).
4. Ask the agent to do something. Then ask it to do something it has no grant
   for, and watch it get refused.

If tools don't appear: check you're on Sol or Terra, that the page is HTTPS,
that registration happened in the top-level document, and that
`Settings → Browser → Permissions → Enable site tools` is on.

### Why bother signing them

ChatGPT reviews each invocation before it runs and ties it to the originating
page. But its own documentation is explicit:

> Website-provided tool definitions and results are untrusted content.
> **A tool's name or claim that it only reads data isn't proof of what it does.**

and it tells sites to use *"your application's existing authentication,
authorization, and input validation"* — which, for delegated agent action, most
sites simply do not have. That is the gap [the WebMCP guide](./webmcp.md)
fills.

---

## B. MCP server (for Codex)

The MCP server gives an agent 7h3 tooling directly — key generation, signing,
verification, and scaffolding — without needing a page open.

### Install

```bash
npx -y @7h3/protocol-mcp
```

Register it with your MCP client. For ChatGPT Codex, add to your MCP config:

```json
{
  "mcpServers": {
    "7h3-protocol": {
      "command": "npx",
      "args": ["-y", "@7h3/protocol-mcp"]
    }
  }
}
```

Generate the exact config for your client:

```bash
npx 7h3 add --framework codex
```

### Tools it provides

| Tool | What it does |
|---|---|
| `7h3_generate_keypair` | Ed25519 keypair (PKCS8/SPKI, base64url) |
| `7h3_generate_secret` | 32-byte HMAC secret |
| `7h3_sign` | Sign a test envelope |
| `7h3_verify` | Verify signature, TTL and shape |
| `7h3_scaffold` | Integration code for a framework — including `webmcp` |
| `7h3_mcp_config` | Install config for other MCP clients |
| `7h3_wrap_mcp_server` | Boilerplate to wrap an MCP handler with 7h3 |

Scaffold a signed WebMCP surface straight from the agent:

```
7h3_scaffold framework="webmcp" sender="shop.example"
```

See **[the MCP server guide](./mcp-server.md)** for other clients.

---

## Which do I need?

- **Building a website an agent should operate** → site tools (WebMCP).
- **Want an agent to help you build with 7h3** → MCP server.
- **Both** → they're independent; install each.
