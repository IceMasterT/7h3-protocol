# Install: MCP server

Gives an AI coding agent 7h3 tooling directly — key generation, signing,
verification and scaffolding.

## Claude Code

```bash
claude mcp add 7h3-protocol -- npx -y @7h3/protocol-mcp
```

## Any MCP client (config file)

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

Generate the exact config for a specific client:

```bash
npx 7h3 add --framework claude-code   # or codex, opencode, grok
```

Or ask the server itself, once connected: `7h3_mcp_config`.

## Tools

| Tool | What it does |
|---|---|
| `7h3_generate_keypair` | Ed25519 keypair (PKCS8/SPKI, base64url) |
| `7h3_generate_secret` | 32-byte HMAC secret |
| `7h3_sign` | Sign a test envelope for debugging or fixtures |
| `7h3_verify` | Verify signature, TTL and shape |
| `7h3_scaffold` | Integration code for a framework |
| `7h3_mcp_config` | Install config for Claude Code, Cursor, Opencode, Codex, Grok |
| `7h3_wrap_mcp_server` | Boilerplate to wrap an MCP handler with 7h3 |

## Scaffolding

```
7h3_scaffold framework="webmcp"            sender="shop.example"
7h3_scaffold framework="cloudflare-worker" sender="agent@example.com" signingMethod="ed25519"
7h3_scaffold framework="nextjs"            sender="agent@example.com"
7h3_scaffold framework="express"           sender="agent@example.com"
```

Every generated target is syntax-checked in CI, and user-supplied values are
escaped before interpolation.

## Hardening your own MCP server

`7h3_wrap_mcp_server` generates boilerplate that puts signature verification in
front of an existing JSON-RPC handler, so only signed, unexpired, non-replayed
calls reach your logic. See [`docs/MCP_WRAPPER.md`](../MCP_WRAPPER.md).

## Using ChatGPT?

See **[the ChatGPT guide](./chatgpt.md)** — it covers this server *and* site
tools in the built-in browser, which are different integrations.
