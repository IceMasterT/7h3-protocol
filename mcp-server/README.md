# @7h3/protocol-mcp

MCP server for [@7h3/protocol](https://github.com/IceMasterT/7h3-protocol) — install into Claude to generate 7h3 secrets, keypairs, and server boilerplate.

## Install into Claude Code

```bash
claude mcp add 7h3-protocol -- npx @7h3/protocol-mcp
```

## Install into Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "7h3-protocol": {
      "command": "npx",
      "args": ["@7h3/protocol-mcp"]
    }
  }
}
```

Run the `7h3_mcp_config` tool for ready-to-paste config for Claude Code, Cursor, or Opencode.

## Tools

| Tool | What it does |
|---|---|
| `7h3_generate_secret` | Generates a 32-byte HMAC secret — store as `P7H3_SECRET` |
| `7h3_generate_keypair` | Generates an Ed25519 keypair — store as `P7H3_PRIVATE_KEY` / `P7H3_PUBLIC_KEY` |
| `7h3_wrap_mcp_server` | Outputs ready-to-paste boilerplate wrapping an existing MCP server handler |
| `7h3_sign` | Signs a test envelope (debugging / fixture generation) |
| `7h3_verify` | Verifies an envelope signature and shape |
| `7h3_scaffold` | Generates integration code for a target framework (Cloudflare Worker, Next.js, Express, Hono, Fastify, Claude Code, raw) |
| `7h3_mcp_config` | Outputs install config/commands for Claude Code, Cursor, Opencode, or npx |

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

`SPDX-License-Identifier: Apache-2.0`
