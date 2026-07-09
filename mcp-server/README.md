# @7h3/protocol-mcp

MCP server for [@7h3/protocol](https://github.com/IceMasterT/7h3-protocol) — install into Claude to generate 7h3 secrets, keypairs, and server boilerplate.

## Install into Claude Code

```bash
claude mcp add aip -- npx @7h3/protocol-mcp
```

## Install into Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aip": {
      "command": "npx",
      "args": ["@7h3/protocol-mcp"]
    }
  }
}
```

## Tools

| Tool | What it does |
|---|---|
| `aip_generate_secret` | Generates a 32-byte HMAC secret — store as `AIP_SECRET` |
| `aip_generate_keypair` | Generates an Ed25519 keypair — store keys as env vars |
| `aip_wrap_mcp_server` | Outputs ready-to-paste boilerplate for your MCP server |
| `aip_sign` | Signs a test envelope (debugging / fixture generation) |
| `aip_verify` | Verifies an envelope signature and shape |

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

`SPDX-License-Identifier: Apache-2.0`
