# 7h3 Protocol AIP Rust SDK

Reference `7h3/0.1` SDK in Rust (crate `protocol-7h3`) with shared conformance fixtures.

## Included

- deterministic canonicalization matching TypeScript behavior
- HS256 HMAC signing and verification
- ED25519 signing and verification
- compact wire encode/decode
- envelope validation helpers (version, required fields, TTL)
- JSON-RPC bridge helpers for TASK/RESULT mapping
- line-based MCP-style gateway runtime over signed 7h3 envelopes
- conformance tests using `conformance/7h3_v0_1.json`

## Run tests

```bash
cargo test --manifest-path sdk/rust/Cargo.toml
```

## Run MCP-style gateway CLI

```bash
cargo run --manifest-path sdk/rust/Cargo.toml --bin aip_mcp_gateway
```

Optional env vars:

- `AIP_SHARED_SECRET` (default `mcp-gateway-secret`)
- `AIP_ALLOWED_METHODS` (comma-separated allowlist)
