# Clean Clone Runbook

Use this to verify deterministic setup from a fresh checkout.

## TypeScript path

```bash
git clone https://github.com/IceMasterT/GLUV-Protocol.git
cd GLUV-Protocol
npm install
npm run lint
npm run test
npm run build
```

## Conformance path

```bash
npm run conformance:python
npm run conformance:rust
```

## Quickstart path

```bash
npm run aip:quickstart
npm run aip:framework:quickstart
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"planner"}}' | npm run aip:mcp:gateway
```

## Rust gateway path

```bash
cargo test --manifest-path sdk/rust/Cargo.toml
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"planner"}}' | cargo run --manifest-path sdk/rust/Cargo.toml --bin aip_mcp_gateway
```
