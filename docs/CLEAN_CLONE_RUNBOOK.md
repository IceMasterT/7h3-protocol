# Clean Clone Runbook

Use this to verify deterministic setup from a fresh checkout.

## TypeScript path

```bash
git clone https://github.com/IceMasterT/7h3-protocol.git
cd 7h3-protocol
npm run install:all
npm run lint
npm run test
npm run build:protocol
```

The `sdk/pq` and `sdk/threshold` optional SDKs have their own lockfiles and are
not covered by a plain root `npm install` — `install:all` restores them too, or
the root test suite will fail to resolve `@noble/post-quantum` and `@noble/curves`
imports. (`install:all` runs `npm install` before restoring the subpackages, so
there's no need to run `npm install` separately first.)

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
