# Install: CLI

The CLI ships with `@7h3/protocol`, so no separate install is needed.

```bash
npx 7h3 help
```

Or install globally:

```bash
npm install -g @7h3/protocol
7h3 help
```

## Commands

```
7h3 keygen  [--output <file>]
7h3 sign    --private-key <key> --sender <id> [--recipient <id>] [--payload <str>] [--ttl <ms>]
7h3 verify  --public-key <key> --envelope <json>
7h3 inspect --envelope <json>
7h3 gateway --upstream <url> [--port <n>] [--public-key <key>] [--require ed25519|none]
            [--sign-responses] [--private-key <key>] [--sender <id>] [--metrics-port <n>]
            [--allow-unverified]
7h3 keys serve [--public-key <key>] [--key-id <id>] [--port <n>]
7h3 add     --framework <name> [--sender <id>] [--output <dir>]
7h3 help
```

## Generate a keypair

```bash
npx 7h3 keygen --output keys.json
```

Ed25519, PKCS8/SPKI, base64url-encoded.

## Handling secrets

`--private-key` is **visible in shell history and process listings**. Prefer
either of these:

```bash
npx 7h3 sign --private-key-file ./key.txt --sender agent@example.com
P7H3_PRIVATE_KEY=... npx 7h3 sign --sender agent@example.com
```

For the gateway, the env var is `GATEWAY_PRIVATE_KEY`.

## Run a verifying gateway

```bash
npx 7h3 gateway --upstream http://localhost:3000 --port 8080 --require ed25519
```

The gateway **refuses to start** as an unverified passthrough. If you genuinely
want to proxy without verification, you must say so explicitly:

```bash
npx 7h3 gateway --upstream http://localhost:3000 --allow-unverified
```

## Serve a key-discovery endpoint

```bash
npx 7h3 keys serve --public-key "$PUBLIC_KEY" --key-id k1 --port 8081
```

Serves `/.well-known/7h3-keys` so peers can fetch your public key.

## Scaffold an integration

```bash
npx 7h3 add --framework webmcp --sender shop.example
```

Available frameworks:

```
webmcp   cloudflare-worker   nextjs   express   hono
fastify  claude-code         opencode codex     grok
```

Write it straight to disk with `--output <dir>`.
