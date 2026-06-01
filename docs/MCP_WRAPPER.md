# MCP Hardening Wrapper

MCP messages are plain JSON-RPC 2.0 with no signature and no replay protection.
This wrapper puts a signed AIP envelope around every MCP message on the wire —
authenticating it, TTL-bounding it, and replay-checking it — **without changing
your MCP handler**. Your handler still receives plain JSON-RPC `{ method, params }`
and returns plain results; AIP lives entirely on the wire.

Source: `src/mcpWrapper.ts`. Runnable demo: `npm run aip:mcp:wrap`.

## Threat coverage

| Threat | Covered by |
|---|---|
| Message tampering (params/method altered in flight) | Canonical signature over the envelope (HS256 / Ed25519) |
| Replay / duplicate execution | `(sender, messageId, nonce)` replay cache + TTL; **on by default** (`InMemoryReplayCache` if none supplied) |
| Cross-server relay (valid envelope for server A replayed to server B) | **Recipient binding** — the server runs the handler only when `recipient === selfAgentId` |
| Response spoofing (another valid signer answers) | **Sender binding** — the client accepts a response only when `sender === peerAgentId` (peerAgentId is required) |
| Response substitution (a valid response to request A returned for request B) | **Correlation binding** — the client requires `correlationId === the request's messageId` |
| Compromised key still in use | Compose `withRevocationCheck` into `receive.signatureResolver` |

`encodeRequest` returns `{ raw, messageId }`; pass `messageId` to `decodeResponse(raw, { expectCorrelationId })` to enforce the correlation binding (`wrapMcpClient` does this for you).

## Server side — wrap an existing handler

```ts
import { wrapMcpServer, signEnvelopeHmac } from '@7h3/protocol'
import { DistributedReplayCache, createRedisReplayStore } from '@7h3/protocol'

// Your existing MCP handler — unchanged, AIP-unaware.
async function myMcpServer(request) {
  if (request.method === 'tools/call') return { jsonrpc: '2.0', id: request.id, result: runTool(request.params) }
  return { jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'Method not found' } }
}

const secured = wrapMcpServer(myMcpServer, {
  selfAgentId: 'agent.mcp-server',
  sign: (e) => signEnvelopeHmac(e, process.env.AIP_SECRET!, 'server-k1'),
  receive: {
    secretResolver: async () => process.env.AIP_SECRET!,
    replayCache: new DistributedReplayCache(createRedisReplayStore(redisLikeClient)), // fleet-wide replay
  },
})

// `secured(rawWireEnvelope) => Promise<rawWireEnvelope>` — drop it into your stdio/HTTP transport read loop.
```

## Client side — sign requests, verify responses

```ts
import { wrapMcpClient, signEnvelopeHmac } from '@7h3/protocol'

const call = wrapMcpClient(transport.send /* (raw) => Promise<raw> */, {
  selfAgentId: 'agent.mcp-client',
  peerAgentId: 'agent.mcp-server',
  sign: (e) => signEnvelopeHmac(e, process.env.AIP_SECRET!, 'client-k1'),
  receive: { secretResolver: async () => process.env.AIP_SECRET! },
})

const result = await call({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'planner' } })
// throws if the server response signature does not verify
```

`createMcpClientCodec(options)` exposes `encodeRequest` / `decodeResponse` directly
when you manage the transport send yourself. `encodeRequest` returns
`{ raw, messageId }`; pass that `messageId` as `decodeResponse(raw, { expectCorrelationId })`
to bind each response to its request. `peerAgentId` is required so responses can be
bound to the expected sender.

## Composes with the rest of the stack

The `receive` field is a full `ReceiveEnvelopeOptions`, so the wrapper inherits
everything the transport pipeline offers:

- **Fleet-wide replay** — pass a `DistributedReplayCache(createRedisReplayStore(...))`.
- **Key revocation** — set `receive.signatureResolver = withRevocationCheck(resolver, revocationStore)`.
- **Ed25519** — sign with `signEnvelopeEd25519` and resolve material via `signatureResolver`.
- **Clock skew / TTL / telemetry** — `maxClockSkewMs`, `telemetry`, etc.

## Transports

The wrapper is transport-agnostic (it operates on wire envelopes). Two adapters
connect it to real transports; both keep the handler on plain JSON-RPC.

### stdio (newline-delimited)

```ts
import { wrapMcpServer, serveMcpOverStdio, createStdioMcpClient, wrapMcpClient } from '@7h3/protocol'

// server process: read envelopes from stdin, write replies to stdout
serveMcpOverStdio(wrapMcpServer(myMcpServer, serverOpts)) // defaults to process.stdin/stdout

// client process: spawn the server and talk to it
const stdio = createStdioMcpClient({ input: child.stdout, output: child.stdin })
const call = wrapMcpClient(stdio.send, clientOpts)
const result = await call({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'planner' } })
```

Stdio frames one envelope per line, so it supports the `json` and `compact` wire
formats. For `binary`, use HTTP.

### HTTP

```ts
import http from 'node:http'
import { wrapMcpServer, createHttpMcpHandler, createHttpMcpClient, wrapMcpClient } from '@7h3/protocol'

// server: any node:http-compatible host
http.createServer(createHttpMcpHandler(wrapMcpServer(myMcpServer, serverOpts))).listen(8787)

// client: POSTs each request envelope, returns the reply envelope (global fetch)
const httpClient = createHttpMcpClient({ url: 'http://localhost:8787' })
const call = wrapMcpClient(httpClient.send, clientOpts)
const result = await call({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'planner' } })
```

Pass `{ binary: true }` to both `createHttpMcpHandler` and `createHttpMcpClient`
to use the `binary` wire format over HTTP.

## Notes

- Both peers must be wrapped: the on-wire message is an AIP envelope, not plain
  JSON-RPC. For interop with un-wrapped MCP peers, terminate AIP at a gateway.
- `wireFormat` defaults to `compact`; use `binary` for the highest-throughput lanes.
- Verification failures and replays come back as signed JSON-RPC errors
  (`-32600`), so the client still gets an authenticated, well-formed response.
