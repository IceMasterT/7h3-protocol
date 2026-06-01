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
| Replay / duplicate execution | `(sender, messageId, nonce)` replay cache + TTL |
| Spoofed responses | The client verifies the server's signature on every response |
| Compromised key still in use | Compose `withRevocationCheck` into `receive.signatureResolver` |

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
when you need to manage the transport send yourself.

## Composes with the rest of the stack

The `receive` field is a full `ReceiveEnvelopeOptions`, so the wrapper inherits
everything the transport pipeline offers:

- **Fleet-wide replay** — pass a `DistributedReplayCache(createRedisReplayStore(...))`.
- **Key revocation** — set `receive.signatureResolver = withRevocationCheck(resolver, revocationStore)`.
- **Ed25519** — sign with `signEnvelopeEd25519` and resolve material via `signatureResolver`.
- **Clock skew / TTL / telemetry** — `maxClockSkewMs`, `telemetry`, etc.

## Notes

- Both peers must be wrapped: the on-wire message is an AIP envelope, not plain
  JSON-RPC. For interop with un-wrapped MCP peers, terminate AIP at a gateway.
- `wireFormat` defaults to `compact`; use `binary` for the highest-throughput lanes.
- Verification failures and replays come back as signed JSON-RPC errors
  (`-32600`), so the client still gets an authenticated, well-formed response.
