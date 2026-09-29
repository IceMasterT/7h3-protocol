# MCP tool pinning and signed SSE streams

Two additions to the MCP hardening in [`MCP_WRAPPER.md`](./MCP_WRAPPER.md), for
problems message signing alone does not solve.

Status: TypeScript reference implementation (`@7h3/protocol`).

## Tool pinning

### The threat

An MCP client shows the model, and usually a human, each tool's `description` and
`inputSchema`. Those strings are instructions to the model. Two attacks use them:

- **Rug pull.** A server ships benign text, gets approved, then changes it. Every
  message is still correctly signed by the server you chose to trust.
- **Tool poisoning by hidden text.** Instructions are placed in the description in
  characters a human reviewer cannot see (zero-width characters, Unicode "tag"
  characters, bidirectional overrides). The model reads them; the reviewer does not.

### What is implemented

1. **Pin.** Each approved tool is recorded as the SHA-256 of everything the model can
   read about it: name, title, description, input and output schema, annotations.
   Any later difference, including one word or a schema default, makes it a *changed*
   tool. Fields the model does not read (`_meta`, icons) are not part of the digest.
2. **Scan.** Tool text, at any depth of a schema and in property names, is refused if
   it contains invisible, direction-overriding, control or Unicode tag characters, or
   is oversized. That is a mechanical property, not a judgement about meaning.
3. **Enforce.** `guardMcpClient` wraps the client call function:
   - `tools/list` results are filtered: changed, suspicious, duplicate-named and (by
     default) unpinned tools are removed before the caller sees them.
   - `tools/call` for anything not currently verified is refused with JSON-RPC error
     `-32001 tool-blocked`, without being forwarded. If the last verification is older
     than `maxListAgeMs` (default 30 s), the guard re-lists (all pages) and
     re-verifies first. If the list cannot be verified, calls fail closed.
   - Two tools with one name are both blocked: that is how a hostile server shadows a
     trusted tool.

```ts
import { pinTools, signToolPins, verifyToolPins, ToolGuard, guardMcpClient } from '@7h3/protocol'

// Once, after a human reviewed the server's tools:
const pins = await pinTools('https://mcp.example.com', reviewedTools, { approvedBy: 'alice' })
const signed = await signToolPins(pins, { privateKey, keyId: 'security-team' }) // distribute this

// In the client:
const verified = await verifyToolPins(signed, { publicKey, expectedServer: 'https://mcp.example.com' })
if (!verified.ok) throw new Error(verified.reason)
const guard = new ToolGuard(verified.set)
const { call, invalidate } = guardMcpClient(rawCall, guard, { onBlocked: (v) => log(v) })
// Call invalidate() when the server sends notifications/tools/list_changed.
```

### What it does not do

- It does not judge visible text. A poisoned description written in plain sight is
  caught only because it differs from the pin a human approved, so **approving the
  pin set is the trust decision.**
- Within `maxListAgeMs` a description change is not seen until the next
  verification. Set `maxListAgeMs: 0` to re-verify before every call, at the cost of
  a `tools/list` round trip per call.
- `allowUnpinned: true` is trust-on-first-use: new tools are still scanned and are
  pinned as they appear, and later changes to them are caught, but the first
  appearance is not reviewed.
- Pins are per server: a pin set for one server identity never applies to another.

## Signed SSE for streamable HTTP

### The threat

MCP servers stream JSON-RPC messages to the client as Server-Sent Events. Signing each
message is not enough for a stream. A party on the path can still drop events,
reorder them, replay old ones, splice in events from another stream, or cut the stream
short so the client believes it finished.

### What is implemented

Each SSE event carries one signed 7h3 envelope. The signed content is
`{ stream, seq, message }`, and the reader enforces:

| Property | How |
|---|---|
| Authenticity | Every event is signed by the peer; unsigned, forged or altered events are rejected. A caller cannot switch signature checking off. |
| Order and completeness | `seq` must be exactly 0, 1, 2, … A gap, repeat or reorder is rejected. |
| Stream binding | The stream id is signed, so events cannot be spliced in from another stream; sender and recipient are checked; the stream id and correlation id can be pinned. |
| Replay | The normal nonce and TTL replay cache applies to every event. |
| Termination | The stream ends with a signed `end` event carrying the message count. A body that stops without it is reported as `stream-truncated`. |

The SSE framing (`id:`, `event:`, `retry:`, comments) is not signed and is never
trusted. Keep-alive comments are ignored. After the first violation the reader
refuses to continue.

```ts
// Server
const w = new SignedSseWriter({ selfAgentId, peerAgentId, sign, correlationId: requestMessageId })
res.writeHead(200, signedSseHeaders())
res.write(await w.message({ jsonrpc: '2.0', method: 'notifications/progress', params }))
res.write(await w.message(finalResult))
res.end(await w.end())

// Client
for await (const { message } of readSignedSse(response.body, {
  selfAgentId, peerAgentId, receive: { signatureResolver }, expectCorrelationId: requestMessageId,
})) handle(message)
// readSignedSse throws SseVerificationError('stream-truncated') if the body ends early.
```

Not supported: resuming with `Last-Event-ID`. A resumed stream cannot prove it has no
gap, so a reconnect must open a new stream (new stream id) and re-request.
