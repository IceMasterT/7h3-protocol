# Step-up approval and provenance

Two features for the same problem: an agent that is *allowed* to do something can
still be *tricked* into doing it. A capability token bounds what an agent may do.
These two add a human-in-the-loop check for the cases where the bound is not
enough, and a signed record of where the inputs to an action came from.

Status: TypeScript reference implementation (`@7h3/protocol`). The Python, Rust
and Go SDKs do not implement these yet.

## What they do, and what they do not

**They do not detect prompt injection.** Nothing here inspects content. A
provenance claim is a label the *sender's runtime* asserts and signs. The value is
that the label cannot be altered or moved to another action in transit, the sender
is accountable for it, and a gateway can enforce policy on it.

**The label is only as good as the taint tracking behind it.** It must be produced
by deterministic code that sees the data flow, never by the model. A model that can
write its own label can write `"trusted"`. Use `ProvenanceContext` in the agent
harness: register every input as it enters the context, and read the sources when
the action is sent.

## Approval grant

A named approver countersigns **one specific action**.

| Bound to | Effect |
|---|---|
| `subject` | The grant authorizes one agent; it cannot be lent to another. |
| `method` + normalized `path` + SHA-256 of the body | It cannot be reused for another route, verb or amount. |
| `expiresAt` (max 10 minutes) | Approvals are acted on now, not stockpiled. |
| a `ReplayStore` | Single use. |

Also enforced: an agent can never approve itself; approvers are a separate key
registry from agents (being a registered agent never implies being an approver);
and a request that fails any check does **not** consume the grant, so an
interceptor cannot burn a legitimate approval by presenting it with a different body.

```ts
import { bindAction, issueApproval, serializeApproval, APPROVAL_HEADER } from '@7h3/protocol'

// On the approver's side, after a human reviewed the action:
const action = await bindAction({ method: 'POST', path: '/api/payments', body: '{"amount":5000}' })
const grant = await issueApproval({
  approverPrivateKey, approverId: 'alice', subject: 'agent.worker', action,
  ttlMs: 120_000, reason: 'invoice #442',
})
// The agent sends it alongside the request:
headers[APPROVAL_HEADER] = serializeApproval(grant)
```

## Provenance claim

```ts
import { ProvenanceContext, signProvenance, serializeProvenance, PROVENANCE_HEADER } from '@7h3/protocol'

const ctx = new ProvenanceContext()
ctx.add({ kind: 'user', id: 'owner', trust: 'trusted' })
ctx.add({ kind: 'email', id: 'msg-123', trust: 'untrusted' }) // read a stranger's email

const claim = await signProvenance({ senderPrivateKey, sender: 'agent.worker', action, sources: ctx.sources() })
headers[PROVENANCE_HEADER] = serializeProvenance(claim)
```

Trust is derived: `trusted` only when there is at least one source and all are
trusted. No sources is `untrusted` — unknown is not clean. A claim may not label
itself cleaner than its own sources, and removing an untrusted source breaks the
signature.

Verification **fails closed**: a missing, malformed, expired, mis-bound or badly
signed claim counts as untrusted.

## Enforcing it at the gateway

```ts
const gateway = createGateway({
  upstream, keyRegistry, replayStore,
  approverRegistry,                       // separate from keyRegistry
  approvalReplayStore,                    // defaults to replayStore, then in-memory
  policies: [
    // Human approval only when untrusted input fed the action:
    { path: '/api/payments', require: 'ed25519',
      approval: { require: 'untrusted', approvers: ['alice', 'bob'] } },
    // Human approval for every call:
    { path: '/api/admin/**', require: 'ed25519',
      approval: { require: 'always', approvers: ['alice'] } },
  ],
})
```

| Outcome | Response |
|---|---|
| No valid approval when one is needed | `403 approval-required`, with `detail.action` (the exact `{method, path, bodySha256}` to sign), `detail.approvers`, `detail.trust` |
| A presented grant fails | `403 approval-invalid:<reason>` (`action-mismatch`, `subject-mismatch`, `expired`, `already-used`, `invalid-signature`, …) |
| Approved | Forwarded with `x-7h3-approved-by: <approver>` and `x-7h3-trust: trusted\|untrusted` |

A misconfigured approval policy (no `approverRegistry`, empty `approvers`, or
`require: 'none'`) throws when the gateway is created.

### Gateway-owned headers

`x-7h3-sender`, `x-7h3-verified`, `x-7h3-approved-by`, `x-7h3-trust` and
`x-7h3-approval` are set by the gateway only. Anything a client sends under those
names (any case) is dropped before forwarding. Before this change a caller could
send `x-7h3-verified: true` to a route with `require: 'none'` and have it reach the
upstream unchanged.

## Operating notes

- Give a multi-instance gateway a shared `approvalReplayStore` (Redis, KV, Durable
  Object). The in-memory default is per process and lost on restart.
  `MemoryReplayStore` fails closed at capacity: when full of live keys it reports
  new keys as replays rather than evicting one an attacker could then reuse.
- Approval UX (showing a human the action and collecting a decision) is out of
  scope. The `approval-required` response carries everything a reviewer tool needs.
- A provenance claim is replayable within its (max 5 minute) lifetime, but only for
  the identical action it is bound to, and the request must still carry a valid
  signature and clear every other gate.
