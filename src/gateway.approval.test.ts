import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'
import { createGateway, type GatewayConfig, type GatewayRequest } from './gateway'
import { createStaticKeyRegistry } from './keyRegistry'
import { createEnvelope, generateEd25519KeypairBase64Url, signEnvelopeEd25519 } from './protocol'
import { APPROVAL_HEADER, issueApproval, serializeApproval } from './approval'
import { PROVENANCE_HEADER, serializeProvenance, signProvenance } from './provenance'
import { bindAction } from './actionBinding'
import { CAP_HEADER, issueCapabilityToken, serializeCapabilityChain } from './capability'
import { MemoryReplayStore, type ReplayStore } from './replayStores'

let agent: { publicKey: string; privateKey: string }
let alice: { publicKey: string; privateKey: string }
let mallory: { publicKey: string; privateKey: string }

const noReplay: ReplayStore = { check: async () => false }
const BODY = '{"amount":5000}'

beforeAll(async () => {
  agent = await generateEd25519KeypairBase64Url()
  alice = await generateEd25519KeypairBase64Url()
  mallory = await generateEd25519KeypairBase64Url()
})

afterEach(() => vi.unstubAllGlobals())

function stubUpstream() {
  const fetchMock = vi.fn().mockResolvedValue({
    status: 200,
    text: () => Promise.resolve('{"ok":true}'),
    headers: new Headers({ 'content-type': 'application/json' }),
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function gateway(over: Partial<GatewayConfig> = {}, require: 'always' | 'untrusted' = 'untrusted') {
  return createGateway({
    upstream: 'http://upstream',
    keyRegistry: createStaticKeyRegistry({ 'agent.worker': agent.publicKey }),
    approverRegistry: { getPublicKey: async (id) => (id === 'alice' ? alice.publicKey : null) },
    replayStore: noReplay,
    approvalReplayStore: new MemoryReplayStore(),
    defaultPolicy: 'deny',
    policies: [
      { path: '/api/payments', require: 'ed25519', approval: { require, approvers: ['alice'] } },
      { path: '/api/read', require: 'ed25519' },
      { path: '/public/**', require: 'none' },
    ],
    ...over,
  })
}

async function signedRequest(over: Partial<GatewayRequest> = {}, headers: Record<string, string> = {}): Promise<GatewayRequest> {
  const envelope = createEnvelope({ sender: 'agent.worker', intent: 'TASK', content: 'pay', ttlMs: 60_000 })
  const signed = await signEnvelopeEd25519(envelope, agent.privateKey)
  return {
    method: 'POST',
    path: '/api/payments',
    body: BODY,
    headers: { 'x-7h3-envelope': JSON.stringify(signed), ...headers },
    ...over,
  }
}

const paymentAction = () => bindAction({ method: 'POST', path: '/api/payments', body: BODY })
const approvalFor = async (over: Parameters<typeof issueApproval>[0] extends infer T ? Partial<T> : never = {}) =>
  serializeApproval(
    await issueApproval({ approverPrivateKey: alice.privateKey, approverId: 'alice', subject: 'agent.worker', action: await paymentAction(), ...over }),
  )
const provenanceHeader = async (sources: Parameters<typeof signProvenance>[0]['sources']) =>
  serializeProvenance(await signProvenance({ senderPrivateKey: agent.privateKey, sender: 'agent.worker', action: await paymentAction(), sources }))

describe('gateway construction', () => {
  it('refuses an approval policy with no approverRegistry', () => {
    expect(() =>
      createGateway({
        upstream: 'http://u',
        keyRegistry: createStaticKeyRegistry({}),
        policies: [{ path: '/x', require: 'ed25519', approval: { require: 'always', approvers: ['alice'] } }],
      }),
    ).toThrow(/approverRegistry/)
  })

  it('refuses an empty approver list and an unauthenticated route', () => {
    const base = { upstream: 'http://u', keyRegistry: createStaticKeyRegistry({}), approverRegistry: { getPublicKey: async () => null } }
    expect(() => createGateway({ ...base, policies: [{ path: '/x', require: 'ed25519', approval: { require: 'always', approvers: [] } }] })).toThrow(/non-empty/)
    expect(() => createGateway({ ...base, policies: [{ path: '/x', require: 'none', approval: { require: 'always', approvers: ['a'] } }] })).toThrow(/authenticates nobody/)
  })
})

describe("approval.require = 'always'", () => {
  it('denies with approval-required and tells the approver what to sign', async () => {
    stubUpstream()
    const res = await gateway({}, 'always').handle(await signedRequest())
    expect(res.status).toBe(403)
    const body = JSON.parse(res.body)
    expect(body.error).toBe('approval-required')
    expect(body.detail.action).toEqual(await paymentAction())
    expect(body.detail.approvers).toEqual(['alice'])
  })

  it('forwards with the approver recorded when a valid grant is presented', async () => {
    const fetchMock = stubUpstream()
    const res = await gateway({}, 'always').handle(await signedRequest({}, { [APPROVAL_HEADER]: await approvalFor() }))
    expect(res.status).toBe(200)
    const sent = fetchMock.mock.calls[0][1].headers as Record<string, string>
    expect(sent['x-7h3-approved-by']).toBe('alice')
    expect(sent[APPROVAL_HEADER]).toBeUndefined() // the grant itself is not passed upstream
  })

  it('a grant works exactly once', async () => {
    stubUpstream()
    const gw = gateway({}, 'always')
    const grant = await approvalFor()
    expect((await gw.handle(await signedRequest({}, { [APPROVAL_HEADER]: grant }))).status).toBe(200)
    const again = await gw.handle(await signedRequest({}, { [APPROVAL_HEADER]: grant }))
    expect(again.status).toBe(403)
    expect(JSON.parse(again.body).error).toBe('approval-invalid:already-used')
  })

  it('a grant for a different amount does not authorize this one, and is not burned by the attempt', async () => {
    const fetchMock = stubUpstream()
    const gw = gateway({}, 'always')
    const grant = await approvalFor()
    const tampered = await gw.handle(await signedRequest({ body: '{"amount":50000}' }, { [APPROVAL_HEADER]: grant }))
    expect(JSON.parse(tampered.body).error).toBe('approval-invalid:action-mismatch')
    expect(fetchMock).not.toHaveBeenCalled()
    expect((await gw.handle(await signedRequest({}, { [APPROVAL_HEADER]: grant }))).status).toBe(200)
  })

  it('a grant for another route or verb is refused', async () => {
    stubUpstream()
    const gw = gateway({}, 'always')
    const other = await approvalFor({ action: await bindAction({ method: 'POST', path: '/api/refunds', body: BODY }) })
    expect(JSON.parse((await gw.handle(await signedRequest({}, { [APPROVAL_HEADER]: other }))).body).error).toBe('approval-invalid:action-mismatch')
  })

  it("a grant for another agent can't be borrowed", async () => {
    stubUpstream()
    const borrowed = await approvalFor({ subject: 'agent.someone-else' })
    const res = await gateway({}, 'always').handle(await signedRequest({}, { [APPROVAL_HEADER]: borrowed }))
    expect(JSON.parse(res.body).error).toBe('approval-invalid:subject-mismatch')
  })

  it('refuses a grant signed by a non-approver, even if it names alice', async () => {
    stubUpstream()
    const forged = await approvalFor({ approverPrivateKey: mallory.privateKey })
    const res = await gateway({}, 'always').handle(await signedRequest({}, { [APPROVAL_HEADER]: forged }))
    expect(JSON.parse(res.body).error).toBe('approval-invalid:invalid-signature')
  })

  it('refuses an approver that is registered but not listed for this route', async () => {
    stubUpstream()
    const gw = gateway({ approverRegistry: { getPublicKey: async () => alice.publicKey } })
    const grant = await approvalFor({ approverId: 'bob' })
    const res = await gw.handle(await signedRequest({}, { [APPROVAL_HEADER]: grant }))
    expect(JSON.parse(res.body).error).toBe('approval-invalid:approver-not-allowed')
  })

  it('treats a garbled approval header as absent', async () => {
    stubUpstream()
    const res = await gateway({}, 'always').handle(await signedRequest({}, { [APPROVAL_HEADER]: '{not json' }))
    expect(JSON.parse(res.body).error).toBe('approval-required')
  })

  it('does not gate routes without an approval policy', async () => {
    stubUpstream()
    const res = await gateway({}, 'always').handle(await signedRequest({ path: '/api/read', method: 'GET', body: undefined }))
    expect(res.status).toBe(200)
  })

  it('a valid approval cannot stand in for authentication', async () => {
    stubUpstream()
    const res = await gateway({}, 'always').handle({
      method: 'POST',
      path: '/api/payments',
      body: BODY,
      headers: { [APPROVAL_HEADER]: await approvalFor() },
    })
    expect(res.status).toBe(401)
  })

  it('also gates the capability-token path', async () => {
    stubUpstream()
    const cap = await issueCapabilityToken({
      issuerPrivateKey: agent.privateKey,
      issuerId: 'agent.worker',
      subject: 'agent.worker',
      scopes: [{ pathGlob: '/api/payments', methods: ['POST'] }],
      ttlMs: 60_000,
    })
    const gw = gateway({ capabilityRegistry: { getPublicKey: async (id) => (id === 'agent.worker' ? agent.publicKey : null) } }, 'always')
    const headers = { [CAP_HEADER]: serializeCapabilityChain([cap]) }
    const denied = await gw.handle({ method: 'POST', path: '/api/payments', body: BODY, headers })
    expect(JSON.parse(denied.body).error).toBe('approval-required')
    const ok = await gw.handle({ method: 'POST', path: '/api/payments', body: BODY, headers: { ...headers, [APPROVAL_HEADER]: await approvalFor() } })
    expect(ok.status).toBe(200)
  })

  it('normalizes the path before binding, so /api/./payments cannot dodge or reuse a grant', async () => {
    stubUpstream()
    const gw = gateway({}, 'always')
    const res = await gw.handle(await signedRequest({ path: '/api/./payments' }, { [APPROVAL_HEADER]: await approvalFor() }))
    expect(res.status).toBe(200) // same normalized action
    const res2 = await gw.handle(await signedRequest({ path: '/api/./payments' }))
    expect(JSON.parse(res2.body).error).toBe('approval-required')
  })
})

describe("approval.require = 'untrusted'", () => {
  it('lets a request through with no human when its signed provenance is all trusted', async () => {
    const fetchMock = stubUpstream()
    const res = await gateway().handle(await signedRequest({}, { [PROVENANCE_HEADER]: await provenanceHeader([{ kind: 'user', id: 'owner', trust: 'trusted' }]) }))
    expect(res.status).toBe(200)
    expect((fetchMock.mock.calls[0][1].headers as Record<string, string>)['x-7h3-trust']).toBe('trusted')
  })

  it('requires approval when any input was untrusted', async () => {
    stubUpstream()
    const prov = await provenanceHeader([
      { kind: 'user', trust: 'trusted' },
      { kind: 'email', id: 'msg-1', trust: 'untrusted' },
    ])
    const res = await gateway().handle(await signedRequest({}, { [PROVENANCE_HEADER]: prov }))
    expect(JSON.parse(res.body)).toMatchObject({ error: 'approval-required', detail: { trust: 'untrusted' } })
  })

  it('fails closed: no provenance at all means approval is required', async () => {
    stubUpstream()
    const res = await gateway().handle(await signedRequest())
    expect(JSON.parse(res.body).error).toBe('approval-required')
  })

  it('a forged "trusted" claim does not bypass approval', async () => {
    stubUpstream()
    const forged = serializeProvenance(
      await signProvenance({
        senderPrivateKey: mallory.privateKey,
        sender: 'agent.worker',
        action: await paymentAction(),
        sources: [{ kind: 'user', trust: 'trusted' }],
      }),
    )
    const res = await gateway().handle(await signedRequest({}, { [PROVENANCE_HEADER]: forged }))
    expect(JSON.parse(res.body).error).toBe('approval-required')
  })

  it('a trusted claim for a different amount does not bypass approval', async () => {
    stubUpstream()
    const other = serializeProvenance(
      await signProvenance({
        senderPrivateKey: agent.privateKey,
        sender: 'agent.worker',
        action: await bindAction({ method: 'POST', path: '/api/payments', body: '{"amount":1}' }),
        sources: [{ kind: 'user', trust: 'trusted' }],
      }),
    )
    const res = await gateway().handle(await signedRequest({}, { [PROVENANCE_HEADER]: other }))
    expect(JSON.parse(res.body).error).toBe('approval-required')
  })

  it('an untrusted request with a valid approval goes through and is marked untrusted', async () => {
    const fetchMock = stubUpstream()
    const prov = await provenanceHeader([{ kind: 'web', id: 'https://evil.example', trust: 'untrusted' }])
    const res = await gateway().handle(await signedRequest({}, { [PROVENANCE_HEADER]: prov, [APPROVAL_HEADER]: await approvalFor() }))
    expect(res.status).toBe(200)
    const sent = fetchMock.mock.calls[0][1].headers as Record<string, string>
    expect(sent['x-7h3-trust']).toBe('untrusted')
    expect(sent['x-7h3-approved-by']).toBe('alice')
  })
})

describe('gateway-owned headers cannot be spoofed by callers', () => {
  it.each(['x-7h3-verified', 'X-7H3-Approved-By', 'x-7h3-trust', 'x-7h3-sender', 'X-7h3-Approval'])('drops inbound %s', async (name) => {
    const fetchMock = stubUpstream()
    const res = await gateway().handle({ method: 'GET', path: '/public/info', headers: { [name]: 'trusted-by-attacker' } })
    expect(res.status).toBe(200)
    const sent = Object.keys(fetchMock.mock.calls[0][1].headers as Record<string, string>).map((k) => k.toLowerCase())
    expect(sent).not.toContain(name.toLowerCase())
  })

  it('an unauthenticated route never claims verification', async () => {
    const fetchMock = stubUpstream()
    await gateway().handle({ method: 'GET', path: '/public/info', headers: { 'x-7h3-verified': 'true', 'x-7h3-sender': 'agent.admin' } })
    const sent = fetchMock.mock.calls[0][1].headers as Record<string, string>
    expect(sent['x-7h3-verified']).toBeUndefined()
    expect(sent['x-7h3-sender']).toBeUndefined()
  })
})
