/**
 * Verify the PUBLISHED packages, not this working tree.
 *
 * Installs every 7h3 package fresh from the registry into a scratch project and
 * exercises it the way a consumer would — signing, tamper detection, every
 * hardening rule, cross-SDK interop, and the WebMCP authorization model.
 *
 * This exists because two packages shipped broken during the 0.6 series
 * (@7h3/protocol-webmcp@0.6.0 and @7h3/protocol-mcp@0.6.1, both
 * ERR_MODULE_NOT_FOUND) while every unit test passed. A green suite says the
 * source is correct; only this says the artifact a user installs is.
 *
 *   node scripts/verify-published-packages.mjs
 *
 * Run it from a scratch directory that has the packages installed:
 *   mkdir /tmp/v && cd /tmp/v && npm init -y && npm pkg set type=module
 *   npm i @7h3/protocol @7h3/protocol-webmcp @7h3/protocol-browser \
 *         @7h3/protocol-pq @7h3/protocol-threshold
 *   node <repo>/scripts/verify-published-packages.mjs
 */

let pass = 0, fail = 0
const ok  = (n, c, d='') => { c ? (pass++, console.log(`  PASS  ${n}${d?'  — '+d:''}`)) : (fail++, console.log(`  FAIL  ${n}${d?'  — '+d:''}`)) }
const sec = (t) => console.log(`\n── ${t} ──`)

// ═══ CORE ═══
sec('@7h3/protocol — signing, validation, hardening')
const core = await import('@7h3/protocol')
const now = Date.now()
const kp = await core.generateEd25519KeypairBase64Url()
const env = core.createEnvelope({ sender: 'a@b.test', intent: 'TASK', content: 'hello', ttlMs: 60_000 })
const signed = await core.signEnvelopeEd25519(env, kp.privateKey, 'k1')

ok('signs and verifies', await core.verifyEnvelopeEd25519(signed, kp.publicKey) === true)
ok('rejects tampered body', await core.verifyEnvelopeEd25519({...signed, body:{...signed.body, content:'EVIL'}}, kp.publicKey) === false)
ok('rejects tampered header', await core.verifyEnvelopeEd25519({...signed, header:{...signed.header, sender:'evil@x'}}, kp.publicKey) === false)
ok('rejects forged signature', await core.verifyEnvelopeEd25519({...signed, signature:{...signed.signature, value:'A'.repeat(86)}}, kp.publicKey) === false)
ok('rejects under a foreign key', await core.verifyEnvelopeEd25519(signed, (await core.generateEd25519KeypairBase64Url()).publicKey) === false)

const errs = (o) => core.validateEnvelope({...signed, header:{...signed.header, ...o}}, now).filter(d=>d.level==='error').map(d=>d.message)
ok('valid envelope has no errors', errs({}).length === 0)
ok('SEC post-dated timestamp rejected', errs({timestampMs: now+31_536_000_000}).some(m=>m.includes('in the future')), 'MAX_TTL_MS bounds nothing without this')
ok('SEC ttl above 24h ceiling rejected', errs({ttlMs: core.MAX_TTL_MS+1}).length > 0)
ok('SEC NaN ttl rejected', errs({ttlMs: NaN}).length > 0)
ok('SEC Infinity ttl rejected', errs({ttlMs: Infinity}).length > 0)
ok('SEC NaN timestamp rejected', errs({timestampMs: NaN}).length > 0)
ok('SEC empty nonce rejected', errs({nonce: ''}).length > 0)
ok('SEC foreign wire version rejected', errs({version: '7h3/9.9'}).length > 0)
ok('expired envelope rejected', errs({timestampMs: now-120_000, ttlMs: 60_000}).some(m=>m.includes('expired')))
ok('wire version is 7h3/0.1', signed.header.version === '7h3/0.1')

sec('@7h3/protocol — CBOR hardening')
const deep = new Uint8Array(200_001); deep.fill(0x81, 0, 200_000); deep[200_000] = 0
let cborBounded = false
try { core.decodeCbor(deep) } catch (e) { cborBounded = /nesting depth/.test(e.message) }
ok('SEC CBOR nesting depth bounded', cborBounded, '50KB of 0x81 would otherwise overflow the stack')
const proto = core.decodeCbor(core.encodeCbor(new Map([['__proto__', {polluted:true}]])))
ok('SEC CBOR resists __proto__ pollution', ({}).polluted === undefined && Object.hasOwn(proto,'__proto__'))

sec('@7h3/protocol — capability delegation')
const root = await core.issueCapabilityToken({ issuerPrivateKey: kp.privateKey, issuerId:'o', subject:'a',
  scopes:[{pathGlob:'money/**'}], ttlMs:60_000, maxDelegations:1, keyId:'k1' })
ok('issues a capability token', await core.verifyCapabilityToken(root, kp.publicKey) === true)
ok('rejects a tampered token', await core.verifyCapabilityToken({...root, subject:'evil'}, kp.publicKey) === false)
let containment = 'not-refused'
try { await core.delegateCapabilityToken({ parentToken: root, delegatorPrivateKey: kp.privateKey,
  delegatorId:'a', newSubject:'b', scopes:[{pathGlob:'money'}], ttlMs:30_000 }) } catch { containment = 'refused' }
ok('SEC delegation refuses an unsound subset', containment === 'refused', "'money' is not covered by 'money/**'")

// ═══ WEBMCP ═══
sec('@7h3/protocol-webmcp — authorization')
const w = await import('@7h3/protocol-webmcp')
const g = w.guard({ origin:'shop.example', privateKey: kp.privateKey, publicKey: kp.publicKey })
let ran = 0
await g.registerTool({ name:'pay', description:'pay', scope:'money/pay',
  limit:{field:'amountCents', max:500_00}, execute: async () => { ran++; return {ok:true} } })

ok('SEC refuses with no grant', (await g.invoke('pay',{amountCents:100})).reason === 'no-active-grant')
await g.grant({ subject:'agent', scopes:['money/*'], caps:{amountCents:50_00}, ttlMs:60_000 })
ok('allows an in-scope call', (await g.invoke('pay',{amountCents:10_00})).ok === true)
ok('SEC cap bound in the signed token binds', (await g.invoke('pay',{amountCents:400_00})).reason === 'limit-exceeded')
ok('SEC ceiling fails closed when the field is omitted', (await g.invoke('pay',{})).reason === 'limit-exceeded')
ok('SEC refuses an out-of-scope tool', (await g.invoke('nope',{})).reason === 'unknown-tool')
ok('handler ran only for authorized calls', ran === 1, `ran ${ran}x`)

const n1 = await g.invoke('pay',{amountCents:100, __7h3_nonce:'n1'})
const n2 = await g.invoke('pay',{amountCents:100, __7h3_nonce:'n1'})
ok('SEC replay refused', n1.ok === true && n2.reason === 'replayed-call')

const chain = await w.verifyChain(g.receipts.all(), kp.publicKey)
ok('receipt chain verifies', chain.ok === true, `${chain.length} receipts`)
const tampered = g.receipts.all().map(r=>({...r})); tampered[0] = {...tampered[0], outcome:'allowed', reason: undefined}
ok('SEC receipt tampering detected', (await w.verifyChain(tampered, kp.publicKey)).ok === false)
const dropped = g.receipts.all().slice(1)
ok('SEC receipt deletion detected', (await w.verifyChain(dropped, kp.publicKey)).ok === false)

const man = await g.manifest()
ok('manifest verifies', (await w.verifyManifest(man, kp.publicKey)).ok === true)
ok('SEC manifest tampering detected', (await w.verifyManifest({...man, origin:'evil'}, kp.publicKey)).ok === false)
const poisoned = await w.diffAgainstManifest([...g.registeredTools(), {name:'evil_tool',description:'x',execute:async()=>{}}], man)
ok('SEC tool-surface poisoning detected', poisoned.ok === false && poisoned.added.includes('evil_tool'))

// ═══ BROWSER ═══
sec('@7h3/protocol-browser — parity with core')
const br = await import('@7h3/protocol-browser')
const bkp = await br.generateKeypair()
const benv = br.createEnvelope({ sender:'a@b.test', body:{intent:'TASK', content:'hello'} })
const bsigned = await br.signEnvelope(benv, bkp.privateKey, 'k1')
ok('signs and verifies', await br.verifyEnvelope(bsigned, bkp.publicKey) === true)
ok('CROSS-SDK browser-signed verifies in core', await core.verifyEnvelopeEd25519(bsigned, bkp.publicKey) === true)
const csigned = await core.signEnvelopeEd25519(env, kp.privateKey, 'k1')
ok('CROSS-SDK core-signed verifies in browser', await br.verifyEnvelope(csigned, kp.publicKey) === true)
ok('canonical bytes identical', br.canonicalizeEnvelope({header:bsigned.header,body:bsigned.body}) === core.canonicalizeEnvelope({header:bsigned.header,body:bsigned.body}))
ok('rejects tampering', await br.verifyEnvelope({...bsigned, body:{...bsigned.body, content:'EVIL'}}, bkp.publicKey) === false)
const berrs = (o) => br.validateEnvelope({...bsigned, header:{...bsigned.header, ...o}}, now).filter(d=>d.level==='error').map(d=>d.message)
ok('SEC post-dated rejected', berrs({timestampMs: now+31_536_000_000}).some(m=>m.includes('in the future')))
ok('SEC NaN ttl rejected', berrs({ttlMs: NaN}).length > 0)
ok('SEC empty nonce rejected', berrs({nonce:''}).length > 0)
ok('SEC isEnvelopeExpired fails closed on NaN', br.isEnvelopeExpired({...bsigned, header:{...bsigned.header, ttlMs:NaN}}) === true)
const same = [{}, {ttlMs:NaN}, {nonce:''}, {version:'7h3/9.9'}, {timestampMs: now+31_536_000_000}, {ttlMs: core.MAX_TTL_MS+1}]
  .every(o => JSON.stringify(berrs(o).sort()) === JSON.stringify(errs(o).sort()))
ok('diagnostics identical to core across 6 malformed cases', same)

// ═══ PQ / THRESHOLD ═══
sec('@7h3/protocol-pq and -threshold')
const pq = await import('@7h3/protocol-pq')
const pkp = pq.generatePqKeyPair()
const psigned = await pq.signEnvelopePq(env, pkp.privateKey)
ok('pq signs and verifies (ML-DSA-65)', await pq.verifyEnvelopePq(psigned, pkp.publicKey) === true)
ok('SEC pq rejects tampering', await pq.verifyEnvelopePq({...psigned, body:{...psigned.body, content:'EVIL'}}, pkp.publicKey) === false)

const th = await import('@7h3/protocol-threshold')
const s1 = th.generateBlsKeyPair(), s2 = th.generateBlsKeyPair(), s3 = th.generateBlsKeyPair()
const pubs = { alice:s1.publicKey, bob:s2.publicKey, carol:s3.publicKey }
const cfg = { m:2, n:3 }
const partials = [ await th.signEnvelopeBls(signed, s1.privateKey, 'alice'), await th.signEnvelopeBls(signed, s2.privateKey, 'bob') ]
const agg = await th.aggregateSignatures(partials, pubs, signed, cfg)
ok('threshold 2-of-3 verifies', await th.verifyThresholdEnvelope(agg, pubs, cfg) === true)
const shares = th.splitPrivateKey(kp.privateKey, 2, 3)
ok('shamir split/reconstruct round-trips', th.reconstructPrivateKey(shares.slice(0,2), 2) === kp.privateKey)

console.log(`\n${'═'.repeat(56)}\n  ${pass} passed, ${fail} failed\n${'═'.repeat(56)}`)
process.exit(fail === 0 ? 0 : 1)
