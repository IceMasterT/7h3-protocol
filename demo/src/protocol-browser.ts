/**
 * Browser entry for the protocol.
 *
 * The package barrel also re-exports `encryption` and `mcpTransports`, which
 * import `node:crypto` and `node:readline`. Bundling the barrel leaves those as
 * browser-external stubs that throw on property access, so the demo pulls in
 * only the two modules it actually needs — both pure Web Crypto.
 */
export * from '../../src/protocol'
export * from '../../src/capability'
