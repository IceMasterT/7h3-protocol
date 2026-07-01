export interface ProtocolHeader {
    version: string;
    messageId: string;
    timestampMs: number;
    ttlMs: number;
    sender: string;
    recipient?: string;
    nonce: string;
}
export interface ProtocolBody {
    intent: string;
    content: string;
    capability?: string;
    correlationId?: string;
}
export interface ProtocolEnvelope {
    header: ProtocolHeader;
    body: ProtocolBody;
}
export interface BlsKeyPair {
    publicKey: string;
    privateKey: string;
}
export interface ThresholdConfig {
    m: number;
    n: number;
}
export interface ThresholdSignature {
    alg: 'BLS-G2-2';
    keyId: string;
    value: string;
    signerIds: string[];
    threshold: ThresholdConfig;
}
export interface ThresholdEnvelope extends ProtocolEnvelope {
    thresholdSignature: ThresholdSignature;
}
/**
 * Canonical serialization of a protocol envelope for signing.
 * Must match the canonical format in @7h3/protocol.
 */
export declare function canonicalizeEnvelopeForBls(envelope: ProtocolEnvelope): string;
export declare function generateBlsKeyPair(): BlsKeyPair;
export declare function signEnvelopeBls(envelope: ProtocolEnvelope, privateKeyBase64Url: string, signerId: string): Promise<{
    signerId: string;
    partialSig: string;
    canonicalHash: string;
}>;
export declare function aggregateSignatures(partialSigs: Array<{
    signerId: string;
    partialSig: string;
}>, publicKeys: Record<string, string>, // signerId → BLS public key (base64url)
envelope: ProtocolEnvelope, config: ThresholdConfig): Promise<ThresholdEnvelope>;
export declare function verifyThresholdEnvelope(envelope: ThresholdEnvelope, participantPublicKeys: Record<string, string>, config: ThresholdConfig): Promise<boolean>;
/**
 * Split a BLS private key into N shares using Shamir's Secret Sharing.
 * Any M shares can reconstruct the original key.
 * Returns N shares as base64url strings.
 * Share format: 1 byte index (1-based) || 32 bytes value
 */
export declare function splitPrivateKey(privateKeyBase64Url: string, m: number, n: number): string[];
/**
 * Reconstruct a BLS private key from M or more shares using Lagrange interpolation.
 * @param shares - array of share strings (base64url, at least m of them)
 * @param m - minimum number of shares required (used for validation only)
 */
export declare function reconstructPrivateKey(shares: string[], m: number): string;
//# sourceMappingURL=index.d.ts.map