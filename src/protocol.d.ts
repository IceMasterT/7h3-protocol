export type ProtocolVersion = '7h3/0.1';
export type IntentKind = 'PING' | 'PONG' | 'CAPS' | 'TASK' | 'RESULT' | 'ERROR';
export interface ProtocolHeader {
    version: ProtocolVersion;
    messageId: string;
    timestampMs: number;
    ttlMs: number;
    sender: string;
    recipient?: string;
    nonce: string;
}
export interface ProtocolBody {
    intent: IntentKind;
    content: string;
    capability?: string;
    correlationId?: string;
}
export interface ProtocolSignature {
    alg: 'HS256' | 'ED25519';
    keyId: string;
    value: string;
}
export interface ProtocolEnvelope {
    header: ProtocolHeader;
    body: ProtocolBody;
    signature?: ProtocolSignature;
}
export interface ProtocolDiagnostic {
    level: 'error' | 'warning';
    message: string;
}
export type SignatureVerificationMaterial = {
    alg: 'HS256';
    secret: string;
} | {
    alg: 'ED25519';
    publicKey: string;
};
export declare function canonicalizeEnvelope(envelope: Omit<ProtocolEnvelope, 'signature'>): string;
export declare function signCanonicalPayloadHmac(payload: string, secret: string): Promise<string>;
export declare function verifyCanonicalPayloadHmac(payload: string, signature: string, secret: string): Promise<boolean>;
export declare function generateEd25519KeypairBase64Url(): Promise<{
    publicKey: string;
    privateKey: string;
}>;
export declare function signCanonicalPayloadEd25519(payload: string, privateKeyPkcs8Base64Url: string): Promise<string>;
export declare function verifyCanonicalPayloadEd25519(payload: string, signature: string, publicKeySpkiBase64Url: string): Promise<boolean>;
export declare function signEnvelopeHmac(envelope: Omit<ProtocolEnvelope, 'signature'>, secret: string, keyId?: string): Promise<ProtocolEnvelope>;
export declare function verifyEnvelopeHmac(envelope: ProtocolEnvelope, secret: string): Promise<boolean>;
export declare function signEnvelopeEd25519(envelope: Omit<ProtocolEnvelope, 'signature'>, privateKeyPkcs8Base64Url: string, keyId?: string): Promise<ProtocolEnvelope>;
export declare function verifyEnvelopeEd25519(envelope: ProtocolEnvelope, publicKeySpkiBase64Url: string): Promise<boolean>;
export declare function verifyEnvelopeSignature(envelope: ProtocolEnvelope, material: SignatureVerificationMaterial): Promise<boolean>;
export declare function verifyCanonicalPayloadSignature(payload: string, signature: ProtocolSignature | undefined, material: SignatureVerificationMaterial): Promise<boolean>;
export declare function validateEnvelope(envelope: ProtocolEnvelope, nowMs?: number): ProtocolDiagnostic[];
export declare function createEnvelope(input: {
    sender: string;
    recipient?: string;
    intent: IntentKind;
    content: string;
    capability?: string;
    correlationId?: string;
    ttlMs?: number;
    messageId?: string;
    nonce?: string;
    nowMs?: number;
}): Omit<ProtocolEnvelope, 'signature'>;
//# sourceMappingURL=protocol.d.ts.map