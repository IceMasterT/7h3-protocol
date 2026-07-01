const textEncoder = new TextEncoder();
const HMAC_KEY_CACHE_LIMIT = 256;
const hmacKeyCache = new Map();
const ED25519_KEY_CACHE_LIMIT = 256;
const ed25519PrivateKeyCache = new Map();
const ed25519PublicKeyCache = new Map();
function getBufferLike() {
    const candidate = globalThis;
    return candidate.Buffer ?? null;
}
function serializeHeaderCanonical(header) {
    const parts = [
        `"messageId":${JSON.stringify(header.messageId)}`,
        `"nonce":${JSON.stringify(header.nonce)}`,
    ];
    if (header.recipient !== undefined) {
        parts.push(`"recipient":${JSON.stringify(header.recipient)}`);
    }
    parts.push(`"sender":${JSON.stringify(header.sender)}`);
    parts.push(`"timestampMs":${header.timestampMs}`);
    parts.push(`"ttlMs":${header.ttlMs}`);
    parts.push(`"version":${JSON.stringify(header.version)}`);
    return `{${parts.join(',')}}`;
}
function serializeBodyCanonical(body) {
    const parts = [];
    if (body.capability !== undefined) {
        parts.push(`"capability":${JSON.stringify(body.capability)}`);
    }
    parts.push(`"content":${JSON.stringify(body.content)}`);
    if (body.correlationId !== undefined) {
        parts.push(`"correlationId":${JSON.stringify(body.correlationId)}`);
    }
    parts.push(`"intent":${JSON.stringify(body.intent)}`);
    return `{${parts.join(',')}}`;
}
function getCachedHmacKey(secret) {
    const cacheKey = `hs256:${secret}`;
    const cached = hmacKeyCache.get(cacheKey);
    if (cached)
        return cached;
    if (hmacKeyCache.size >= HMAC_KEY_CACHE_LIMIT) {
        hmacKeyCache.clear();
    }
    const subtle = requireCryptoSubtle();
    const imported = subtle
        .importKey('raw', textEncoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
        .catch((error) => {
        hmacKeyCache.delete(cacheKey);
        throw error;
    });
    hmacKeyCache.set(cacheKey, imported);
    return imported;
}
function getCachedEd25519PrivateKey(privateKeyPkcs8Base64Url) {
    const cacheKey = `ed25519:pkcs8:${privateKeyPkcs8Base64Url}`;
    const cached = ed25519PrivateKeyCache.get(cacheKey);
    if (cached)
        return cached;
    if (ed25519PrivateKeyCache.size >= ED25519_KEY_CACHE_LIMIT) {
        ed25519PrivateKeyCache.clear();
    }
    const subtle = requireCryptoSubtle();
    const imported = subtle
        .importKey('pkcs8', toArrayBuffer(fromBase64Url(privateKeyPkcs8Base64Url)), { name: 'Ed25519' }, false, ['sign'])
        .catch((error) => {
        ed25519PrivateKeyCache.delete(cacheKey);
        throw error;
    });
    ed25519PrivateKeyCache.set(cacheKey, imported);
    return imported;
}
function getCachedEd25519PublicKey(publicKeySpkiBase64Url) {
    const cacheKey = `ed25519:spki:${publicKeySpkiBase64Url}`;
    const cached = ed25519PublicKeyCache.get(cacheKey);
    if (cached)
        return cached;
    if (ed25519PublicKeyCache.size >= ED25519_KEY_CACHE_LIMIT) {
        ed25519PublicKeyCache.clear();
    }
    const subtle = requireCryptoSubtle();
    const imported = subtle
        .importKey('spki', toArrayBuffer(fromBase64Url(publicKeySpkiBase64Url)), { name: 'Ed25519' }, false, ['verify'])
        .catch((error) => {
        ed25519PublicKeyCache.delete(cacheKey);
        throw error;
    });
    ed25519PublicKeyCache.set(cacheKey, imported);
    return imported;
}
function toBase64Url(bytes) {
    const bufferLike = getBufferLike();
    const base64 = bufferLike ? bufferLike.from(bytes).toString('base64') : btoa(String.fromCharCode(...bytes));
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}
function fromBase64Url(value) {
    const padded = value
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(Math.ceil(value.length / 4) * 4, '=');
    const bufferLike = getBufferLike();
    if (bufferLike) {
        return new Uint8Array(bufferLike.from(padded, 'base64'));
    }
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
function toArrayBuffer(bytes) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}
export function canonicalizeEnvelope(envelope) {
    return `{"body":${serializeBodyCanonical(envelope.body)},"header":${serializeHeaderCanonical(envelope.header)}}`;
}
function requireCryptoSubtle() {
    if (typeof crypto === 'undefined' || !crypto.subtle) {
        throw new Error('Web Crypto API is not available in this runtime');
    }
    return crypto.subtle;
}
async function hmacSign(payload, secret) {
    const subtle = requireCryptoSubtle();
    const key = await getCachedHmacKey(secret);
    const signature = await subtle.sign('HMAC', key, textEncoder.encode(payload));
    return toBase64Url(new Uint8Array(signature));
}
async function hmacVerify(payload, signature, secret) {
    const subtle = requireCryptoSubtle();
    const key = await getCachedHmacKey(secret);
    const signatureBytes = fromBase64Url(signature);
    return subtle.verify('HMAC', key, signatureBytes.buffer, textEncoder.encode(payload));
}
async function ed25519Sign(payload, privateKeyPkcs8Base64Url) {
    const subtle = requireCryptoSubtle();
    const key = await getCachedEd25519PrivateKey(privateKeyPkcs8Base64Url);
    const signature = await subtle.sign('Ed25519', key, textEncoder.encode(payload));
    return toBase64Url(new Uint8Array(signature));
}
async function ed25519Verify(payload, signature, publicKeySpkiBase64Url) {
    const subtle = requireCryptoSubtle();
    const key = await getCachedEd25519PublicKey(publicKeySpkiBase64Url);
    const signatureBytes = fromBase64Url(signature);
    return subtle.verify('Ed25519', key, signatureBytes.buffer, textEncoder.encode(payload));
}
export async function signCanonicalPayloadHmac(payload, secret) {
    return hmacSign(payload, secret);
}
export async function verifyCanonicalPayloadHmac(payload, signature, secret) {
    return hmacVerify(payload, signature, secret);
}
export async function generateEd25519KeypairBase64Url() {
    const subtle = requireCryptoSubtle();
    const pair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const privateKeyRaw = await subtle.exportKey('pkcs8', pair.privateKey);
    const publicKeyRaw = await subtle.exportKey('spki', pair.publicKey);
    return {
        privateKey: toBase64Url(new Uint8Array(privateKeyRaw)),
        publicKey: toBase64Url(new Uint8Array(publicKeyRaw)),
    };
}
export async function signCanonicalPayloadEd25519(payload, privateKeyPkcs8Base64Url) {
    return ed25519Sign(payload, privateKeyPkcs8Base64Url);
}
export async function verifyCanonicalPayloadEd25519(payload, signature, publicKeySpkiBase64Url) {
    return ed25519Verify(payload, signature, publicKeySpkiBase64Url);
}
export async function signEnvelopeHmac(envelope, secret, keyId = 'local-dev-key') {
    const payload = canonicalizeEnvelope(envelope);
    const signature = await hmacSign(payload, secret);
    return {
        ...envelope,
        signature: {
            alg: 'HS256',
            keyId,
            value: signature,
        },
    };
}
export async function verifyEnvelopeHmac(envelope, secret) {
    if (!envelope.signature)
        return false;
    if (envelope.signature.alg !== 'HS256')
        return false;
    const unsigned = {
        header: envelope.header,
        body: envelope.body,
    };
    const payload = canonicalizeEnvelope(unsigned);
    return hmacVerify(payload, envelope.signature.value, secret);
}
export async function signEnvelopeEd25519(envelope, privateKeyPkcs8Base64Url, keyId = 'local-ed25519-key') {
    const payload = canonicalizeEnvelope(envelope);
    const signature = await ed25519Sign(payload, privateKeyPkcs8Base64Url);
    return {
        ...envelope,
        signature: {
            alg: 'ED25519',
            keyId,
            value: signature,
        },
    };
}
export async function verifyEnvelopeEd25519(envelope, publicKeySpkiBase64Url) {
    if (!envelope.signature)
        return false;
    if (envelope.signature.alg !== 'ED25519')
        return false;
    const unsigned = {
        header: envelope.header,
        body: envelope.body,
    };
    const payload = canonicalizeEnvelope(unsigned);
    return ed25519Verify(payload, envelope.signature.value, publicKeySpkiBase64Url);
}
export async function verifyEnvelopeSignature(envelope, material) {
    if (!envelope.signature)
        return false;
    if (envelope.signature.alg !== material.alg)
        return false;
    if (material.alg === 'HS256') {
        return verifyEnvelopeHmac(envelope, material.secret);
    }
    return verifyEnvelopeEd25519(envelope, material.publicKey);
}
export async function verifyCanonicalPayloadSignature(payload, signature, material) {
    if (!signature)
        return false;
    if (signature.alg !== material.alg)
        return false;
    if (material.alg === 'HS256') {
        return verifyCanonicalPayloadHmac(payload, signature.value, material.secret);
    }
    return verifyCanonicalPayloadEd25519(payload, signature.value, material.publicKey);
}
export function validateEnvelope(envelope, nowMs = Date.now()) {
    const diagnostics = [];
    const header = envelope.header ?? {};
    const body = envelope.body ?? {};
    const version = typeof header.version === 'string' ? header.version : '';
    const messageId = typeof header.messageId === 'string' ? header.messageId : '';
    const sender = typeof header.sender === 'string' ? header.sender : '';
    const nonce = typeof header.nonce === 'string' ? header.nonce : '';
    const timestampMs = typeof header.timestampMs === 'number' ? header.timestampMs : 0;
    const ttlMs = typeof header.ttlMs === 'number' ? header.ttlMs : 0;
    const content = typeof body.content === 'string' ? body.content : '';
    if (version !== '7h3/0.1') {
        diagnostics.push({ level: 'error', message: `Unsupported protocol version '${version}'` });
    }
    if (!messageId.trim()) {
        diagnostics.push({ level: 'error', message: 'Missing messageId' });
    }
    if (!sender.trim()) {
        diagnostics.push({ level: 'error', message: 'Missing sender identity' });
    }
    if (!nonce.trim()) {
        diagnostics.push({ level: 'error', message: 'Missing nonce — replay protection requires a unique nonce per message' });
    }
    if (ttlMs <= 0) {
        diagnostics.push({ level: 'error', message: 'ttlMs must be greater than zero' });
    }
    if (timestampMs + ttlMs < nowMs) {
        diagnostics.push({ level: 'error', message: 'Message TTL expired' });
    }
    if (!content.trim()) {
        diagnostics.push({ level: 'warning', message: 'Empty content payload' });
    }
    return diagnostics;
}
export function createEnvelope(input) {
    const nowMs = input.nowMs ?? Date.now();
    return {
        header: {
            version: '7h3/0.1',
            messageId: input.messageId ?? `msg-${nowMs}-${Math.random().toString(36).slice(2, 10)}`,
            timestampMs: nowMs,
            ttlMs: input.ttlMs ?? 60_000,
            sender: input.sender,
            recipient: input.recipient,
            nonce: input.nonce ?? Math.random().toString(36).slice(2, 12),
        },
        body: {
            intent: input.intent,
            content: input.content,
            capability: input.capability,
            correlationId: input.correlationId,
        },
    };
}
