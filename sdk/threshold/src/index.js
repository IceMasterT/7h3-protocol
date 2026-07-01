import { bls12_381 } from '@noble/curves/bls12-381';
// ─── Helpers ─────────────────────────────────────────────────────────────────
function toBase64Url(bytes) {
    const base64 = Buffer.from(bytes).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function fromBase64Url(value) {
    const padded = value
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(Math.ceil(value.length / 4) * 4, '=');
    return new Uint8Array(Buffer.from(padded, 'base64'));
}
async function sha256(data) {
    const encoder = new TextEncoder();
    const buf = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    return new Uint8Array(buf);
}
/**
 * Canonical serialization of a protocol envelope for signing.
 * Must match the canonical format in @7h3/protocol.
 */
export function canonicalizeEnvelopeForBls(envelope) {
    const h = envelope.header;
    const b = envelope.body;
    const headerParts = [
        `"messageId":${JSON.stringify(h.messageId)}`,
        `"nonce":${JSON.stringify(h.nonce)}`,
    ];
    if (h.recipient !== undefined) {
        headerParts.push(`"recipient":${JSON.stringify(h.recipient)}`);
    }
    headerParts.push(`"sender":${JSON.stringify(h.sender)}`);
    headerParts.push(`"timestampMs":${h.timestampMs}`);
    headerParts.push(`"ttlMs":${h.ttlMs}`);
    headerParts.push(`"version":${JSON.stringify(h.version)}`);
    const headerStr = `{${headerParts.join(',')}}`;
    const bodyParts = [];
    if (b.capability !== undefined)
        bodyParts.push(`"capability":${JSON.stringify(b.capability)}`);
    bodyParts.push(`"content":${JSON.stringify(b.content)}`);
    if (b.correlationId !== undefined)
        bodyParts.push(`"correlationId":${JSON.stringify(b.correlationId)}`);
    bodyParts.push(`"intent":${JSON.stringify(b.intent)}`);
    const bodyStr = `{${bodyParts.join(',')}}`;
    return `{"body":${bodyStr},"header":${headerStr}}`;
}
// ─── Key Generation ──────────────────────────────────────────────────────────
export function generateBlsKeyPair() {
    const privateKeyBytes = bls12_381.utils.randomPrivateKey();
    const publicKeyBytes = bls12_381.getPublicKey(privateKeyBytes);
    return {
        publicKey: toBase64Url(publicKeyBytes),
        privateKey: toBase64Url(privateKeyBytes),
    };
}
// ─── Partial Signing ─────────────────────────────────────────────────────────
export async function signEnvelopeBls(envelope, privateKeyBase64Url, signerId) {
    const canonical = canonicalizeEnvelopeForBls(envelope);
    const msgHash = await sha256(canonical);
    const privateKeyBytes = fromBase64Url(privateKeyBase64Url);
    // BLS sign: signature is a G2 point (96 bytes)
    const sigBytes = bls12_381.sign(msgHash, privateKeyBytes);
    return {
        signerId,
        partialSig: toBase64Url(sigBytes),
        canonicalHash: toBase64Url(msgHash),
    };
}
// ─── Aggregation ─────────────────────────────────────────────────────────────
export async function aggregateSignatures(partialSigs, publicKeys, // signerId → BLS public key (base64url)
envelope, config) {
    if (partialSigs.length < config.m) {
        throw new Error(`Threshold not met: need ${config.m} signatures, got ${partialSigs.length}`);
    }
    // Use exactly m signatures (first m)
    const selected = partialSigs.slice(0, config.m);
    const signerIds = selected.map((s) => s.signerId);
    const sigBytesArr = selected.map((s) => fromBase64Url(s.partialSig));
    const pubKeyBytesArr = signerIds.map((id) => {
        const pk = publicKeys[id];
        if (!pk)
            throw new Error(`Missing public key for signer: ${id}`);
        return fromBase64Url(pk);
    });
    const aggregatedSig = bls12_381.aggregateSignatures(sigBytesArr);
    const aggregatedPubKey = bls12_381.aggregatePublicKeys(pubKeyBytesArr);
    // Fingerprint: first 16 bytes of aggregated pubkey as base64url
    const keyId = toBase64Url(aggregatedPubKey.slice(0, 16));
    return {
        ...envelope,
        thresholdSignature: {
            alg: 'BLS-G2-2',
            keyId,
            value: toBase64Url(aggregatedSig),
            signerIds,
            threshold: config,
        },
    };
}
// ─── Verification ────────────────────────────────────────────────────────────
export async function verifyThresholdEnvelope(envelope, participantPublicKeys, config) {
    try {
        const { thresholdSignature } = envelope;
        if (!thresholdSignature)
            return false;
        if (thresholdSignature.alg !== 'BLS-G2-2')
            return false;
        if (thresholdSignature.signerIds.length < config.m)
            return false;
        const canonical = canonicalizeEnvelopeForBls({
            header: envelope.header,
            body: envelope.body,
        });
        const msgHash = await sha256(canonical);
        const signerIds = thresholdSignature.signerIds;
        const pubKeyBytesArr = signerIds.map((id) => {
            const pk = participantPublicKeys[id];
            if (!pk)
                throw new Error(`Missing public key for signer: ${id}`);
            return fromBase64Url(pk);
        });
        const aggregatedPubKey = bls12_381.aggregatePublicKeys(pubKeyBytesArr);
        const sigBytes = fromBase64Url(thresholdSignature.value);
        return bls12_381.verify(sigBytes, msgHash, aggregatedPubKey);
    }
    catch {
        return false;
    }
}
// ─── Shamir Secret Sharing ───────────────────────────────────────────────────
// Operates over the BLS12-381 scalar field (Fr), prime order r.
// BLS12-381 scalar field order r
const FIELD_ORDER = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');
function fieldMod(n) {
    return ((n % FIELD_ORDER) + FIELD_ORDER) % FIELD_ORDER;
}
function fieldAdd(a, b) {
    return fieldMod(a + b);
}
function fieldMul(a, b) {
    return fieldMod(a * b);
}
// Modular inverse via Fermat's little theorem (field is prime order)
function fieldInv(a) {
    if (a === 0n)
        throw new Error('Cannot invert zero');
    return fieldPow(a, FIELD_ORDER - 2n);
}
function fieldPow(base, exp) {
    let result = 1n;
    base = fieldMod(base);
    while (exp > 0n) {
        if (exp & 1n)
            result = fieldMul(result, base);
        base = fieldMul(base, base);
        exp >>= 1n;
    }
    return result;
}
function bigintToBytes32(n) {
    const hex = n.toString(16).padStart(64, '0');
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
function bytes32ToBigint(bytes) {
    let hex = '';
    for (const b of bytes) {
        hex += b.toString(16).padStart(2, '0');
    }
    return BigInt('0x' + hex);
}
// Generate a cryptographically random field element
function randomFieldElement() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return fieldMod(bytes32ToBigint(bytes));
}
/**
 * Split a BLS private key into N shares using Shamir's Secret Sharing.
 * Any M shares can reconstruct the original key.
 * Returns N shares as base64url strings.
 * Share format: 1 byte index (1-based) || 32 bytes value
 */
export function splitPrivateKey(privateKeyBase64Url, m, n) {
    if (m < 2 || m > n)
        throw new Error(`Invalid threshold: m=${m}, n=${n}`);
    const secretBytes = fromBase64Url(privateKeyBase64Url);
    const secret = fieldMod(bytes32ToBigint(secretBytes));
    // Build polynomial: f(x) = secret + a1*x + a2*x^2 + ... + a_{m-1}*x^{m-1}
    const coefficients = [secret];
    for (let i = 1; i < m; i++) {
        coefficients.push(randomFieldElement());
    }
    // Evaluate at x = 1..n
    const shares = [];
    for (let x = 1; x <= n; x++) {
        let y = 0n;
        let xPow = 1n;
        for (const coeff of coefficients) {
            y = fieldAdd(y, fieldMul(coeff, xPow));
            xPow = fieldMul(xPow, BigInt(x));
        }
        // Encode share: index byte + 32-byte value
        const shareBytes = new Uint8Array(33);
        shareBytes[0] = x;
        shareBytes.set(bigintToBytes32(y), 1);
        shares.push(toBase64Url(shareBytes));
    }
    return shares;
}
/**
 * Reconstruct a BLS private key from M or more shares using Lagrange interpolation.
 * @param shares - array of share strings (base64url, at least m of them)
 * @param m - minimum number of shares required (used for validation only)
 */
export function reconstructPrivateKey(shares, m) {
    if (shares.length < m) {
        throw new Error(`Need at least ${m} shares, got ${shares.length}`);
    }
    // Decode shares — take exactly m
    const decoded = shares.slice(0, m).map((s) => {
        const bytes = fromBase64Url(s);
        if (bytes.length !== 33)
            throw new Error('Invalid share format');
        const x = BigInt(bytes[0]);
        const y = bytes32ToBigint(bytes.slice(1));
        return { x, y };
    });
    // Lagrange interpolation at x=0 to recover secret
    let secret = 0n;
    for (let i = 0; i < decoded.length; i++) {
        const xi = decoded[i].x;
        const yi = decoded[i].y;
        // Compute Lagrange basis polynomial l_i(0)
        let num = 1n;
        let den = 1n;
        for (let j = 0; j < decoded.length; j++) {
            if (i === j)
                continue;
            const xj = decoded[j].x;
            // num *= (0 - xj) = -xj
            num = fieldMul(num, fieldMod(-xj));
            // den *= (xi - xj)
            den = fieldMul(den, fieldMod(xi - xj));
        }
        const lagrangeBasis = fieldMul(num, fieldInv(den));
        secret = fieldAdd(secret, fieldMul(yi, lagrangeBasis));
    }
    return toBase64Url(bigintToBytes32(secret));
}
