from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from typing import Any, Dict, Optional, TypedDict

# Ceiling on ttlMs — a huge TTL keeps an envelope replayable (and its nonce
# pinned in every replay store) far beyond any legitimate messaging window.
MAX_TTL_MS = 86_400_000  # 24 hours

# How far into the future a timestamp may sit before it is rejected. Without
# this ceiling MAX_TTL_MS bounds nothing: a sender can post-date timestampMs by
# a year and still pass a 24h ttlMs, keeping the envelope valid — and
# replayable — long after any replay store has forgotten its nonce.
MAX_CLOCK_SKEW_MS = 30_000

# ---------------------------------------------------------------------------
# Optional native Ed25519 backend — try cryptography, then PyNaCl
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAS_CRYPTOGRAPHY = True
except Exception:
    _HAS_CRYPTOGRAPHY = False

try:
    import nacl.signing as _nacl_signing  # type: ignore[import]

    _HAS_NACL = True
except Exception:
    _HAS_NACL = False

# ---------------------------------------------------------------------------
# Pure-Python Ed25519 fallback (no external dependencies)
#
# Uses extended twisted Edwards coordinates (X:Y:Z:T) to eliminate the
# expensive field inversion from the inner loop — inversion runs once at
# point compression only. ~10–50 ms/op in CPython; correct for conformance
# testing. Install 'cryptography' for production-grade performance.
#
# Based on the reference implementation: https://ed25519.cr.yp.to/software.html
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

# Base point G in extended coordinates (X:Y:Z:T)
_GY = 4 * pow(5, _P - 2, _P) % _P
_GX_SQ = (_GY * _GY - 1) * pow(_D * _GY * _GY + 1, _P - 2, _P) % _P
_GX = pow(_GX_SQ, (_P + 3) // 8, _P)
if (_GX * _GX - _GX_SQ) % _P != 0:
    _GX = _GX * _SQRT_M1 % _P
if _GX & 1:
    _GX = _P - _GX
_G_BASE = (_GX, _GY, 1, _GX * _GY % _P)


def _point_add(P: tuple, Q: tuple) -> tuple:
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    C = 2 * P[3] * Q[3] * _D % _P
    D_ = 2 * P[2] * Q[2] % _P
    E = B - A
    F = D_ - C
    G_ = D_ + C
    H = B + A
    return (E * F % _P, G_ * H % _P, F * G_ % _P, E * H % _P)


def _point_mul(s: int, P: tuple) -> tuple:
    Q: tuple = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _compress(P: tuple) -> bytes:
    zi = pow(P[2], _P - 2, _P)
    x = P[0] * zi % _P
    y = P[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(b: bytes) -> Optional[tuple]:
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return (0, y, 1, 0) if sign == 0 else None
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _py_ed25519_sign(seed: bytes, message: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    prefix = h[32:]
    A = _compress(_point_mul(a, _G_BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    R = _compress(_point_mul(r, _G_BASE))
    S = (r + int.from_bytes(hashlib.sha512(R + A + message).digest(), "little") * a) % _L
    return R + int.to_bytes(S, 32, "little")


def _py_ed25519_verify(pub_bytes: bytes, message: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pub_bytes) != 32:
        return False
    A = _decompress(pub_bytes)
    if A is None:
        return False
    R_pt = _decompress(sig[:32])
    if R_pt is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub_bytes + message).digest(), "little")
    sB = _point_mul(s, _G_BASE)
    hA = _point_mul(h, A)
    return _compress(sB) == _compress(_point_add(R_pt, hA))


# ---------------------------------------------------------------------------
# DER key extraction helpers
#
# WebCrypto exports Ed25519 keys as PKCS8 (private) and SPKI (public) DER.
# Both formats have a fixed structure for Ed25519 with known byte offsets:
#
#   PKCS8 v0 (48 bytes):
#     30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 [32-byte seed]
#
#   SPKI (44 bytes):
#     30 2a 30 05 06 03 2b 65 70 03 21 00 [32-byte public key]
# ---------------------------------------------------------------------------

# fmt: off
_PKCS8_ED25519_LEN = 48  # 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 [32-byte seed]
_SPKI_ED25519_LEN  = 44  # 30 2a 30 05 06 03 2b 65 70 03 21 00 [32-byte public key]
# fmt: on


def _seed_from_pkcs8(pkcs8_der: bytes) -> bytes:
    if len(pkcs8_der) != 48:
        raise ValueError(
            f"Ed25519 PKCS8 DER must be 48 bytes, got {len(pkcs8_der)}. "
            "Ensure the key was exported with SubtleCrypto.exportKey('pkcs8', key)."
        )
    return pkcs8_der[16:48]


def _pubkey_from_spki(spki_der: bytes) -> bytes:
    if len(spki_der) != 44:
        raise ValueError(
            f"Ed25519 SPKI DER must be 44 bytes, got {len(spki_der)}. "
            "Ensure the key was exported with SubtleCrypto.exportKey('spki', key)."
        )
    return spki_der[12:44]


# ---------------------------------------------------------------------------
# Protocol types
# ---------------------------------------------------------------------------


class ProtocolHeader(TypedDict, total=False):
    version: str
    messageId: str
    timestampMs: int
    ttlMs: int
    sender: str
    recipient: str
    nonce: str


class ProtocolBody(TypedDict, total=False):
    intent: str
    content: str
    capability: str
    correlationId: str


class ProtocolSignature(TypedDict):
    alg: str
    keyId: str
    value: str


class ProtocolEnvelope(TypedDict, total=False):
    header: ProtocolHeader
    body: ProtocolBody
    signature: ProtocolSignature


@dataclass(frozen=True)
class ProtocolDiagnostic:
    level: str
    message: str


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _json_string(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    return base64.urlsafe_b64decode(value + padding)


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def canonicalize_envelope(envelope: Dict[str, Any]) -> str:
    header = envelope["header"]
    body = envelope["body"]

    body_parts = []
    if "capability" in body and body["capability"] is not None:
        body_parts.append(f'"capability":{_json_string(body["capability"])}')
    body_parts.append(f'"content":{_json_string(body["content"])}')
    if "correlationId" in body and body["correlationId"] is not None:
        body_parts.append(f'"correlationId":{_json_string(body["correlationId"])}')
    body_parts.append(f'"intent":{_json_string(body["intent"])}')

    header_parts = [
        f'"messageId":{_json_string(header["messageId"])}',
        f'"nonce":{_json_string(header["nonce"])}',
    ]
    if "recipient" in header and header["recipient"] is not None:
        header_parts.append(f'"recipient":{_json_string(header["recipient"])}')
    header_parts.extend(
        [
            f'"sender":{_json_string(header["sender"])}',
            f'"timestampMs":{int(header["timestampMs"])}',
            f'"ttlMs":{int(header["ttlMs"])}',
            f'"version":{_json_string(header["version"])}',
        ]
    )

    return (
        f'{{"body":{{{",".join(body_parts)}}},"header":{{{",".join(header_parts)}}}}}'
    )


# ---------------------------------------------------------------------------
# HMAC-SHA256 (HS256)
# ---------------------------------------------------------------------------


def sign_canonical_payload_hmac(canonical_payload: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"), canonical_payload.encode("utf-8"), hashlib.sha256
    ).digest()
    return _base64url(digest)


def verify_canonical_payload_hmac(
    canonical_payload: str, signature: str, secret: str
) -> bool:
    expected = sign_canonical_payload_hmac(canonical_payload, secret)
    return hmac.compare_digest(signature, expected)


# ---------------------------------------------------------------------------
# Ed25519 — tries cryptography → PyNaCl → pure-Python in order
# ---------------------------------------------------------------------------


def sign_canonical_payload_ed25519(
    canonical_payload: str, private_key_pkcs8_base64url: str
) -> str:
    private_der = _base64url_decode(private_key_pkcs8_base64url)
    msg = canonical_payload.encode("utf-8")

    if _HAS_CRYPTOGRAPHY:
        key = serialization.load_der_private_key(private_der, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("DER key is not an Ed25519 private key")
        return _base64url(key.sign(msg))

    if _HAS_NACL:
        seed = _seed_from_pkcs8(private_der)
        sk = _nacl_signing.SigningKey(seed)
        return _base64url(bytes(sk.sign(msg).signature))

    # Pure-Python fallback
    seed = _seed_from_pkcs8(private_der)
    return _base64url(_py_ed25519_sign(seed, msg))


def verify_canonical_payload_ed25519(
    canonical_payload: str, signature: str, public_key_spki_base64url: str
) -> bool:
    public_der = _base64url_decode(public_key_spki_base64url)
    msg = canonical_payload.encode("utf-8")
    sig_bytes = _base64url_decode(signature)

    if _HAS_CRYPTOGRAPHY:
        try:
            key = serialization.load_der_public_key(public_der)
            if not isinstance(key, Ed25519PublicKey):
                return False
            key.verify(sig_bytes, msg)
            return True
        except Exception:
            return False

    if _HAS_NACL:
        try:
            pub_bytes = _pubkey_from_spki(public_der)
            vk = _nacl_signing.VerifyKey(pub_bytes)
            vk.verify(msg, sig_bytes)
            return True
        except Exception:
            return False

    # Pure-Python fallback
    try:
        pub_bytes = _pubkey_from_spki(public_der)
        return _py_ed25519_verify(pub_bytes, msg, sig_bytes)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Envelope-level sign/verify helpers
# ---------------------------------------------------------------------------


def sign_envelope_hmac(
    envelope: Dict[str, Any], secret: str, key_id: str = "python-dev-key"
) -> Dict[str, Any]:
    canonical = canonicalize_envelope(envelope)
    signature = sign_canonical_payload_hmac(canonical, secret)
    return {
        "header": dict(envelope["header"]),
        "body": dict(envelope["body"]),
        "signature": {"alg": "HS256", "keyId": key_id, "value": signature},
    }


def verify_envelope_hmac(envelope: Dict[str, Any], secret: str) -> bool:
    signature = envelope.get("signature")
    if not signature:
        return False
    if signature.get("alg") != "HS256":
        return False
    unsigned = {"header": envelope["header"], "body": envelope["body"]}
    canonical = canonicalize_envelope(unsigned)
    return verify_canonical_payload_hmac(canonical, signature.get("value", ""), secret)


def sign_envelope_ed25519(
    envelope: Dict[str, Any],
    private_key_pkcs8_base64url: str,
    key_id: str = "python-ed25519-key",
) -> Dict[str, Any]:
    canonical = canonicalize_envelope(envelope)
    signature = sign_canonical_payload_ed25519(canonical, private_key_pkcs8_base64url)
    return {
        "header": dict(envelope["header"]),
        "body": dict(envelope["body"]),
        "signature": {"alg": "ED25519", "keyId": key_id, "value": signature},
    }


def verify_envelope_ed25519(
    envelope: Dict[str, Any], public_key_spki_base64url: str
) -> bool:
    signature = envelope.get("signature")
    if not signature:
        return False
    if signature.get("alg") != "ED25519":
        return False
    unsigned = {"header": envelope["header"], "body": envelope["body"]}
    canonical = canonicalize_envelope(unsigned)
    return verify_canonical_payload_ed25519(
        canonical, signature.get("value", ""), public_key_spki_base64url
    )


# ---------------------------------------------------------------------------
# Wire encode/decode
# ---------------------------------------------------------------------------


def encode_envelope_compact(envelope: Dict[str, Any]) -> str:
    header = envelope["header"]
    body = envelope["body"]
    compact: Dict[str, Any] = {
        "v": header["version"],
        "mid": header["messageId"],
        "ts": header["timestampMs"],
        "ttl": header["ttlMs"],
        "s": header["sender"],
        "n": header["nonce"],
        "i": body["intent"],
        "c": body["content"],
    }
    if "recipient" in header and header["recipient"] is not None:
        compact["r"] = header["recipient"]
    if "capability" in body and body["capability"] is not None:
        compact["cap"] = body["capability"]
    if "correlationId" in body and body["correlationId"] is not None:
        compact["cid"] = body["correlationId"]

    signature = envelope.get("signature")
    if signature:
        compact["sig"] = {
            "a": signature.get("alg", "HS256"),
            "k": signature["keyId"],
            "v": signature["value"],
        }

    return _json_string(compact)


def decode_envelope(raw: str) -> Dict[str, Any]:
    parsed = json.loads(raw)
    if "header" in parsed and "body" in parsed:
        return parsed

    if parsed.get("v") != "7h3/0.1" or "mid" not in parsed or "i" not in parsed:
        raise ValueError("Envelope JSON shape is not recognized")

    header: Dict[str, Any] = {
        "version": parsed["v"],
        "messageId": parsed["mid"],
        "timestampMs": parsed["ts"],
        "ttlMs": parsed["ttl"],
        "sender": parsed["s"],
        "nonce": parsed["n"],
    }
    if "r" in parsed:
        header["recipient"] = parsed["r"]

    body: Dict[str, Any] = {
        "intent": parsed["i"],
        "content": parsed["c"],
    }
    if "cap" in parsed:
        body["capability"] = parsed["cap"]
    if "cid" in parsed:
        body["correlationId"] = parsed["cid"]

    envelope: Dict[str, Any] = {"header": header, "body": body}
    if parsed.get("sig"):
        envelope["signature"] = {
            "alg": parsed["sig"].get("a", "HS256"),
            "keyId": parsed["sig"]["k"],
            "value": parsed["sig"]["v"],
        }
    return envelope


# ---------------------------------------------------------------------------
# Envelope validation
# ---------------------------------------------------------------------------


def _header_str(value: Any) -> str:
    """A header string field, or "" when it is absent or not actually a string.

    `str(value).strip()` is NOT equivalent: it renders None as "None", False as
    "False" and 0 as "0" — all non-empty — so a JSON envelope carrying
    `"nonce": null` or `"sender": 0` would satisfy a presence check while
    carrying no usable identity or replay nonce at all.
    """
    return value.strip() if isinstance(value, str) else ""


def _header_number(value: Any) -> Optional[float]:
    """A finite numeric header field, or None when absent, non-numeric or non-finite.

    bool is excluded deliberately: `isinstance(True, int)` is True in Python, so
    `"ttlMs": true` would otherwise be read as 1. NaN and ±Infinity are excluded
    because every comparison against them is False, which silently defeats the
    TTL ceiling, TTL expiry and clock-skew checks at once — and because int()
    raises on them, which would turn a malformed envelope into an unhandled
    exception inside a request handler rather than a clean rejection.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def validate_envelope(
    envelope: Dict[str, Any], now_ms: Optional[int] = None
) -> list[ProtocolDiagnostic]:
    header = envelope.get("header") or {}
    body = envelope.get("body") or {}
    current = int(now_ms if now_ms is not None else 0)
    diagnostics: list[ProtocolDiagnostic] = []

    if header.get("version") != "7h3/0.1":
        diagnostics.append(
            ProtocolDiagnostic(
                level="error",
                message=f"Unsupported protocol version '{header.get('version')}'",
            )
        )
    if not _header_str(header.get("messageId")):
        diagnostics.append(
            ProtocolDiagnostic(level="error", message="Missing messageId")
        )
    if not _header_str(header.get("sender")):
        diagnostics.append(
            ProtocolDiagnostic(level="error", message="Missing sender identity")
        )
    if not _header_str(header.get("nonce")):
        diagnostics.append(
            ProtocolDiagnostic(
                level="error",
                message="Missing nonce — replay protection requires a unique nonce per message",
            )
        )

    timestamp_ms = _header_number(header.get("timestampMs"))
    ttl_ms = _header_number(header.get("ttlMs"))

    if timestamp_ms is None:
        diagnostics.append(
            ProtocolDiagnostic(
                level="error", message="timestampMs must be a finite number"
            )
        )
    if ttl_ms is None:
        diagnostics.append(
            ProtocolDiagnostic(level="error", message="ttlMs must be a finite number")
        )
    else:
        if ttl_ms <= 0:
            diagnostics.append(
                ProtocolDiagnostic(
                    level="error", message="ttlMs must be greater than zero"
                )
            )
        if ttl_ms > MAX_TTL_MS:
            diagnostics.append(
                ProtocolDiagnostic(
                    level="error",
                    message=f"ttlMs exceeds maximum allowed {MAX_TTL_MS} ms",
                )
            )

    if now_ms is not None and timestamp_ms is not None:
        if timestamp_ms > current + MAX_CLOCK_SKEW_MS:
            diagnostics.append(
                ProtocolDiagnostic(
                    level="error",
                    message=f"timestampMs is more than {MAX_CLOCK_SKEW_MS} ms in the future",
                )
            )
        if ttl_ms is not None and timestamp_ms + ttl_ms < current:
            diagnostics.append(
                ProtocolDiagnostic(level="error", message="Message TTL expired")
            )

    if not _header_str(body.get("content")):
        diagnostics.append(
            ProtocolDiagnostic(level="warning", message="Empty content payload")
        )

    return diagnostics
