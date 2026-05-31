from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, TypedDict

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - optional dependency
    _HAS_CRYPTOGRAPHY = False


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


def _json_string(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    return base64.urlsafe_b64decode(value + padding)


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


def sign_canonical_payload_ed25519(
    canonical_payload: str, private_key_pkcs8_base64url: str
) -> str:
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography package is required for ED25519 operations")

    private_der = _base64url_decode(private_key_pkcs8_base64url)
    private_key = serialization.load_der_private_key(private_der, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Invalid ED25519 private key")
    signature = private_key.sign(canonical_payload.encode("utf-8"))
    return _base64url(signature)


def verify_canonical_payload_ed25519(
    canonical_payload: str, signature: str, public_key_spki_base64url: str
) -> bool:
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography package is required for ED25519 operations")

    public_der = _base64url_decode(public_key_spki_base64url)
    public_key = serialization.load_der_public_key(public_der)
    if not isinstance(public_key, Ed25519PublicKey):
        return False

    try:
        public_key.verify(
            _base64url_decode(signature), canonical_payload.encode("utf-8")
        )
        return True
    except Exception:
        return False


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

    if parsed.get("v") != "aip/0.1" or "mid" not in parsed or "i" not in parsed:
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

    envelope: Dict[str, Any] = {
        "header": header,
        "body": body,
    }
    if parsed.get("sig"):
        envelope["signature"] = {
            "alg": parsed["sig"].get("a", "HS256"),
            "keyId": parsed["sig"]["k"],
            "value": parsed["sig"]["v"],
        }
    return envelope


def validate_envelope(
    envelope: Dict[str, Any], now_ms: Optional[int] = None
) -> list[ProtocolDiagnostic]:
    header = envelope["header"]
    body = envelope["body"]
    current = int(now_ms if now_ms is not None else 0)
    diagnostics: list[ProtocolDiagnostic] = []

    if header.get("version") != "aip/0.1":
        diagnostics.append(
            ProtocolDiagnostic(
                level="error",
                message=f"Unsupported protocol version '{header.get('version')}'",
            )
        )
    if not str(header.get("messageId", "")).strip():
        diagnostics.append(
            ProtocolDiagnostic(level="error", message="Missing messageId")
        )
    if not str(header.get("sender", "")).strip():
        diagnostics.append(
            ProtocolDiagnostic(level="error", message="Missing sender identity")
        )
    if int(header.get("ttlMs", 0)) <= 0:
        diagnostics.append(
            ProtocolDiagnostic(level="error", message="ttlMs must be greater than zero")
        )

    if now_ms is not None:
        if int(header.get("timestampMs", 0)) + int(header.get("ttlMs", 0)) < current:
            diagnostics.append(
                ProtocolDiagnostic(level="error", message="Message TTL expired")
            )

    if not str(body.get("content", "")).strip():
        diagnostics.append(
            ProtocolDiagnostic(level="warning", message="Empty content payload")
        )

    return diagnostics
