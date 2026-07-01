"""
Post-quantum signatures for 7h3 Protocol.

Provides ML-DSA-65 and ML-DSA-87 (formerly Dilithium3 / Dilithium5) via
the dilithium-py pure-Python library.

Install the dependency:
    pip install dilithium-py

Mapping:
    ML-DSA-44  ≈  Dilithium2  (security category 2)
    ML-DSA-65  ≈  Dilithium3  (security category 3)
    ML-DSA-87  ≈  Dilithium5  (security category 5)
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional dilithium-py backend
# ---------------------------------------------------------------------------

try:
    from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5  # type: ignore[import]

    _HAS_DILITHIUM = True
except ImportError:
    _HAS_DILITHIUM = False


def _require_dilithium() -> None:
    if not _HAS_DILITHIUM:
        raise ImportError(
            "dilithium-py is required for post-quantum signatures.\n"
            "Install it with:\n\n"
            "    pip install dilithium-py\n"
        )


# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------


def _to_b64url(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_b64url(value: str) -> bytes:
    """Decode base64url (with or without padding)."""
    padded = value + "=" * ((-len(value)) % 4)
    return base64.urlsafe_b64decode(padded)


# ---------------------------------------------------------------------------
# Level → Dilithium implementation mapping
# ---------------------------------------------------------------------------

_LEVEL_MAP = {
    44: "Dilithium2",
    65: "Dilithium3",
    87: "Dilithium5",
}


def _get_impl(level: int) -> Any:
    """Return the Dilithium implementation for the given ML-DSA level."""
    _require_dilithium()
    if level == 44:
        return Dilithium2
    if level == 65:
        return Dilithium3
    if level == 87:
        return Dilithium5
    raise ValueError(f"Unsupported ML-DSA level: {level}. Use 44, 65, or 87.")


def _alg_name(level: int) -> str:
    if level == 44:
        return "ML-DSA-44"
    if level == 65:
        return "ML-DSA-65"
    if level == 87:
        return "ML-DSA-87"
    raise ValueError(f"Unsupported ML-DSA level: {level}")


# ---------------------------------------------------------------------------
# Canonicalization (mirrors TypeScript canonicalizeEnvelope)
# ---------------------------------------------------------------------------


def _canonicalize_envelope(envelope: Dict[str, Any]) -> str:
    """Produce the canonical JSON string for signing (matches TS implementation)."""
    header = envelope["header"]
    body = envelope["body"]

    # Build canonical header (sorted keys, only defined fields)
    header_parts: list[str] = [
        f'"messageId":{json.dumps(header["messageId"])}',
        f'"nonce":{json.dumps(header["nonce"])}',
    ]
    if header.get("recipient") is not None:
        header_parts.append(f'"recipient":{json.dumps(header["recipient"])}')
    header_parts.append(f'"sender":{json.dumps(header["sender"])}')
    header_parts.append(f'"timestampMs":{header["timestampMs"]}')
    header_parts.append(f'"ttlMs":{header["ttlMs"]}')
    header_parts.append(f'"version":{json.dumps(header["version"])}')
    canonical_header = "{" + ",".join(header_parts) + "}"

    # Build canonical body (sorted keys, only defined fields)
    body_parts: list[str] = []
    if body.get("capability") is not None:
        body_parts.append(f'"capability":{json.dumps(body["capability"])}')
    body_parts.append(f'"content":{json.dumps(body["content"])}')
    if body.get("correlationId") is not None:
        body_parts.append(f'"correlationId":{json.dumps(body["correlationId"])}')
    body_parts.append(f'"intent":{json.dumps(body["intent"])}')
    canonical_body = "{" + ",".join(body_parts) + "}"

    return '{"body":' + canonical_body + ',"header":' + canonical_header + "}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_ml_dsa_keypair(level: int = 65) -> Tuple[str, str]:
    """
    Generate a fresh ML-DSA keypair.

    Parameters
    ----------
    level : int
        Security level: 44 (≈ ML-DSA-44), 65 (≈ ML-DSA-65), 87 (≈ ML-DSA-87).
        Default is 65.

    Returns
    -------
    (public_key_b64url, secret_key_b64url) : tuple[str, str]
        Both keys encoded as base64url without padding.
    """
    impl = _get_impl(level)
    pk, sk = impl.keygen()
    return _to_b64url(pk), _to_b64url(sk)


def sign_envelope_pq(
    envelope_dict: Dict[str, Any],
    secret_key_b64url: str,
    level: int = 65,
) -> Dict[str, Any]:
    """
    Sign a protocol envelope dict with ML-DSA.

    Parameters
    ----------
    envelope_dict : dict
        Envelope with 'header' and 'body' keys. Any existing 'signature' is ignored.
    secret_key_b64url : str
        Base64url-encoded secret key (from generate_ml_dsa_keypair).
    level : int
        ML-DSA security level (44, 65, or 87). Default 65.

    Returns
    -------
    dict
        Copy of envelope_dict with 'signature' populated.
    """
    impl = _get_impl(level)
    alg = _alg_name(level)

    # Strip existing signature for canonicalization
    unsigned = {k: v for k, v in envelope_dict.items() if k != "signature"}
    canonical = _canonicalize_envelope(unsigned)
    message = canonical.encode("utf-8")

    sk = _from_b64url(secret_key_b64url)
    sig_bytes = impl.sign(sk, message)
    sig_b64url = _to_b64url(sig_bytes)
    key_id = secret_key_b64url[:16]

    return {
        **unsigned,
        "signature": {
            "alg": alg,
            "keyId": key_id,
            "value": sig_b64url,
        },
    }


def verify_envelope_pq(
    envelope_dict: Dict[str, Any],
    public_key_b64url: str,
    level: Optional[int] = None,
) -> bool:
    """
    Verify a ML-DSA-signed protocol envelope.

    Parameters
    ----------
    envelope_dict : dict
        Signed envelope with 'signature' key.
    public_key_b64url : str
        Base64url-encoded public key.
    level : int or None
        ML-DSA security level. If None, inferred from signature.alg field.

    Returns
    -------
    bool
        True if the signature is valid, False otherwise.
    """
    sig = envelope_dict.get("signature")
    if not sig:
        return False

    alg: str = sig.get("alg", "")
    if level is None:
        # Infer level from alg field
        _alg_to_level = {"ML-DSA-44": 44, "ML-DSA-65": 65, "ML-DSA-87": 87}
        level = _alg_to_level.get(alg)
        if level is None:
            return False

    impl = _get_impl(level)
    unsigned = {k: v for k, v in envelope_dict.items() if k != "signature"}
    canonical = _canonicalize_envelope(unsigned)
    message = canonical.encode("utf-8")

    pk = _from_b64url(public_key_b64url)
    try:
        sig_bytes = _from_b64url(sig["value"])
        return bool(impl.verify(pk, message, sig_bytes))
    except Exception:
        return False
