"""
E2E Encryption for 7h3 Protocol — Python SDK

Uses X25519 Diffie-Hellman key exchange + ChaCha20-Poly1305 AEAD.
Requires: pip install cryptography

EncryptedEnvelope = SignedEnvelope where body['content'] is a base64url-encoded
EncryptedPayload JSON, body['intent'] = 'ENCRYPTED',
body['capability'] = 'x25519-chacha20poly1305'
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
except ImportError as exc:
    raise ImportError(
        "7h3/encryption requires the 'cryptography' package. "
        "Install it with: pip install cryptography"
    ) from exc

from .protocol import (
    sign_envelope_ed25519,
    verify_envelope_ed25519,
)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    return base64.urlsafe_b64decode(value + padding)


# ---------------------------------------------------------------------------
# Types (documented shapes, not enforced at runtime)
# ---------------------------------------------------------------------------
# X25519KeyPair: tuple[str, str] = (publicKey_base64url, privateKey_base64url)
# EncryptedPayload dict keys: ephemeralPublic, nonce, ciphertext, tag


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_x25519_keypair() -> Tuple[str, str]:
    """
    Generate a fresh X25519 keypair.

    Returns:
        (public_base64url, private_base64url) — both are raw 32 bytes, base64url-encoded
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return _b64url_encode(pub_raw), _b64url_encode(priv_raw)


# ---------------------------------------------------------------------------
# HKDF key derivation
# ---------------------------------------------------------------------------


def _derive_encryption_key(
    private_key_b64: str,
    peer_public_key_b64: str,
    nonce_b64: str,
) -> bytes:
    """
    X25519 DH + HKDF-SHA256 → 32 bytes for ChaCha20-Poly1305.

    nonce_b64: base64url-encoded 12-byte ChaCha nonce; used as HKDF salt.
    """
    priv_bytes = _b64url_decode(private_key_b64)
    pub_bytes = _b64url_decode(peer_public_key_b64)
    nonce_bytes = _b64url_decode(nonce_b64)

    private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
    public_key = X25519PublicKey.from_public_bytes(pub_bytes)

    shared_secret = private_key.exchange(public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce_bytes,
        info=b"7h3-enc/1",
    )
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# Body encryption / decryption
# ---------------------------------------------------------------------------


def _encrypt_body(
    body: Dict[str, Any],
    recipient_x25519_public_b64: str,
) -> Dict[str, str]:
    """
    Encrypt a protocol body dict.

    Returns EncryptedPayload dict with: ephemeralPublic, nonce, ciphertext, tag
    """
    # Generate ephemeral keypair for forward secrecy
    ephemeral_pub_b64, ephemeral_priv_b64 = generate_x25519_keypair()

    # Random 12-byte ChaCha nonce (also used as HKDF salt)
    nonce12 = os.urandom(12)
    nonce_b64 = _b64url_encode(nonce12)

    # Derive encryption key
    key = _derive_encryption_key(ephemeral_priv_b64, recipient_x25519_public_b64, nonce_b64)

    # Encrypt body as JSON
    plaintext = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    aead = ChaCha20Poly1305(key)
    # ChaCha20Poly1305.encrypt returns ciphertext‖tag (tag is last 16 bytes)
    ct_with_tag = aead.encrypt(nonce12, plaintext, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    return {
        "ephemeralPublic": ephemeral_pub_b64,
        "nonce": nonce_b64,
        "ciphertext": _b64url_encode(ciphertext),
        "tag": _b64url_encode(tag),
    }


def _decrypt_body(
    encrypted_content_b64: str,
    recipient_x25519_private_b64: str,
) -> Dict[str, Any]:
    """
    Decrypt an EncryptedPayload back to a protocol body dict.

    Raises ValueError if AEAD tag verification fails.
    """
    payload_json = _b64url_decode(encrypted_content_b64).decode("utf-8")
    payload = json.loads(payload_json)

    ephemeral_pub_b64 = payload["ephemeralPublic"]
    nonce_b64 = payload["nonce"]
    ciphertext_b64 = payload["ciphertext"]
    tag_b64 = payload["tag"]

    key = _derive_encryption_key(recipient_x25519_private_b64, ephemeral_pub_b64, nonce_b64)

    nonce12 = _b64url_decode(nonce_b64)
    ciphertext = _b64url_decode(ciphertext_b64)
    tag = _b64url_decode(tag_b64)

    aead = ChaCha20Poly1305(key)
    # Re-concatenate ciphertext‖tag for decryption
    ct_with_tag = ciphertext + tag
    plaintext = aead.decrypt(nonce12, ct_with_tag, None)
    return json.loads(plaintext.decode("utf-8"))


# ---------------------------------------------------------------------------
# Envelope-level seal / open
# ---------------------------------------------------------------------------


def seal_envelope(
    envelope: Dict[str, Any],
    recipient_x25519_public_b64: str,
    sender_ed25519_private_b64: str,
) -> Dict[str, Any]:
    """
    Encrypt the envelope body and sign the result with Ed25519.

    The original body is encrypted; the envelope body is replaced with:
      { intent: 'ENCRYPTED', content: <encrypted-payload>, capability: 'x25519-chacha20poly1305' }
    The modified envelope is signed with Ed25519.
    """
    encrypted_payload = _encrypt_body(envelope["body"], recipient_x25519_public_b64)
    encrypted_content = _b64url_encode(
        json.dumps(encrypted_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )

    encrypted_body: Dict[str, Any] = {
        "intent": "ENCRYPTED",
        "content": encrypted_content,
        "capability": "x25519-chacha20poly1305",
    }
    # Preserve correlationId if present
    if "correlationId" in envelope["body"] and envelope["body"]["correlationId"] is not None:
        encrypted_body["correlationId"] = envelope["body"]["correlationId"]

    unsigned = {
        "header": envelope["header"],
        "body": encrypted_body,
    }

    return sign_envelope_ed25519(unsigned, sender_ed25519_private_b64)


def open_envelope(
    envelope: Dict[str, Any],
    recipient_x25519_private_b64: str,
    sender_ed25519_public_b64: str,
) -> Dict[str, Any]:
    """
    Verify Ed25519 signature, then decrypt the body.

    Signature is verified FIRST — decryption only proceeds if valid.

    Returns a dict with:
      'envelope': the signed envelope (with encrypted body)
      'body': the decrypted original ProtocolBody dict

    Raises ValueError if signature is invalid or AEAD tag fails.
    """
    # 1. Verify Ed25519 signature FIRST
    if not verify_envelope_ed25519(envelope, sender_ed25519_public_b64):
        raise ValueError("7h3/encryption: Ed25519 signature verification failed")

    # 2. Decrypt
    body = _decrypt_body(envelope["body"]["content"], recipient_x25519_private_b64)
    return {"envelope": envelope, "body": body}
