"""Tests for protocol_7h3.encryption — X25519 + ChaCha20-Poly1305 E2E encryption."""
from __future__ import annotations

import base64
import json
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from protocol_7h3.encryption import (
    generate_x25519_keypair,
    seal_envelope,
    open_envelope,
    _encrypt_body,
    _decrypt_body,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _generate_ed25519_keypair():
    """Generate Ed25519 keypair in PKCS8/SPKI DER format (base64url) — matches TS protocol.ts."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_der = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _b64url_encode(priv_der), _b64url_encode(pub_der)


def _make_envelope(body: dict) -> dict:
    now_ms = int(time.time() * 1000)
    return {
        "header": {
            "version": "7h3/0.1",
            "messageId": f"msg-{now_ms}-test",
            "timestampMs": now_ms,
            "ttlMs": 60_000,
            "sender": "agent-alice",
            "recipient": "agent-bob",
            "nonce": _b64url_encode(__import__("os").urandom(12)),
        },
        "body": body,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGenerateX25519Keypair(unittest.TestCase):
    """Test 1: generate_x25519_keypair returns 32-byte base64url keys."""

    def test_key_format(self):
        pub, priv = generate_x25519_keypair()
        # base64url of 32 bytes = 43 chars (no padding)
        self.assertRegex(pub, r"^[A-Za-z0-9_-]{43}$")
        self.assertRegex(priv, r"^[A-Za-z0-9_-]{43}$")
        # Decoded must be exactly 32 bytes
        padding = "=" * ((4 - (len(pub) % 4)) % 4)
        self.assertEqual(len(base64.urlsafe_b64decode(pub + padding)), 32)
        padding = "=" * ((4 - (len(priv) % 4)) % 4)
        self.assertEqual(len(base64.urlsafe_b64decode(priv + padding)), 32)


class TestSealAndOpenEnvelope(unittest.TestCase):
    """Test 2: sealEnvelope + openEnvelope round-trip recovers original body exactly."""

    def test_round_trip(self):
        recipient_pub, recipient_priv = generate_x25519_keypair()
        sender_priv_ed, sender_pub_ed = _generate_ed25519_keypair()

        original_body = {
            "intent": "TASK",
            "content": "Hello encrypted world!",
            "capability": "some-cap",
            "correlationId": "corr-123",
        }
        envelope = _make_envelope(original_body)

        sealed = seal_envelope(envelope, recipient_pub, sender_priv_ed)
        result = open_envelope(sealed, recipient_priv, sender_pub_ed)
        body = result["body"]

        self.assertEqual(body["intent"], original_body["intent"])
        self.assertEqual(body["content"], original_body["content"])
        self.assertEqual(body.get("capability"), original_body["capability"])
        self.assertEqual(body.get("correlationId"), original_body["correlationId"])


class TestWrongRecipientKey(unittest.TestCase):
    """Test 3: fails with wrong recipient private key (AEAD tag mismatch)."""

    def test_wrong_key_fails(self):
        recipient_pub, _ = generate_x25519_keypair()
        _, wrong_priv = generate_x25519_keypair()
        sender_priv_ed, sender_pub_ed = _generate_ed25519_keypair()

        envelope = _make_envelope({"intent": "PING", "content": "secret"})
        sealed = seal_envelope(envelope, recipient_pub, sender_priv_ed)

        # Use _decrypt_body directly to bypass signature check (wrong key scenario)
        with self.assertRaises(Exception):
            _decrypt_body(sealed["body"]["content"], wrong_priv)


class TestTamperedSignature(unittest.TestCase):
    """Test 4: fails if envelope signature is tampered."""

    def test_tampered_signature(self):
        recipient_pub, recipient_priv = generate_x25519_keypair()
        sender_priv_ed, sender_pub_ed = _generate_ed25519_keypair()

        envelope = _make_envelope({"intent": "PING", "content": "secret"})
        sealed = seal_envelope(envelope, recipient_pub, sender_priv_ed)

        # Tamper with signature
        tampered = dict(sealed)
        tampered["signature"] = dict(sealed["signature"])
        tampered["signature"]["value"] = "A" * 86  # wrong Ed25519 sig

        with self.assertRaises(ValueError) as ctx:
            open_envelope(tampered, recipient_priv, sender_pub_ed)
        self.assertIn("signature", str(ctx.exception).lower())


class TestTamperedCiphertext(unittest.TestCase):
    """Test 5: fails if ciphertext tampered (AEAD auth tag fails)."""

    def test_tampered_ciphertext(self):
        recipient_pub, recipient_priv = generate_x25519_keypair()

        body = {"intent": "PING", "content": "secret"}
        encrypted_payload_dict = _encrypt_body(body, recipient_pub)

        # Flip bits in ciphertext
        import base64
        ct_bytes = bytearray(base64.urlsafe_b64decode(
            encrypted_payload_dict["ciphertext"] + "=" * ((4 - len(encrypted_payload_dict["ciphertext"]) % 4) % 4)
        ))
        ct_bytes[0] ^= 0xFF
        encrypted_payload_dict["ciphertext"] = base64.urlsafe_b64encode(bytes(ct_bytes)).decode().rstrip("=")

        # Re-encode payload
        tampered_content = _b64url_encode(
            json.dumps(encrypted_payload_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )

        with self.assertRaises(Exception):
            _decrypt_body(tampered_content, recipient_priv)


class TestEphemeralRandomness(unittest.TestCase):
    """Test 6: Two seal calls on same body produce different ciphertexts."""

    def test_different_ciphertexts(self):
        recipient_pub, _ = generate_x25519_keypair()
        sender_priv_ed, _ = _generate_ed25519_keypair()

        envelope1 = _make_envelope({"intent": "PING", "content": "same content"})
        envelope2 = _make_envelope({"intent": "PING", "content": "same content"})

        sealed1 = seal_envelope(envelope1, recipient_pub, sender_priv_ed)
        sealed2 = seal_envelope(envelope2, recipient_pub, sender_priv_ed)

        self.assertNotEqual(sealed1["body"]["content"], sealed2["body"]["content"])


class TestEncryptedContentOpaque(unittest.TestCase):
    """Test 7: Encrypted content is opaque (does not contain original body.content)."""

    def test_content_is_opaque(self):
        recipient_pub, _ = generate_x25519_keypair()
        sender_priv_ed, _ = _generate_ed25519_keypair()

        original_content = "super-secret-data-12345"
        envelope = _make_envelope({"intent": "TASK", "content": original_content})

        sealed = seal_envelope(envelope, recipient_pub, sender_priv_ed)

        # The encrypted content (as JSON) should not reveal the original string
        encrypted_content_decoded = base64.urlsafe_b64decode(
            sealed["body"]["content"] + "=" * ((4 - len(sealed["body"]["content"]) % 4) % 4)
        ).decode("utf-8")
        self.assertNotIn(original_content, encrypted_content_decoded)
        self.assertNotIn(original_content, sealed["body"]["content"])


if __name__ == "__main__":
    unittest.main()
