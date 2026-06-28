"""Tests for the 7h3 Protocol webhook binding."""
from __future__ import annotations

import json
import time
import unittest

from protocol_7h3.webhook import (
    WEBHOOK_SIG_HEADER,
    WEBHOOK_TS_HEADER,
    consume_webhook,
    sign_webhook,
    sign_webhook_hmac,
    verify_webhook,
    verify_webhook_hmac,
)


# ---------------------------------------------------------------------------
# Test key generation helpers
# ---------------------------------------------------------------------------

def _generate_ed25519_keypair_base64url():
    """Generate an Ed25519 keypair using whatever backend is available.

    Returns (private_key_pkcs8_base64url, public_key_spki_base64url).
    """
    import base64
    import hashlib

    # Attempt to use the cryptography package first
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv = Ed25519PrivateKey.generate()
        priv_der = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_der = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        b64 = lambda b: base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
        return b64(priv_der), b64(pub_der)
    except ImportError:
        pass

    # Fallback: use pure-Python implementation from protocol.py internals
    # to build a minimal PKCS8/SPKI DER pair
    import os
    from protocol_7h3.protocol import (
        _py_ed25519_sign,
        _G_BASE,
        _point_mul,
        _compress,
        _seed_from_pkcs8,
        _pubkey_from_spki,
    )

    seed = os.urandom(32)

    # PKCS8 v0 for Ed25519: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 [32-byte seed]
    pkcs8_der = bytes([
        0x30, 0x2e,
        0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20,
    ]) + seed

    # Derive the public key from the seed
    import hashlib as _hashlib
    h = _hashlib.sha512(seed).digest()
    from bytearray import bytearray  # stdlib
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    A_bytes = _compress(_point_mul(a, _G_BASE))

    # SPKI for Ed25519: 30 2a 30 05 06 03 2b 65 70 03 21 00 [32-byte public key]
    spki_der = bytes([
        0x30, 0x2a,
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00,
    ]) + A_bytes

    b64 = lambda b: base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
    return b64(pkcs8_der), b64(spki_der)


def _generate_ed25519_keypair():
    """Return (private_key_b64url, public_key_b64url) using best available backend."""
    import base64
    import os

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv = Ed25519PrivateKey.generate()
        priv_der = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_der = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        b64url = lambda b: base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
        return b64url(priv_der), b64url(pub_der)
    except ImportError:
        pass

    # Pure-Python fallback
    import hashlib as _hashlib
    from protocol_7h3.protocol import _G_BASE, _point_mul, _compress

    seed = os.urandom(32)

    h = _hashlib.sha512(seed).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(bytes(a_bytes), "little")
    A_bytes = _compress(_point_mul(a, _G_BASE))

    pkcs8_der = bytes([
        0x30, 0x2e,
        0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20,
    ]) + seed

    spki_der = bytes([
        0x30, 0x2a,
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00,
    ]) + A_bytes

    b64url = lambda b: base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
    return b64url(pkcs8_der), b64url(spki_der)


def _generate_second_keypair():
    """Generate a second, independent keypair (for wrong-key tests)."""
    return _generate_ed25519_keypair()


# ---------------------------------------------------------------------------
# Test fixtures — generated once per module load
# ---------------------------------------------------------------------------

_PRIV_KEY, _PUB_KEY = _generate_ed25519_keypair()
_PRIV_KEY2, _PUB_KEY2 = _generate_ed25519_keypair()
_HMAC_SECRET = "super-secret-webhook-key-abc123"
_HMAC_SECRET2 = "different-secret-key-xyz789"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSignWebhookEd25519RoundTrip(unittest.TestCase):
    """1. sign_webhook + verify_webhook round trip."""

    def test_str_payload(self):
        payload = '{"event":"user.created","id":"123"}'
        headers = sign_webhook(payload, _PRIV_KEY)
        self.assertIn(WEBHOOK_SIG_HEADER, headers)
        self.assertIn(WEBHOOK_TS_HEADER, headers)
        result = verify_webhook(payload, headers, _PUB_KEY)
        self.assertTrue(result)

    def test_bytes_payload(self):
        payload = b'{"event":"order.shipped"}'
        headers = sign_webhook(payload, _PRIV_KEY)
        result = verify_webhook(payload, headers, _PUB_KEY)
        self.assertTrue(result)

    def test_headers_are_strings(self):
        headers = sign_webhook("hello", _PRIV_KEY)
        self.assertIsInstance(headers[WEBHOOK_SIG_HEADER], str)
        self.assertIsInstance(headers[WEBHOOK_TS_HEADER], str)


class TestSignWebhookHmacRoundTrip(unittest.TestCase):
    """2. sign_webhook_hmac + verify_webhook_hmac round trip."""

    def test_str_payload(self):
        payload = '{"event":"payment.succeeded","amount":9900}'
        headers = sign_webhook_hmac(payload, _HMAC_SECRET)
        self.assertIn(WEBHOOK_SIG_HEADER, headers)
        self.assertIn(WEBHOOK_TS_HEADER, headers)
        result = verify_webhook_hmac(payload, headers, _HMAC_SECRET)
        self.assertTrue(result)

    def test_bytes_payload(self):
        payload = b'{"event":"charge.failed"}'
        headers = sign_webhook_hmac(payload, _HMAC_SECRET)
        result = verify_webhook_hmac(payload, headers, _HMAC_SECRET)
        self.assertTrue(result)

    def test_headers_case_insensitive(self):
        payload = "test-body"
        headers_lower = sign_webhook_hmac(payload, _HMAC_SECRET)
        # Uppercase header keys should still verify
        upper_headers = {k.upper(): v for k, v in headers_lower.items()}
        result = verify_webhook_hmac(payload, upper_headers, _HMAC_SECRET)
        self.assertTrue(result)


class TestTamperedPayload(unittest.TestCase):
    """3. Tampered payload returns False."""

    def test_tampered_ed25519(self):
        original = '{"event":"user.deleted","id":"42"}'
        headers = sign_webhook(original, _PRIV_KEY)
        tampered = '{"event":"user.deleted","id":"99"}'
        result = verify_webhook(tampered, headers, _PUB_KEY)
        self.assertFalse(result)

    def test_tampered_hmac(self):
        original = '{"amount":100}'
        headers = sign_webhook_hmac(original, _HMAC_SECRET)
        tampered = '{"amount":999}'
        result = verify_webhook_hmac(tampered, headers, _HMAC_SECRET)
        self.assertFalse(result)

    def test_tampered_signature_ed25519(self):
        payload = "legitimate-body"
        headers = sign_webhook(payload, _PRIV_KEY)
        headers[WEBHOOK_SIG_HEADER] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        result = verify_webhook(payload, headers, _PUB_KEY)
        self.assertFalse(result)


class TestExpiredTimestamp(unittest.TestCase):
    """4. Expired timestamp returns False (use old timestamp to force expiry)."""

    def test_expired_ed25519(self):
        """Use a timestamp 10 minutes in the past — beyond the 5-min default TTL."""
        payload = '{"event":"subscription.renewed"}'
        headers = sign_webhook(payload, _PRIV_KEY)
        # Overwrite timestamp with something 10 minutes in the past
        old_ts = int(time.time() * 1000) - 600_000
        headers[WEBHOOK_TS_HEADER] = str(old_ts)
        result = verify_webhook(payload, headers, _PUB_KEY)
        self.assertFalse(result)

    def test_expired_hmac(self):
        """Use a timestamp 10 minutes in the past — beyond the 5-min default TTL."""
        payload = '{"event":"invoice.paid"}'
        headers = sign_webhook_hmac(payload, _HMAC_SECRET)
        old_ts = int(time.time() * 1000) - 600_000
        headers[WEBHOOK_TS_HEADER] = str(old_ts)
        result = verify_webhook_hmac(payload, headers, _HMAC_SECRET)
        self.assertFalse(result)

    def test_expired_very_small_max_age(self):
        """Craft headers with old timestamp; use explicit short max_age_ms."""
        payload = "some-body"
        headers = sign_webhook(payload, _PRIV_KEY)
        # Timestamp 1 second old with max_age 500 ms — must fail
        old_ts = int(time.time() * 1000) - 1000
        headers[WEBHOOK_TS_HEADER] = str(old_ts)
        result = verify_webhook(payload, headers, _PUB_KEY, max_age_ms=500)
        self.assertFalse(result)


class TestWrongKey(unittest.TestCase):
    """5. Wrong key returns False."""

    def test_wrong_public_key_ed25519(self):
        payload = '{"event":"user.updated"}'
        headers = sign_webhook(payload, _PRIV_KEY)
        # Verify with a different public key
        result = verify_webhook(payload, headers, _PUB_KEY2)
        self.assertFalse(result)

    def test_wrong_secret_hmac(self):
        payload = '{"event":"payment.failed"}'
        headers = sign_webhook_hmac(payload, _HMAC_SECRET)
        result = verify_webhook_hmac(payload, headers, _HMAC_SECRET2)
        self.assertFalse(result)


class TestConsumeWebhook(unittest.TestCase):
    """6. consume_webhook: valid payload parses JSON and returns dict."""

    def test_valid_payload_returns_dict(self):
        payload = '{"event":"checkout.completed","order_id":"ord-456"}'
        headers = sign_webhook(payload, _PRIV_KEY)
        result = consume_webhook(payload, headers, _PUB_KEY)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["event"], "checkout.completed")
        self.assertEqual(result["order_id"], "ord-456")

    def test_valid_payload_with_nested_json(self):
        data = {"event": "order.created", "data": {"items": [1, 2, 3], "total": 49.99}}
        payload = json.dumps(data)
        headers = sign_webhook(payload, _PRIV_KEY)
        result = consume_webhook(payload, headers, _PUB_KEY)
        self.assertEqual(result["data"]["total"], 49.99)


class TestConsumeWebhookInvalidSig(unittest.TestCase):
    """7. consume_webhook: invalid sig raises ValueError."""

    def test_wrong_key_raises(self):
        payload = '{"event":"refund.issued"}'
        headers = sign_webhook(payload, _PRIV_KEY)
        with self.assertRaises(ValueError) as ctx:
            consume_webhook(payload, headers, _PUB_KEY2)
        self.assertIn("7h3", str(ctx.exception))

    def test_tampered_payload_raises(self):
        original = '{"event":"user.created"}'
        headers = sign_webhook(original, _PRIV_KEY)
        tampered = '{"event":"admin.created"}'
        with self.assertRaises(ValueError):
            consume_webhook(tampered, headers, _PUB_KEY)

    def test_missing_headers_raises(self):
        payload = '{"event":"ping"}'
        with self.assertRaises(ValueError):
            consume_webhook(payload, {}, _PUB_KEY)

    def test_expired_signature_raises(self):
        payload = '{"event":"ping"}'
        headers = sign_webhook(payload, _PRIV_KEY)
        # Overwrite timestamp with 10-minute-old value to force expiry
        old_ts = int(time.time() * 1000) - 600_000
        headers[WEBHOOK_TS_HEADER] = str(old_ts)
        with self.assertRaises(ValueError):
            consume_webhook(payload, headers, _PUB_KEY)


if __name__ == "__main__":
    unittest.main()
