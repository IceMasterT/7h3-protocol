"""Tests for protocol_7h3.http — HTTP binding."""
from __future__ import annotations

import json
import time
import unittest

from protocol_7h3.protocol import sign_envelope_ed25519, sign_envelope_hmac
from protocol_7h3.http import (
    DEFAULT_HEADER,
    KeyRegistry,
    StaticKeyRegistry,
    build_signed_request_headers,
    sign_http_request,
    verify_http_envelope,
)

# ED25519 test key pair from conformance vectors (SPKI public / PKCS8 private, base64url)
_TEST_PUBLIC_KEY = "MCowBQYDK2VwAyEA-mUFiTQtcKN4nnD19V_-Wyy4q19OivnAutRUPhOcC78"
_TEST_PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEICheZbQGuDVb6hezIlcs0QnCHGxz6IhiLkC9M0qr8OOZ"
_SENDER = "agent.ed"


def _make_valid_envelope(ttl_ms: int = 60_000) -> dict:
    """Return an unsigned envelope with a current timestamp."""
    now = int(time.time() * 1000)
    return {
        "header": {
            "version": "7h3/0.1",
            "messageId": "test-msg-1",
            "timestampMs": now,
            "ttlMs": ttl_ms,
            "sender": _SENDER,
            "nonce": "test-nonce-1",
        },
        "body": {
            "intent": "TASK",
            "content": "hello http",
        },
    }


def _signed_envelope(ttl_ms: int = 60_000) -> dict:
    env = _make_valid_envelope(ttl_ms=ttl_ms)
    return sign_envelope_ed25519(env, _TEST_PRIVATE_KEY)


def _registry() -> StaticKeyRegistry:
    return StaticKeyRegistry({_SENDER: _TEST_PUBLIC_KEY})


class TestVerifyHttpEnvelopeMissingHeader(unittest.TestCase):
    """1. verify_http_envelope: missing header."""

    def test_missing_header_returns_false_and_reason(self):
        ok, env, reason = verify_http_envelope({}, _registry())
        self.assertFalse(ok)
        self.assertIsNone(env)
        self.assertEqual(reason, "missing-header")

    def test_wrong_header_name_treated_as_missing(self):
        headers = {"x-other-header": "{}"}
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertFalse(ok)
        self.assertEqual(reason, "missing-header")


class TestVerifyHttpEnvelopeInvalidJson(unittest.TestCase):
    """2. verify_http_envelope: invalid JSON."""

    def test_malformed_json(self):
        headers = {DEFAULT_HEADER: "not-json{{{"}
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertFalse(ok)
        self.assertIsNone(env)
        self.assertEqual(reason, "malformed-envelope")

    def test_json_without_required_keys(self):
        headers = {DEFAULT_HEADER: json.dumps({"foo": "bar"})}
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertFalse(ok)
        self.assertEqual(reason, "malformed-envelope")

    def test_json_missing_signature_key(self):
        headers = {DEFAULT_HEADER: json.dumps({"header": {}, "body": {}})}
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertFalse(ok)
        self.assertEqual(reason, "malformed-envelope")


class TestVerifyHttpEnvelopeValidEd25519(unittest.TestCase):
    """3. verify_http_envelope: valid Ed25519 signed envelope."""

    def test_valid_signed_envelope(self):
        signed = _signed_envelope()
        headers = {DEFAULT_HEADER: json.dumps(signed)}
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertTrue(ok)
        self.assertIsNotNone(env)
        self.assertIsNone(reason)

    def test_valid_envelope_mixed_case_header(self):
        """Headers are case-insensitive per HTTP spec."""
        signed = _signed_envelope()
        headers = {"X-7H3-Envelope": json.dumps(signed)}
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_returns_envelope_dict_on_success(self):
        signed = _signed_envelope()
        headers = {DEFAULT_HEADER: json.dumps(signed)}
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertTrue(ok)
        self.assertIn("header", env)
        self.assertIn("body", env)
        self.assertIn("signature", env)


class TestVerifyHttpEnvelopeTampered(unittest.TestCase):
    """4. verify_http_envelope: tampered envelope."""

    def test_tampered_content_fails_verification(self):
        signed = _signed_envelope()
        # Tamper with the body content after signing
        signed["body"]["content"] = "tampered!"
        headers = {DEFAULT_HEADER: json.dumps(signed)}
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertFalse(ok)
        self.assertEqual(reason, "invalid-signature")

    def test_tampered_sender_fails_verification(self):
        signed = _signed_envelope()
        signed["header"]["sender"] = "evil.agent"
        headers = {DEFAULT_HEADER: json.dumps(signed)}
        # evil.agent not in registry → unknown-sender
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertFalse(ok)
        self.assertIn(reason, ("unknown-sender", "invalid-signature"))

    def test_tampered_signature_value_fails(self):
        signed = _signed_envelope()
        signed["signature"]["value"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        headers = {DEFAULT_HEADER: json.dumps(signed)}
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertFalse(ok)
        self.assertEqual(reason, "invalid-signature")


class TestVerifyHttpEnvelopeUnknownSender(unittest.TestCase):
    """5. verify_http_envelope: unknown sender."""

    def test_unknown_sender_ed25519(self):
        signed = _signed_envelope()
        # Empty registry — no known senders
        empty_registry = StaticKeyRegistry({})
        headers = {DEFAULT_HEADER: json.dumps(signed)}
        ok, env, reason = verify_http_envelope(headers, empty_registry)
        self.assertFalse(ok)
        self.assertIsNone(env)
        self.assertEqual(reason, "unknown-sender")

    def test_unknown_sender_hmac(self):
        env = _make_valid_envelope()
        signed = sign_envelope_hmac(env, "mysecret", "key-1")
        headers = {DEFAULT_HEADER: json.dumps(signed)}

        class NoSecretRegistry(KeyRegistry):
            def get_public_key(self, sender_id: str):
                return None
            def get_shared_secret(self, key_id: str):
                return None  # key_id "key-1" unknown

        ok, result, reason = verify_http_envelope(headers, NoSecretRegistry())
        self.assertFalse(ok)
        self.assertEqual(reason, "unknown-sender")


class TestSignHttpRequestRoundTrip(unittest.TestCase):
    """6. sign_http_request + verify_http_envelope round trip."""

    def test_round_trip_succeeds(self):
        unsigned = _make_valid_envelope()
        headers = sign_http_request(unsigned, _TEST_PRIVATE_KEY)
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertTrue(ok)
        self.assertIsNone(reason)
        self.assertEqual(env["body"]["content"], "hello http")

    def test_round_trip_strict_ttl_expired(self):
        # Create envelope that is already expired
        past_ms = int(time.time() * 1000) - 120_000  # 2 minutes ago
        envelope = {
            "header": {
                "version": "7h3/0.1",
                "messageId": "expired-msg",
                "timestampMs": past_ms,
                "ttlMs": 1_000,  # 1 second TTL → already expired
                "sender": _SENDER,
                "nonce": "nonce-x",
            },
            "body": {
                "intent": "TASK",
                "content": "stale",
            },
        }
        signed = sign_envelope_ed25519(envelope, _TEST_PRIVATE_KEY)
        headers = {DEFAULT_HEADER: json.dumps(signed)}
        ok, env, reason = verify_http_envelope(headers, _registry(), strict_ttl=True)
        self.assertFalse(ok)
        self.assertEqual(reason, "ttl-expired")

    def test_round_trip_strict_ttl_disabled(self):
        # Same expired envelope but strict_ttl=False → signature still valid
        past_ms = int(time.time() * 1000) - 120_000
        envelope = {
            "header": {
                "version": "7h3/0.1",
                "messageId": "expired-msg-2",
                "timestampMs": past_ms,
                "ttlMs": 1_000,
                "sender": _SENDER,
                "nonce": "nonce-y",
            },
            "body": {
                "intent": "TASK",
                "content": "stale but skip ttl check",
            },
        }
        signed = sign_envelope_ed25519(envelope, _TEST_PRIVATE_KEY)
        headers = {DEFAULT_HEADER: json.dumps(signed)}
        ok, env, reason = verify_http_envelope(headers, _registry(), strict_ttl=False)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_custom_header_name(self):
        unsigned = _make_valid_envelope()
        custom_hdr = "x-my-agent-envelope"
        headers = sign_http_request(unsigned, _TEST_PRIVATE_KEY, header_name=custom_hdr)
        self.assertIn(custom_hdr, headers)
        ok, env, reason = verify_http_envelope(headers, _registry(), header_name=custom_hdr)
        self.assertTrue(ok)
        self.assertIsNone(reason)


class TestBuildSignedRequestHeaders(unittest.TestCase):
    """7. build_signed_request_headers produces correct header key."""

    def test_default_header_key_present(self):
        headers = build_signed_request_headers(
            sender=_SENDER,
            private_key=_TEST_PRIVATE_KEY,
            content="ping",
        )
        self.assertIn(DEFAULT_HEADER, headers)

    def test_custom_header_key(self):
        custom = "x-aip-envelope"
        headers = build_signed_request_headers(
            sender=_SENDER,
            private_key=_TEST_PRIVATE_KEY,
            content="ping",
            header_name=custom,
        )
        self.assertIn(custom, headers)
        self.assertNotIn(DEFAULT_HEADER, headers)

    def test_header_value_is_valid_json_envelope(self):
        headers = build_signed_request_headers(
            sender=_SENDER,
            private_key=_TEST_PRIVATE_KEY,
            content="check me",
            ttl_ms=30_000,
        )
        raw = headers[DEFAULT_HEADER]
        envelope = json.loads(raw)
        self.assertEqual(envelope["header"]["sender"], _SENDER)
        self.assertEqual(envelope["body"]["content"], "check me")
        self.assertEqual(envelope["signature"]["alg"], "ED25519")

    def test_round_trip_verify(self):
        headers = build_signed_request_headers(
            sender=_SENDER,
            private_key=_TEST_PRIVATE_KEY,
            content="full round trip",
            recipient="agent.receiver",
        )
        ok, env, reason = verify_http_envelope(headers, _registry())
        self.assertTrue(ok)
        self.assertIsNone(reason)
        self.assertEqual(env["body"]["content"], "full round trip")

    def test_recipient_is_included_when_provided(self):
        headers = build_signed_request_headers(
            sender=_SENDER,
            private_key=_TEST_PRIVATE_KEY,
            content="msg",
            recipient="agent.b",
        )
        envelope = json.loads(headers[DEFAULT_HEADER])
        self.assertEqual(envelope["header"].get("recipient"), "agent.b")


if __name__ == "__main__":
    unittest.main()
