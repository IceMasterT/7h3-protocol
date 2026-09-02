"""Tests for protocol_7h3.queue — Queue message binding."""
from __future__ import annotations

import json
import unittest

from protocol_7h3.queue import (
    sign_queue_message,
    verify_queue_message,
    verify_queue_batch,
)
from protocol_7h3.replay import InMemoryReplayStore

# Keys from conformance vectors (PKCS8/SPKI DER, base64url-encoded)
PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEICheZbQGuDVb6hezIlcs0QnCHGxz6IhiLkC9M0qr8OOZ"
PUBLIC_KEY = "MCowBQYDK2VwAyEA-mUFiTQtcKN4nnD19V_-Wyy4q19OivnAutRUPhOcC78"

# A different public key to test wrong-key rejection (second key from test vectors or generated)
OTHER_PUBLIC_KEY = "MCowBQYDK2VwAyEAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


def _make_signed(payload: object) -> str:
    return sign_queue_message(payload, PRIVATE_KEY, sender="test.sender")


class TestSignVerifyRoundTrip(unittest.TestCase):
    def test_string_payload_roundtrip(self):
        """sign_queue_message + verify_queue_message round trip (string payload)."""
        payload = "hello queue"
        signed = _make_signed(payload)
        result = verify_queue_message(signed, PUBLIC_KEY)
        self.assertEqual(result["payload"], payload)
        self.assertIn("envelope", result)
        self.assertIn("header", result["envelope"])
        self.assertIn("signature", result["envelope"])

    def test_dict_payload_roundtrip(self):
        """Round trip with dict payload."""
        payload = {"task": "process", "items": [1, 2, 3], "meta": {"retry": True}}
        signed = _make_signed(payload)
        result = verify_queue_message(signed, PUBLIC_KEY)
        self.assertEqual(result["payload"], payload)
        self.assertIn("signature", result["envelope"])

    def test_verify_raises_on_tampered_envelope(self):
        """verify_queue_message raises on tampered envelope."""
        signed = _make_signed("important data")
        wrapper = json.loads(signed)
        # Tamper with the sender field inside the envelope
        wrapper["envelope"]["header"]["sender"] = "evil.actor"
        tampered = json.dumps(wrapper)
        with self.assertRaises(ValueError) as ctx:
            verify_queue_message(tampered, PUBLIC_KEY)
        self.assertIn("7h3:", str(ctx.exception))

    def test_verify_raises_on_wrong_public_key(self):
        """verify_queue_message raises on wrong public key."""
        # Generate a different key pair by using a known different key from a second vector
        # We use a second private/public pair
        alt_private = "MC4CAQAwBQYDK2VwBCIEIBcJSnDN3_g3o_0K5VJHOO_HqFcBCUt1tnGbqiVoaWyb"
        alt_public = "MCowBQYDK2VwAyEAiFt0vBZq_X5sMCbR5_LhkRKU2ueD80_bqFMhqfYP5TA"
        signed = sign_queue_message("payload", alt_private, sender="test.sender")
        with self.assertRaises(ValueError) as ctx:
            verify_queue_message(signed, PUBLIC_KEY)
        self.assertIn("7h3:", str(ctx.exception))

    def test_verify_raises_on_malformed_json(self):
        """verify_queue_message raises on malformed JSON."""
        with self.assertRaises(ValueError) as ctx:
            verify_queue_message("{not valid json}", PUBLIC_KEY)
        self.assertIn("7h3: malformed queue message", str(ctx.exception))

    def test_verify_raises_on_missing_envelope(self):
        """verify_queue_message raises when envelope key is missing."""
        msg = json.dumps({"payload": "data"})
        with self.assertRaises(ValueError) as ctx:
            verify_queue_message(msg, PUBLIC_KEY)
        self.assertIn("7h3: missing envelope", str(ctx.exception))

    def test_verify_raises_on_expired_message(self):
        """verify_queue_message rejects an expired envelope (TTL now actually enforced)."""
        signed = sign_queue_message("expiring", PRIVATE_KEY, sender="test.sender", ttl_ms=1)
        wrapper = json.loads(signed)
        # Backdate the timestamp well past the 1ms TTL so it's unambiguously expired.
        wrapper["envelope"]["header"]["timestampMs"] -= 60_000
        expired = json.dumps(wrapper)
        with self.assertRaises(ValueError) as ctx:
            verify_queue_message(expired, PUBLIC_KEY)
        self.assertIn("validation failed", str(ctx.exception))

    def test_verify_raises_on_missing_nonce(self):
        """verify_queue_message rejects an envelope with no nonce (replay protection requires it)."""
        signed = sign_queue_message("no-nonce", PRIVATE_KEY, sender="test.sender")
        wrapper = json.loads(signed)
        del wrapper["envelope"]["header"]["nonce"]
        malformed = json.dumps(wrapper)
        with self.assertRaises(ValueError) as ctx:
            verify_queue_message(malformed, PUBLIC_KEY)
        self.assertIn("validation failed", str(ctx.exception))

    def test_replay_rejected_when_replay_store_reused_across_calls(self):
        """A shared InMemoryReplayStore persists across calls and catches replays."""
        replay_store = InMemoryReplayStore()
        signed = _make_signed("once-only")

        first = verify_queue_message(signed, PUBLIC_KEY, replay_store=replay_store)
        self.assertEqual(first["payload"], "once-only")

        with self.assertRaises(ValueError) as ctx:
            verify_queue_message(signed, PUBLIC_KEY, replay_store=replay_store)
        self.assertIn("replay detected", str(ctx.exception))

    def test_no_replay_protection_when_replay_store_omitted(self):
        """Replay protection is opt-in — same nonce twice is allowed with no replay_store."""
        signed = _make_signed("no-dedup")
        first = verify_queue_message(signed, PUBLIC_KEY)
        second = verify_queue_message(signed, PUBLIC_KEY)
        self.assertEqual(first["payload"], "no-dedup")
        self.assertEqual(second["payload"], "no-dedup")


class TestVerifyQueueBatch(unittest.TestCase):
    def test_batch_mixed_ok_and_fail(self):
        """verify_queue_batch: returns correct ok/false mix."""
        valid_msg = _make_signed("valid payload")
        invalid_msg = "not json at all"
        results = verify_queue_batch([valid_msg, invalid_msg], PUBLIC_KEY)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0]["ok"])
        self.assertEqual(results[0]["payload"], "valid payload")
        self.assertFalse(results[1]["ok"])
        self.assertIn("error", results[1])
        self.assertEqual(results[1]["raw"], invalid_msg)

    def test_batch_all_valid(self):
        """verify_queue_batch: all valid messages."""
        messages = [_make_signed(f"msg-{i}") for i in range(3)]
        results = verify_queue_batch(messages, PUBLIC_KEY)
        self.assertEqual(len(results), 3)
        for i, r in enumerate(results):
            self.assertTrue(r["ok"], f"message {i} should be ok")
            self.assertEqual(r["payload"], f"msg-{i}")
            self.assertIn("envelope", r)

    def test_batch_all_invalid_never_throws(self):
        """verify_queue_batch: all invalid messages (never throws)."""
        bad_messages = [
            "not json",
            json.dumps({"no": "envelope"}),
            "",
            "{}",
        ]
        # Must not raise
        results = verify_queue_batch(bad_messages, PUBLIC_KEY)
        self.assertEqual(len(results), len(bad_messages))
        for r in results:
            self.assertFalse(r["ok"])
            self.assertIn("error", r)


if __name__ == "__main__":
    unittest.main()


class QueuePayloadIntegrityTest(unittest.TestCase):
    """The signature covers envelope.body.content, not the sibling "payload"
    field. Returning that field unchecked let an attacker take any validly
    signed message, swap the payload, and have it accepted. Parity with the
    TypeScript and Rust SDKs."""

    def _keys(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
        priv = Ed25519PrivateKey.generate()
        sk = b64(priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        pk = b64(priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        return sk, pk

    def test_rejects_a_swapped_payload_under_a_valid_signature(self):
        sk, pk = self._keys()
        message = sign_queue_message({"job": "reindex", "amount": 10}, sk, "a@b.test", ttl_ms=60_000)
        parsed = json.loads(message)
        # Envelope untouched, so the signature still verifies.
        forged = json.dumps({
            "envelope": parsed["envelope"],
            "payload": {"job": "DROP TABLE users", "amount": 10**9},
        })
        with self.assertRaises(ValueError) as ctx:
            verify_queue_message(forged, pk)
        self.assertIn("does not match the signed content", str(ctx.exception))

    def test_rejects_a_removed_payload(self):
        sk, pk = self._keys()
        message = sign_queue_message({"job": "reindex"}, sk, "a@b.test", ttl_ms=60_000)
        forged = json.dumps({"envelope": json.loads(message)["envelope"]})
        with self.assertRaises(ValueError):
            verify_queue_message(forged, pk)

    def test_still_accepts_an_untouched_message(self):
        sk, pk = self._keys()
        message = sign_queue_message({"job": "reindex", "amount": 10}, sk, "a@b.test", ttl_ms=60_000)
        out = verify_queue_message(message, pk)
        self.assertEqual(out["payload"], {"job": "reindex", "amount": 10})

    def test_round_trips_a_string_payload(self):
        sk, pk = self._keys()
        message = sign_queue_message("plain-text-job", sk, "a@b.test", ttl_ms=60_000)
        self.assertEqual(verify_queue_message(message, pk)["payload"], "plain-text-job")
