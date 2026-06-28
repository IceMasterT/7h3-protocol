"""Tests for protocol_7h3.queue — Queue message binding."""
from __future__ import annotations

import json
import unittest

from protocol_7h3.queue import (
    sign_queue_message,
    verify_queue_message,
    verify_queue_batch,
)

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
