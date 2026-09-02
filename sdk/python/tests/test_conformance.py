import json
import pathlib
import unittest

from protocol_7h3.protocol import (
    canonicalize_envelope,
    decode_envelope,
    encode_envelope_compact,
    sign_canonical_payload_ed25519,
    sign_canonical_payload_hmac,
    sign_envelope_ed25519,
    sign_envelope_hmac,
    validate_envelope,
    MAX_CLOCK_SKEW_MS,
    verify_canonical_payload_ed25519,
    verify_canonical_payload_hmac,
    verify_envelope_ed25519,
    verify_envelope_hmac,
)


ROOT = pathlib.Path(__file__).resolve().parents[3]
VECTORS_PATH = ROOT / "conformance" / "7h3_v0_1.json"


class ConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with VECTORS_PATH.open("r", encoding="utf-8") as handle:
            cls.payload = json.load(handle)

    def test_vectors_match_canonical_and_signatures(self) -> None:
        for vector in self.payload["vectors"]:
            envelope = vector["envelope"]
            canonical = canonicalize_envelope(envelope)
            self.assertEqual(canonical, vector["canonical"])

            signature = sign_canonical_payload_hmac(canonical, vector["secret"])
            self.assertEqual(signature, vector["signature"])
            self.assertTrue(
                verify_canonical_payload_hmac(canonical, signature, vector["secret"])
            )
            self.assertFalse(
                verify_canonical_payload_hmac(
                    canonical, signature, vector["secret"] + "-bad"
                )
            )

            signed = sign_envelope_hmac(envelope, vector["secret"], vector["keyId"])
            self.assertTrue(verify_envelope_hmac(signed, vector["secret"]))
            self.assertFalse(verify_envelope_hmac(signed, vector["secret"] + "-bad"))

    def test_compact_roundtrip(self) -> None:
        for vector in self.payload["vectors"]:
            signed = sign_envelope_hmac(
                vector["envelope"], vector["secret"], vector["keyId"]
            )
            raw = encode_envelope_compact(signed)
            decoded = decode_envelope(raw)
            self.assertEqual(decoded, signed)

    def test_ttl_validation(self) -> None:
        vector = self.payload["vectors"][0]
        envelope = vector["envelope"]

        valid = validate_envelope(
            envelope, now_ms=envelope["header"]["timestampMs"] + 1
        )
        self.assertFalse(any(d.message == "Message TTL expired" for d in valid))

        expired = validate_envelope(
            envelope,
            now_ms=envelope["header"]["timestampMs"] + envelope["header"]["ttlMs"] + 1,
        )
        self.assertTrue(any(d.message == "Message TTL expired" for d in expired))

    def test_ttl_ceiling(self) -> None:
        from protocol_7h3.protocol import MAX_TTL_MS

        vector = self.payload["vectors"][0]
        envelope = json.loads(json.dumps(vector["envelope"]))
        envelope["header"]["ttlMs"] = MAX_TTL_MS + 1

        diags = validate_envelope(envelope)
        self.assertTrue(any("exceeds maximum" in d.message for d in diags))

        # Exactly at the ceiling stays valid
        envelope["header"]["ttlMs"] = MAX_TTL_MS
        diags = validate_envelope(envelope)
        self.assertFalse(any(d.level == "error" for d in diags))

    def test_nonce_required(self) -> None:
        # Cross-language parity: the TS validateEnvelope has always required a
        # nonce (replay protection depends on it); the Python port previously
        # didn't check for one at all.
        vector = self.payload["vectors"][0]
        envelope = dict(vector["envelope"])
        header = dict(envelope["header"])
        envelope["header"] = header

        present = validate_envelope(envelope)
        self.assertFalse(any("nonce" in d.message.lower() for d in present))

        del header["nonce"]
        missing = validate_envelope(envelope)
        self.assertTrue(any("nonce" in d.message.lower() for d in missing))

    def test_ed25519_vectors_if_crypto_available(self) -> None:
        vectors = self.payload.get("ed25519Vectors", [])
        if not vectors:
            self.skipTest("No ED25519 vectors present")

        for vector in vectors:
            envelope = vector["envelope"]
            canonical = canonicalize_envelope(envelope)
            self.assertEqual(canonical, vector["canonical"])

            try:
                signature = sign_canonical_payload_ed25519(
                    canonical, vector["privateKey"]
                )
            except RuntimeError as exc:
                if "cryptography package is required" in str(exc):
                    self.skipTest("cryptography package unavailable for ED25519")
                raise

            self.assertEqual(signature, vector["signature"])
            self.assertTrue(
                verify_canonical_payload_ed25519(
                    canonical, signature, vector["publicKey"]
                )
            )

            signed = sign_envelope_ed25519(
                envelope, vector["privateKey"], vector["keyId"]
            )
            self.assertTrue(verify_envelope_ed25519(signed, vector["publicKey"]))
            self.assertEqual(signed["signature"]["alg"], "ED25519")


if __name__ == "__main__":
    unittest.main()


class ClockSkewCeilingTest(unittest.TestCase):
    """Parity with the TypeScript, Rust and Go SDKs: a post-dated timestamp is
    rejected, because MAX_TTL_MS alone cannot bound how long an envelope lives."""

    def _envelope(self, timestamp_ms: int):
        return {
            "header": {
                "version": "7h3/0.1",
                "messageId": "msg-1",
                "timestampMs": timestamp_ms,
                "ttlMs": 60_000,
                "sender": "a@b.test",
                "nonce": "abc123",
            },
            "body": {"intent": "TASK", "content": "x"},
        }

    def test_rejects_post_dated_timestamp(self):
        now = 1_700_000_000_000
        diags = validate_envelope(self._envelope(now + 31_536_000_000), now)
        self.assertTrue(
            any(d.level == "error" and "in the future" in d.message for d in diags)
        )

    def test_tolerates_timestamp_within_skew(self):
        now = 1_700_000_000_000
        diags = validate_envelope(self._envelope(now + MAX_CLOCK_SKEW_MS - 1_000), now)
        self.assertEqual([d for d in diags if d.level == "error"], [])
