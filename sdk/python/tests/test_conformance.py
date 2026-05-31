import json
import pathlib
import unittest

from aip7h3.protocol import (
    canonicalize_envelope,
    decode_envelope,
    encode_envelope_compact,
    sign_canonical_payload_ed25519,
    sign_canonical_payload_hmac,
    sign_envelope_ed25519,
    sign_envelope_hmac,
    validate_envelope,
    verify_canonical_payload_ed25519,
    verify_canonical_payload_hmac,
    verify_envelope_ed25519,
    verify_envelope_hmac,
)


ROOT = pathlib.Path(__file__).resolve().parents[3]
VECTORS_PATH = ROOT / "conformance" / "aip_v0_1.json"


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
