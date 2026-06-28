"""Tests for protocol_7h3.keys — key infrastructure."""
from __future__ import annotations

import json
import time
import unittest

from protocol_7h3.keys import (
    KeyEntry,
    KeyRotationManager,
    ManagedKeyPair,
    RevocationRegistry,
    WellKnownKeysDocument,
)
from protocol_7h3.http import StaticKeyRegistry


class TestWellKnownKeysDocumentRoundTrip(unittest.TestCase):
    """Test 1: WellKnownKeysDocument.to_json / from_json round trip."""

    def test_round_trip_basic(self):
        now = int(time.time() * 1000)
        original = WellKnownKeysDocument(
            version="7h3/0.1",
            updated=now,
            keys=[
                KeyEntry(
                    id="key-abc",
                    algorithm="Ed25519",
                    public_key="MCowBQYDK2VwAyEAAABBBBCCDDEEFF==",
                    created=now - 1000,
                ),
                KeyEntry(
                    id="key-def",
                    algorithm="Ed25519",
                    public_key="MCowBQYDK2VwAyEA11223344==",
                    created=now - 500,
                    expires=now + 3600000,
                ),
            ],
        )

        serialized = original.to_json()
        parsed = json.loads(serialized)

        # Check top-level structure
        self.assertEqual(parsed["version"], "7h3/0.1")
        self.assertEqual(parsed["updated"], now)
        self.assertEqual(len(parsed["keys"]), 2)

        # Deserialize
        restored = WellKnownKeysDocument.from_json(serialized)
        self.assertEqual(restored.version, original.version)
        self.assertEqual(restored.updated, original.updated)
        self.assertEqual(len(restored.keys), 2)

        k0 = restored.keys[0]
        self.assertEqual(k0.id, "key-abc")
        self.assertEqual(k0.algorithm, "Ed25519")
        self.assertEqual(k0.public_key, "MCowBQYDK2VwAyEAAABBBBCCDDEEFF==")
        self.assertEqual(k0.created, now - 1000)
        self.assertIsNone(k0.expires)
        self.assertFalse(k0.revoked)

        k1 = restored.keys[1]
        self.assertEqual(k1.id, "key-def")
        self.assertEqual(k1.expires, now + 3600000)

    def test_round_trip_with_revoked_key(self):
        now = int(time.time() * 1000)
        original = WellKnownKeysDocument(
            version="7h3/0.1",
            updated=now,
            keys=[
                KeyEntry(
                    id="key-revoked",
                    algorithm="Ed25519",
                    public_key="MCowBQYDK2VwAyEA==",
                    created=now - 10000,
                    revoked=True,
                    revoked_at=now - 5000,
                ),
            ],
        )

        serialized = original.to_json()
        restored = WellKnownKeysDocument.from_json(serialized)

        k = restored.keys[0]
        self.assertTrue(k.revoked)
        self.assertEqual(k.revoked_at, now - 5000)

    def test_to_json_omits_optional_fields_when_absent(self):
        now = int(time.time() * 1000)
        doc = WellKnownKeysDocument(
            version="7h3/0.1",
            updated=now,
            keys=[
                KeyEntry(
                    id="key-minimal",
                    algorithm="Ed25519",
                    public_key="abc123==",
                    created=now,
                ),
            ],
        )
        serialized = doc.to_json()
        parsed = json.loads(serialized)
        k = parsed["keys"][0]
        self.assertNotIn("expires", k)
        self.assertNotIn("revoked", k)
        self.assertNotIn("revokedAt", k)


class TestStaticKeyRegistry(unittest.TestCase):
    """Test 2: StaticKeyRegistry (from http.py) get_public_key."""

    def test_get_public_key_returns_registered_key(self):
        registry = StaticKeyRegistry({"agent-alice": "MCowBQYDK2VwAyEAAlice=="})
        result = registry.get_public_key("agent-alice")
        self.assertEqual(result, "MCowBQYDK2VwAyEAAlice==")

    def test_get_public_key_returns_none_for_unknown(self):
        registry = StaticKeyRegistry({"agent-alice": "MCowBQYDK2VwAyEAAlice=="})
        result = registry.get_public_key("agent-unknown")
        self.assertIsNone(result)

    def test_get_public_key_empty_registry(self):
        registry = StaticKeyRegistry({})
        self.assertIsNone(registry.get_public_key("any-id"))

    def test_get_public_key_multiple_keys(self):
        keys = {
            "alice": "pub-alice",
            "bob": "pub-bob",
            "carol": "pub-carol",
        }
        registry = StaticKeyRegistry(keys)
        self.assertEqual(registry.get_public_key("alice"), "pub-alice")
        self.assertEqual(registry.get_public_key("bob"), "pub-bob")
        self.assertEqual(registry.get_public_key("carol"), "pub-carol")


class TestRevocationRegistryRevokeAndIsRevoked(unittest.TestCase):
    """Test 3: RevocationRegistry: revoke + is_revoked."""

    def test_revoke_marks_key_as_revoked(self):
        reg = RevocationRegistry()
        reg.revoke("key-abc")
        self.assertTrue(reg.is_revoked("key-abc"))

    def test_is_revoked_returns_false_for_unrevo_key(self):
        reg = RevocationRegistry()
        reg.revoke("key-abc")
        self.assertFalse(reg.is_revoked("key-xyz"))

    def test_revoke_with_reason(self):
        reg = RevocationRegistry()
        reg.revoke("key-compromised", reason="private key leak")
        self.assertTrue(reg.is_revoked("key-compromised"))

    def test_revoke_multiple_keys(self):
        reg = RevocationRegistry()
        reg.revoke("key-1")
        reg.revoke("key-2")
        self.assertTrue(reg.is_revoked("key-1"))
        self.assertTrue(reg.is_revoked("key-2"))
        self.assertFalse(reg.is_revoked("key-3"))

    def test_empty_registry_returns_false(self):
        reg = RevocationRegistry()
        self.assertFalse(reg.is_revoked("key-anything"))


class TestRevocationRegistryGetList(unittest.TestCase):
    """Test 4: RevocationRegistry: get_list returns correct structure."""

    def test_get_list_structure_when_empty(self):
        reg = RevocationRegistry()
        result = reg.get_list()
        self.assertEqual(result["version"], "7h3/0.1")
        self.assertIn("updated", result)
        self.assertIsInstance(result["updated"], int)
        self.assertEqual(result["revokedKeys"], [])

    def test_get_list_contains_revoked_key(self):
        reg = RevocationRegistry()
        before = int(time.time() * 1000)
        reg.revoke("key-foo", reason="expired")
        after = int(time.time() * 1000)

        result = reg.get_list()
        self.assertEqual(result["version"], "7h3/0.1")
        self.assertEqual(len(result["revokedKeys"]), 1)

        entry = result["revokedKeys"][0]
        self.assertEqual(entry["id"], "key-foo")
        self.assertGreaterEqual(entry["revokedAt"], before)
        self.assertLessEqual(entry["revokedAt"], after)
        self.assertEqual(entry["reason"], "expired")

    def test_get_list_omits_reason_when_none(self):
        reg = RevocationRegistry()
        reg.revoke("key-noreaso")
        result = reg.get_list()
        entry = result["revokedKeys"][0]
        self.assertNotIn("reason", entry)

    def test_get_list_multiple_revoked(self):
        reg = RevocationRegistry()
        reg.revoke("key-a")
        reg.revoke("key-b")
        result = reg.get_list()
        ids = {e["id"] for e in result["revokedKeys"]}
        self.assertIn("key-a", ids)
        self.assertIn("key-b", ids)


class TestRevocationRegistryImportList(unittest.TestCase):
    """Test 5: RevocationRegistry: import_list merges entries."""

    def test_import_list_adds_entries(self):
        reg = RevocationRegistry()
        revocation_list = {
            "version": "7h3/0.1",
            "updated": int(time.time() * 1000),
            "revokedKeys": [
                {"id": "key-remote-1", "revokedAt": 1700000000000},
                {"id": "key-remote-2", "revokedAt": 1700000001000, "reason": "compromised"},
            ],
        }
        reg.import_list(revocation_list)

        self.assertTrue(reg.is_revoked("key-remote-1"))
        self.assertTrue(reg.is_revoked("key-remote-2"))

    def test_import_list_does_not_overwrite_existing(self):
        reg = RevocationRegistry()
        local_revoked_at = int(time.time() * 1000)
        reg.revoke("key-shared")

        revocation_list = {
            "revokedKeys": [
                {"id": "key-shared", "revokedAt": 1000000000000, "reason": "remote"},
            ]
        }
        reg.import_list(revocation_list)

        # Should still be revoked; original entry should be kept (not overwritten)
        self.assertTrue(reg.is_revoked("key-shared"))
        # Check that the local timestamp is preserved (not overwritten by remote)
        result = reg.get_list()
        entry = next(e for e in result["revokedKeys"] if e["id"] == "key-shared")
        self.assertGreaterEqual(entry["revokedAt"], local_revoked_at - 100)

    def test_import_list_merges_new_and_existing(self):
        reg = RevocationRegistry()
        reg.revoke("key-existing")

        revocation_list = {
            "revokedKeys": [
                {"id": "key-new-from-remote", "revokedAt": 1700000000000},
            ]
        }
        reg.import_list(revocation_list)

        self.assertTrue(reg.is_revoked("key-existing"))
        self.assertTrue(reg.is_revoked("key-new-from-remote"))

    def test_import_empty_list(self):
        reg = RevocationRegistry()
        reg.import_list({"revokedKeys": []})
        result = reg.get_list()
        self.assertEqual(result["revokedKeys"], [])


class TestKeyRotationManagerAddKeyGetCurrentKey(unittest.TestCase):
    """Test 6: KeyRotationManager: add_key + get_current_key returns newest."""

    def test_get_current_key_returns_none_when_empty(self):
        mgr = KeyRotationManager()
        self.assertIsNone(mgr.get_current_key())

    def test_get_current_key_returns_added_key(self):
        mgr = KeyRotationManager()
        now = int(time.time() * 1000)
        pair = ManagedKeyPair(
            id="key-1", public_key="pub-1", private_key="priv-1", created=now
        )
        mgr.add_key(pair)
        result = mgr.get_current_key()
        self.assertIsNotNone(result)
        self.assertEqual(result.id, "key-1")

    def test_get_current_key_returns_newest_of_multiple(self):
        mgr = KeyRotationManager()
        now = int(time.time() * 1000)
        old_pair = ManagedKeyPair(
            id="key-old", public_key="pub-old", private_key="priv-old",
            created=now - 10000
        )
        new_pair = ManagedKeyPair(
            id="key-new", public_key="pub-new", private_key="priv-new",
            created=now
        )
        mgr.add_key(old_pair)
        mgr.add_key(new_pair)

        result = mgr.get_current_key()
        self.assertEqual(result.id, "key-new")

    def test_get_current_key_excludes_expired(self):
        mgr = KeyRotationManager()
        now = int(time.time() * 1000)
        expired_pair = ManagedKeyPair(
            id="key-expired", public_key="pub-exp", private_key="priv-exp",
            created=now - 10000,
            expires_at=now - 1000,  # already expired
        )
        active_pair = ManagedKeyPair(
            id="key-active", public_key="pub-act", private_key="priv-act",
            created=now - 5000,
            expires_at=now + 3600000,
        )
        mgr.add_key(expired_pair)
        mgr.add_key(active_pair)

        result = mgr.get_current_key()
        self.assertEqual(result.id, "key-active")

    def test_get_current_key_none_when_all_expired(self):
        mgr = KeyRotationManager()
        now = int(time.time() * 1000)
        expired = ManagedKeyPair(
            id="key-exp", public_key="pub", private_key="priv",
            created=now - 10000,
            expires_at=now - 1000,
        )
        mgr.add_key(expired)
        self.assertIsNone(mgr.get_current_key())


class TestKeyRotationManagerGetWellKnownDocument(unittest.TestCase):
    """Test 7: KeyRotationManager: get_well_known_document returns correct format."""

    def test_well_known_document_empty(self):
        mgr = KeyRotationManager()
        doc = mgr.get_well_known_document()
        self.assertEqual(doc.version, "7h3/0.1")
        self.assertIsInstance(doc.updated, int)
        self.assertEqual(doc.keys, [])

    def test_well_known_document_with_keys(self):
        mgr = KeyRotationManager()
        now = int(time.time() * 1000)
        pair1 = ManagedKeyPair(
            id="key-1", public_key="pub-spki-1==", private_key="priv-pkcs8-1==",
            created=now - 1000,
        )
        pair2 = ManagedKeyPair(
            id="key-2", public_key="pub-spki-2==", private_key="priv-pkcs8-2==",
            created=now,
            expires_at=now + 3600000,
        )
        mgr.add_key(pair1)
        mgr.add_key(pair2)

        doc = mgr.get_well_known_document()
        self.assertEqual(doc.version, "7h3/0.1")
        self.assertEqual(len(doc.keys), 2)

        ids = {k.id for k in doc.keys}
        self.assertIn("key-1", ids)
        self.assertIn("key-2", ids)

        for k in doc.keys:
            self.assertEqual(k.algorithm, "Ed25519")
            self.assertIsNotNone(k.public_key)

    def test_well_known_document_is_serializable(self):
        mgr = KeyRotationManager()
        now = int(time.time() * 1000)
        mgr.add_key(ManagedKeyPair(
            id="key-serial", public_key="pub-spki==", private_key="priv==",
            created=now,
        ))

        doc = mgr.get_well_known_document()
        serialized = doc.to_json()
        parsed = json.loads(serialized)

        self.assertEqual(parsed["version"], "7h3/0.1")
        self.assertIn("updated", parsed)
        self.assertEqual(len(parsed["keys"]), 1)
        self.assertEqual(parsed["keys"][0]["id"], "key-serial")
        self.assertEqual(parsed["keys"][0]["algorithm"], "Ed25519")
        self.assertEqual(parsed["keys"][0]["publicKey"], "pub-spki==")

    def test_expired_key_marked_revoked_in_document(self):
        mgr = KeyRotationManager()
        now = int(time.time() * 1000)
        # A key that has already expired
        expired_pair = ManagedKeyPair(
            id="key-expired", public_key="pub==", private_key="priv==",
            created=now - 10000,
            expires_at=now - 1000,
        )
        mgr.add_key(expired_pair)

        doc = mgr.get_well_known_document()
        self.assertEqual(len(doc.keys), 1)
        entry = doc.keys[0]
        self.assertTrue(entry.revoked)


if __name__ == "__main__":
    unittest.main()
