use protocol_7h3::keys::{
    KeyEntry, KeyRotationManager, ManagedKeyPair, RevocationRegistry, WellKnownKeysDocument,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_key_entry(id: &str, revoked: Option<bool>, expires: Option<u64>) -> KeyEntry {
    KeyEntry {
        id: id.to_string(),
        algorithm: "Ed25519".to_string(),
        public_key: "dGVzdC1wdWJsaWMta2V5".to_string(),
        created: now_ms() - 1000,
        expires,
        revoked,
        revoked_at: None,
    }
}

// 1. WellKnownKeysDocument round-trip JSON serialization
#[test]
fn test_well_known_document_json_round_trip() {
    let entry = make_key_entry("key-1", None, None);
    let doc = WellKnownKeysDocument::new(vec![entry]);

    let json = doc.to_json().expect("serialization should succeed");
    let restored = WellKnownKeysDocument::from_json(&json).expect("deserialization should succeed");

    assert_eq!(restored.version, "7h3/0.1");
    assert_eq!(restored.keys.len(), 1);
    assert_eq!(restored.keys[0].id, "key-1");
    assert_eq!(restored.keys[0].algorithm, "Ed25519");
}

// 2. get_active_key finds non-revoked keys
#[test]
fn test_get_active_key_finds_active() {
    let entry = make_key_entry("key-active", None, None);
    let doc = WellKnownKeysDocument::new(vec![entry]);

    let found = doc.get_active_key("key-active");
    assert!(found.is_some(), "should find an active key");
    assert_eq!(found.unwrap().id, "key-active");
}

// 3. get_active_key ignores revoked keys
#[test]
fn test_get_active_key_ignores_revoked() {
    let revoked = make_key_entry("key-revoked", Some(true), None);
    let doc = WellKnownKeysDocument::new(vec![revoked]);

    let found = doc.get_active_key("key-revoked");
    assert!(found.is_none(), "should NOT find a revoked key");
}

// 3b. get_active_key ignores expired keys
#[test]
fn test_get_active_key_ignores_expired() {
    // expires 10 seconds in the past
    let expired = make_key_entry("key-expired", None, Some(now_ms() - 10_000));
    let doc = WellKnownKeysDocument::new(vec![expired]);

    let found = doc.get_active_key("key-expired");
    assert!(found.is_none(), "should NOT find an expired key");
}

// 4. KeyRotationManager: add_key + get_current_key
#[test]
fn test_rotation_manager_add_and_get_current() {
    let mgr = KeyRotationManager::new(86_400_000, 3_600_000);

    let pair = ManagedKeyPair {
        id: "rot-key-1".to_string(),
        public_key: "pub1".to_string(),
        private_key: "priv1".to_string(),
        created: now_ms(),
        expires_at: None,
    };
    mgr.add_key(pair);

    let current = mgr.get_current_key();
    assert!(current.is_some(), "should return current key");
    assert_eq!(current.unwrap().id, "rot-key-1");
}

// 4b. get_current_key returns the most recent non-expired key
#[test]
fn test_rotation_manager_returns_most_recent() {
    let mgr = KeyRotationManager::new(86_400_000, 3_600_000);
    let base = now_ms();

    mgr.add_key(ManagedKeyPair {
        id: "older".to_string(),
        public_key: "pub-older".to_string(),
        private_key: "priv-older".to_string(),
        created: base - 5000,
        expires_at: None,
    });
    mgr.add_key(ManagedKeyPair {
        id: "newer".to_string(),
        public_key: "pub-newer".to_string(),
        private_key: "priv-newer".to_string(),
        created: base,
        expires_at: None,
    });

    let current = mgr.get_current_key().expect("should have a current key");
    assert_eq!(current.id, "newer");
}

// 4c. get_current_key excludes expired keys
#[test]
fn test_rotation_manager_excludes_expired() {
    let mgr = KeyRotationManager::new(86_400_000, 3_600_000);

    mgr.add_key(ManagedKeyPair {
        id: "exp-key".to_string(),
        public_key: "pub-exp".to_string(),
        private_key: "priv-exp".to_string(),
        created: now_ms() - 2000,
        expires_at: Some(now_ms() - 1000), // already expired
    });

    let current = mgr.get_current_key();
    assert!(current.is_none(), "expired key should not be returned as current");
}

// 5. KeyRotationManager: get_well_known_document structure
#[test]
fn test_rotation_manager_well_known_document() {
    let mgr = KeyRotationManager::new(86_400_000, 3_600_000);

    mgr.add_key(ManagedKeyPair {
        id: "doc-key-1".to_string(),
        public_key: "pub-doc".to_string(),
        private_key: "priv-doc".to_string(),
        created: now_ms(),
        expires_at: None,
    });

    let doc = mgr.get_well_known_document();
    assert_eq!(doc.version, "7h3/0.1");
    assert_eq!(doc.keys.len(), 1);
    assert_eq!(doc.keys[0].id, "doc-key-1");
    assert_eq!(doc.keys[0].algorithm, "Ed25519");
    assert_eq!(doc.keys[0].public_key, "pub-doc");
    // non-expired key should not be marked revoked
    assert!(doc.keys[0].revoked.is_none() || !doc.keys[0].revoked.unwrap());
}

// 6. RevocationRegistry: revoke + is_revoked
#[test]
fn test_revocation_registry_revoke_and_check() {
    let registry = RevocationRegistry::new();

    assert!(!registry.is_revoked("key-x"), "should not be revoked initially");
    registry.revoke("key-x", Some("compromised"));
    assert!(registry.is_revoked("key-x"), "should be revoked after revoke()");
    assert!(!registry.is_revoked("key-y"), "unrelated key should not be revoked");
}

// 7. RevocationRegistry: get_list contains correct fields
#[test]
fn test_revocation_registry_get_list() {
    let registry = RevocationRegistry::new();
    registry.revoke("key-a", Some("expired"));
    registry.revoke("key-b", None);

    let list = registry.get_list();

    assert_eq!(list["version"], "7h3/0.1");
    let revoked_keys = list["revokedKeys"].as_array().expect("revokedKeys should be array");
    assert_eq!(revoked_keys.len(), 2);

    // Find key-a in the list
    let key_a = revoked_keys.iter().find(|e| e["id"] == "key-a").expect("key-a should be in list");
    assert!(key_a["revokedAt"].as_u64().unwrap() > 0, "revokedAt should be a positive timestamp");
    assert_eq!(key_a["reason"], "expired");

    // Find key-b in the list — no reason
    let key_b = revoked_keys.iter().find(|e| e["id"] == "key-b").expect("key-b should be in list");
    assert!(key_b["revokedAt"].as_u64().unwrap() > 0);
    assert!(key_b.get("reason").is_none() || key_b["reason"].is_null());
}

// 8. ManagedKeyPair: Debug output must never contain private key material
#[test]
fn test_managed_keypair_debug_redacts_private_key() {
    let pair = ManagedKeyPair {
        id: "debug-key".to_string(),
        public_key: "public-material".to_string(),
        private_key: "SUPER-SECRET-PKCS8-MATERIAL".to_string(),
        created: now_ms(),
        expires_at: None,
    };

    let printed = format!("{:?}", pair);
    assert!(!printed.contains("SUPER-SECRET-PKCS8-MATERIAL"), "Debug must not leak private key");
    assert!(printed.contains("<redacted>"), "Debug should mark the private key as redacted");
    assert!(printed.contains("public-material"), "public fields should still be printed");
}
