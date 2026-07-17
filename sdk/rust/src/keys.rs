//! Key infrastructure for 7h3 Protocol — discovery, rotation, revocation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// An entry in the /.well-known/7h3-keys document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    pub algorithm: String,    // "Ed25519"
    #[serde(rename = "publicKey")]
    pub public_key: String,   // SPKI base64url
    pub created: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

/// The /.well-known/7h3-keys document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WellKnownKeysDocument {
    pub version: String,  // "7h3/0.1"
    pub updated: u64,
    pub keys: Vec<KeyEntry>,
}

impl WellKnownKeysDocument {
    pub fn new(keys: Vec<KeyEntry>) -> Self {
        Self { version: "7h3/0.1".to_string(), updated: now_ms(), keys }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Find an active (non-revoked, non-expired) public key by ID.
    pub fn get_active_key(&self, key_id: &str) -> Option<&KeyEntry> {
        let now = now_ms();
        self.keys.iter().find(|k| {
            k.id == key_id
                && !k.revoked.unwrap_or(false)
                && k.expires.map_or(true, |e| e > now)
        })
    }
}

/// Managed key pair for rotation.
///
/// The private key is wiped from memory on drop, and the `Debug` impl
/// redacts it so key material can never reach logs via `{:?}`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ManagedKeyPair {
    #[zeroize(skip)]
    pub id: String,
    #[zeroize(skip)]
    pub public_key: String,   // SPKI base64url
    pub private_key: String,  // PKCS8 base64url
    #[zeroize(skip)]
    pub created: u64,
    #[zeroize(skip)]
    pub expires_at: Option<u64>,
}

impl std::fmt::Debug for ManagedKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedKeyPair")
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .field("created", &self.created)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Manages key pairs with rotation policy.
pub struct KeyRotationManager {
    pub max_age_ms: u64,
    pub overlap_ms: u64,
    keys: Arc<Mutex<Vec<ManagedKeyPair>>>,
}

impl KeyRotationManager {
    pub fn new(max_age_ms: u64, overlap_ms: u64) -> Self {
        Self {
            max_age_ms,
            overlap_ms,
            keys: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn add_key(&self, pair: ManagedKeyPair) {
        self.keys.lock().unwrap().push(pair);
    }

    /// Returns the most recently created non-expired key.
    pub fn get_current_key(&self) -> Option<ManagedKeyPair> {
        let now = now_ms();
        let keys = self.keys.lock().unwrap();
        keys.iter()
            .filter(|k| k.expires_at.map_or(true, |e| e > now))
            .max_by_key(|k| k.created)
            .cloned()
    }

    /// Build a WellKnownKeysDocument from the managed keys.
    pub fn get_well_known_document(&self) -> WellKnownKeysDocument {
        let now = now_ms();
        let keys = self.keys.lock().unwrap();
        let entries: Vec<KeyEntry> = keys.iter().map(|k| KeyEntry {
            id: k.id.clone(),
            algorithm: "Ed25519".to_string(),
            public_key: k.public_key.clone(),
            created: k.created,
            expires: k.expires_at,
            revoked: if k.expires_at.map_or(false, |e| e < now) { Some(true) } else { None },
            revoked_at: None,
        }).collect();
        WellKnownKeysDocument::new(entries)
    }
}

/// Tracks revoked key IDs in memory.
#[derive(Default)]
pub struct RevocationRegistry {
    revoked: Arc<Mutex<HashMap<String, RevocationEntry>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    #[serde(rename = "revokedAt")]
    pub revoked_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&self, key_id: &str, reason: Option<&str>) {
        self.revoked.lock().unwrap().insert(
            key_id.to_string(),
            RevocationEntry { revoked_at: now_ms(), reason: reason.map(String::from) },
        );
    }

    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked.lock().unwrap().contains_key(key_id)
    }

    pub fn get_list(&self) -> serde_json::Value {
        let revoked = self.revoked.lock().unwrap();
        let entries: Vec<serde_json::Value> = revoked.iter().map(|(id, entry)| {
            let mut obj = serde_json::json!({ "id": id, "revokedAt": entry.revoked_at });
            if let Some(ref r) = entry.reason {
                obj["reason"] = serde_json::json!(r);
            }
            obj
        }).collect();
        serde_json::json!({ "version": "7h3/0.1", "updated": now_ms(), "revokedKeys": entries })
    }
}
