use protocol_7h3::{
    canonicalize_envelope, decode_envelope, encode_envelope_compact, sign_canonical_payload_hmac,
    sign_envelope_ed25519, sign_envelope_hmac, validate_envelope, verify_canonical_payload_ed25519,
    verify_canonical_payload_hmac, verify_envelope_ed25519, verify_envelope_hmac, ProtocolEnvelope,
};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct VectorFixture {
    id: String,
    secret: String,
    #[serde(rename = "keyId")]
    key_id: String,
    envelope: ProtocolEnvelope,
    canonical: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct Fixtures {
    vectors: Vec<VectorFixture>,
    #[serde(rename = "ed25519Vectors", default)]
    ed25519_vectors: Vec<Ed25519VectorFixture>,
}

#[derive(Debug, Deserialize)]
struct Ed25519VectorFixture {
    id: String,
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "privateKey")]
    private_key: String,
    envelope: ProtocolEnvelope,
    canonical: String,
    signature: String,
}

fn load_fixtures() -> Fixtures {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../conformance/7h3_v0_1.json");
    let raw = fs::read_to_string(path).expect("conformance fixture should exist");
    serde_json::from_str(&raw).expect("conformance fixture should be valid JSON")
}

#[test]
fn conformance_vectors_match_canonical_and_signatures() {
    let fixtures = load_fixtures();
    for vector in fixtures.vectors {
        let canonical = canonicalize_envelope(&vector.envelope);
        assert_eq!(
            canonical, vector.canonical,
            "canonical mismatch for {}",
            vector.id
        );

        let signature = sign_canonical_payload_hmac(&canonical, &vector.secret);
        assert_eq!(
            signature, vector.signature,
            "signature mismatch for {}",
            vector.id
        );

        let signed = sign_envelope_hmac(&vector.envelope, &vector.secret, &vector.key_id);
        assert!(verify_canonical_payload_hmac(
            &canonical,
            &vector.signature,
            &vector.secret
        ));
        assert!(verify_envelope_hmac(&signed, &vector.secret));
        assert!(!verify_envelope_hmac(
            &signed,
            &format!("{}-bad", vector.secret)
        ));
    }
}

#[test]
fn compact_roundtrip_and_ttl_validation() {
    let fixtures = load_fixtures();
    for vector in fixtures.vectors {
        let signed = sign_envelope_hmac(&vector.envelope, &vector.secret, &vector.key_id);
        let encoded = encode_envelope_compact(&signed);
        let decoded = decode_envelope(&encoded).expect("compact decode should succeed");
        assert_eq!(
            canonicalize_envelope(&decoded),
            canonicalize_envelope(&signed)
        );
        assert_eq!(decoded.signature, signed.signature);

        let valid = validate_envelope(&decoded, Some(decoded.header.timestamp_ms + 1));
        assert!(
            valid.iter().all(|d| d.message != "Message TTL expired"),
            "valid envelope unexpectedly expired for {}",
            vector.id
        );

        let expired = validate_envelope(
            &decoded,
            Some(decoded.header.timestamp_ms + decoded.header.ttl_ms + 1),
        );
        assert!(
            expired.iter().any(|d| d.message == "Message TTL expired"),
            "expired envelope missing TTL diagnostic for {}",
            vector.id
        );
    }
}

#[test]
fn ed25519_vectors_match_canonical_and_signatures() {
    let fixtures = load_fixtures();
    for vector in fixtures.ed25519_vectors {
        let canonical = canonicalize_envelope(&vector.envelope);
        assert_eq!(
            canonical, vector.canonical,
            "canonical mismatch for {}",
            vector.id
        );

        let signature = protocol_7h3::sign_canonical_payload_ed25519(&canonical, &vector.private_key)
            .expect("ed25519 sign should succeed");
        assert_eq!(
            signature, vector.signature,
            "ed25519 signature mismatch for {}",
            vector.id
        );

        assert!(
            verify_canonical_payload_ed25519(&canonical, &vector.signature, &vector.public_key)
                .expect("ed25519 verify should succeed"),
            "ed25519 verify failed for {}",
            vector.id
        );

        let signed = sign_envelope_ed25519(&vector.envelope, &vector.private_key, &vector.key_id)
            .expect("sign envelope ed25519 should succeed");
        assert!(
            verify_envelope_ed25519(&signed, &vector.public_key)
                .expect("verify envelope ed25519 should succeed"),
            "ed25519 envelope verify failed for {}",
            vector.id
        );
    }
}

#[test]
fn validate_envelope_rejects_ttl_above_ceiling() {
    use protocol_7h3::{ProtocolBody, ProtocolHeader, MAX_TTL_MS};

    let mut envelope = ProtocolEnvelope {
        header: ProtocolHeader {
            version: "7h3/0.1".to_string(),
            message_id: "msg-huge-ttl".to_string(),
            timestamp_ms: 1_000,
            ttl_ms: MAX_TTL_MS + 1,
            sender: "agent.a".to_string(),
            recipient: None,
            nonce: "nonce-huge-ttl".to_string(),
        },
        body: ProtocolBody {
            intent: "PING".to_string(),
            content: "long-lived".to_string(),
            capability: None,
            correlation_id: None,
        },
        signature: None,
    };

    let diags = validate_envelope(&envelope, None);
    assert!(
        diags.iter().any(|d| d.message.contains("exceeds maximum")),
        "expected ttlMs ceiling diagnostic, got: {diags:?}"
    );

    // Exactly at the ceiling stays valid
    envelope.header.ttl_ms = MAX_TTL_MS;
    let diags = validate_envelope(&envelope, None);
    assert!(
        diags.iter().all(|d| d.level != "error"),
        "ttlMs == MAX_TTL_MS should not error, got: {diags:?}"
    );
}
