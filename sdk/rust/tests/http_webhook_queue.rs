use protocol_7h3::{
    create_envelope,
    http::{sign_http_request, verify_http_envelope, EnvelopeInput, StaticKeyRegistry, VerifyFailReason, DEFAULT_HEADER},
    queue::{sign_queue_message, verify_queue_message},
    webhook::{sign_webhook, sign_webhook_hmac, verify_webhook, verify_webhook_hmac},
    ProtocolBody,
};
use std::collections::HashMap;

// Ed25519 test keys from the conformance vectors.
const TEST_PRIVATE_KEY: &str = "MC4CAQAwBQYDK2VwBCIEICheZbQGuDVb6hezIlcs0QnCHGxz6IhiLkC9M0qr8OOZ";
const TEST_PUBLIC_KEY: &str = "MCowBQYDK2VwAyEA-mUFiTQtcKN4nnD19V_-Wyy4q19OivnAutRUPhOcC78";
const TEST_SENDER: &str = "agent.ed";

fn make_registry() -> StaticKeyRegistry {
    let mut keys = HashMap::new();
    keys.insert(TEST_SENDER.to_string(), TEST_PUBLIC_KEY.to_string());
    StaticKeyRegistry::new(keys)
}

fn make_input() -> EnvelopeInput {
    EnvelopeInput {
        sender: TEST_SENDER.to_string(),
        recipient: Some("agent.verify".to_string()),
        ttl_ms: 60_000,
        body: ProtocolBody {
            intent: "TASK".to_string(),
            content: "hello-http".to_string(),
            capability: None,
            correlation_id: None,
        },
        key_id: "key-1".to_string(),
    }
}

// ── HTTP tests ────────────────────────────────────────────────────────────────

#[test]
fn http_sign_produces_correct_header() {
    let (name, value) = sign_http_request(&make_input(), TEST_PRIVATE_KEY, None)
        .expect("sign_http_request should succeed");
    assert_eq!(name, DEFAULT_HEADER, "header name should be x-7h3-envelope");
    // value must be valid JSON containing an ED25519 signature
    let parsed: serde_json::Value =
        serde_json::from_str(&value).expect("header value must be valid JSON");
    assert_eq!(
        parsed["signature"]["alg"].as_str().unwrap(),
        "ED25519",
        "alg must be ED25519"
    );
}

#[test]
fn http_verify_passes_on_valid_envelope() {
    let (name, value) = sign_http_request(&make_input(), TEST_PRIVATE_KEY, None)
        .expect("sign should succeed");
    let mut headers = HashMap::new();
    headers.insert(name, value);

    let registry = make_registry();
    let result = verify_http_envelope(&headers, &registry, None, false);
    assert!(result.is_ok(), "verification should pass: {:?}", result.err());
    assert_eq!(result.unwrap().header.sender, TEST_SENDER);
}

#[test]
fn http_verify_fails_on_missing_header() {
    let registry = make_registry();
    let headers = HashMap::new();
    let result = verify_http_envelope(&headers, &registry, None, false);
    assert_eq!(result.unwrap_err(), VerifyFailReason::MissingHeader);
}

#[test]
fn http_verify_fails_on_tampered_envelope() {
    let (name, value) = sign_http_request(&make_input(), TEST_PRIVATE_KEY, None)
        .expect("sign should succeed");

    // Tamper: change the sender in the JSON
    let mut parsed: serde_json::Value = serde_json::from_str(&value).unwrap();
    parsed["header"]["sender"] = serde_json::json!("attacker.agent");
    let tampered = serde_json::to_string(&parsed).unwrap();

    let mut headers = HashMap::new();
    headers.insert(name, tampered);

    // The registry won't know "attacker.agent"
    let registry = make_registry();
    let result = verify_http_envelope(&headers, &registry, None, false);
    assert!(
        matches!(
            result.unwrap_err(),
            VerifyFailReason::UnknownSender(_) | VerifyFailReason::InvalidSignature
        ),
        "expected UnknownSender or InvalidSignature"
    );
}

// ── Webhook Ed25519 tests ─────────────────────────────────────────────────────

#[test]
fn webhook_ed25519_sign_verify_roundtrip() {
    let body = r#"{"event":"order.created","id":42}"#;
    let (sig, ts) =
        sign_webhook(body, TEST_PRIVATE_KEY).expect("sign_webhook should succeed");

    let valid = verify_webhook(body, &sig, &ts, TEST_PUBLIC_KEY, None)
        .expect("verify_webhook should not error");
    assert!(valid, "webhook signature should verify");
}

#[test]
fn webhook_hmac_sign_verify_roundtrip() {
    let secret = "shared-hmac-secret-for-test";
    let body = r#"{"event":"payment.captured"}"#;

    let (sig, ts) = sign_webhook_hmac(body, secret).expect("sign_webhook_hmac should succeed");
    let valid = verify_webhook_hmac(body, &sig, &ts, secret, None)
        .expect("verify_webhook_hmac should not error");
    assert!(valid, "HMAC webhook signature should verify");
}

#[test]
fn webhook_expired_timestamp_returns_false() {
    let body = "test-payload";
    let secret = "any-secret";
    // Use a timestamp 10 minutes in the past (600_000 ms), default TTL is 300_000 ms
    let old_ts = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        now - 600_000
    };
    let payload = format!("{old_ts}.{body}");
    let sig = protocol_7h3::sign_canonical_payload_hmac(&payload, secret);

    let valid = verify_webhook_hmac(body, &sig, &old_ts.to_string(), secret, None)
        .expect("should not error");
    assert!(!valid, "expired timestamp should return false");
}

// ── Queue tests ───────────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct TestTask {
    action: String,
    priority: u32,
}

#[test]
fn queue_sign_verify_roundtrip() {
    let task = TestTask {
        action: "compute".to_string(),
        priority: 5,
    };

    let msg = sign_queue_message(
        &task,
        TEST_PRIVATE_KEY,
        "key-1",
        TEST_SENDER,
        Some("agent.worker"),
        None,
    )
    .expect("sign_queue_message should succeed");

    let (payload_val, envelope) =
        verify_queue_message(&msg, TEST_PUBLIC_KEY).expect("verify_queue_message should succeed");

    assert_eq!(envelope.header.sender, TEST_SENDER);

    let recovered: TestTask =
        serde_json::from_value(payload_val).expect("payload should deserialize");
    assert_eq!(recovered, task);
}

#[test]
fn queue_fails_on_tampered_message() {
    let task = TestTask {
        action: "delete-all".to_string(),
        priority: 99,
    };
    let msg = sign_queue_message(
        &task,
        TEST_PRIVATE_KEY,
        "key-1",
        TEST_SENDER,
        None,
        None,
    )
    .expect("sign should succeed");

    // Tamper with the payload section
    let mut parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
    parsed["envelope"]["header"]["sender"] = serde_json::json!("evil-agent");
    let tampered = serde_json::to_string(&parsed).unwrap();

    let result = verify_queue_message(&tampered, TEST_PUBLIC_KEY);
    assert!(result.is_err(), "tampered message should fail verification");
}

/// The signature covers `envelope.body.content`, not the sibling `payload`
/// field. Returning that field unchecked let an attacker take any validly
/// signed message, swap the payload, and have it accepted — a complete
/// integrity bypass. Parity with the TypeScript and Python SDKs.
#[test]
fn queue_rejects_payload_swapped_under_a_valid_signature() {
    let message = protocol_7h3::queue::sign_queue_message(
        &serde_json::json!({ "job": "reindex", "amount": 10 }),
        TEST_PRIVATE_KEY,
        "key-1",
        TEST_SENDER,
        None,
        Some(60_000),
    )
    .expect("sign");

    let parsed: serde_json::Value = serde_json::from_str(&message).expect("parse");

    // Envelope untouched, so the signature still verifies.
    let forged = serde_json::json!({
        "envelope": parsed["envelope"],
        "payload": { "job": "DROP TABLE users", "amount": 1_000_000_000i64 }
    })
    .to_string();

    let result = protocol_7h3::queue::verify_queue_message(&forged, TEST_PUBLIC_KEY);
    assert!(result.is_err(), "a swapped payload must be rejected");
    assert!(
        result.unwrap_err().to_string().contains("does not match the signed content"),
        "rejection should name the cause"
    );

    // An untouched message still round-trips.
    let (payload, _) = protocol_7h3::queue::verify_queue_message(&message, TEST_PUBLIC_KEY).expect("honest message");
    assert_eq!(payload["job"], "reindex");
}
