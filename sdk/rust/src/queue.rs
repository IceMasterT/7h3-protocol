//! Queue binding — signed message envelope for Kafka/SQS/Pub-Sub transit.

use crate::{
    create_envelope, sign_envelope_ed25519, validate_envelope, verify_envelope_ed25519,
    ProtocolBody, ProtocolEnvelope,
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_TTL_MS: i64 = 3_600_000;

#[derive(Serialize, Deserialize)]
pub struct QueueMessage<T: Serialize> {
    pub envelope: ProtocolEnvelope,
    pub payload: T,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Sign a payload for queue transit. Returns a JSON string.
pub fn sign_queue_message<T: Serialize>(
    payload: &T,
    private_key: &str,
    key_id: &str,
    sender: &str,
    recipient: Option<&str>,
    ttl_ms: Option<i64>,
) -> Result<String, Box<dyn std::error::Error>> {
    let content = serde_json::to_string(payload)?;
    let now = now_ms();
    let envelope = create_envelope(
        sender,
        recipient,
        "TASK",
        &content,
        None,
        None,
        now,
        ttl_ms.unwrap_or(DEFAULT_TTL_MS),
    );
    let signed = sign_envelope_ed25519(&envelope, private_key, key_id)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    // Re-serialize payload as Value so the QueueMessage wrapper holds both fields
    let payload_value = serde_json::to_value(payload)?;
    let msg = serde_json::json!({
        "envelope": signed,
        "payload": payload_value,
    });
    Ok(serde_json::to_string(&msg)?)
}

/// Verify and unwrap a queue message. Returns (payload_json_value, envelope).
pub fn verify_queue_message(
    message: &str,
    public_key: &str,
) -> Result<(serde_json::Value, ProtocolEnvelope), Box<dyn std::error::Error>> {
    let wrapper: serde_json::Value = serde_json::from_str(message)?;

    let envelope: ProtocolEnvelope = serde_json::from_value(wrapper["envelope"].clone())
        .map_err(|e| -> Box<dyn std::error::Error> { format!("malformed envelope: {e}").into() })?;

    let now = now_ms();
    let diags = validate_envelope(&envelope, Some(now));
    if diags.iter().any(|d| d.level == "error") {
        return Err("envelope expired or invalid".into());
    }

    let valid = verify_envelope_ed25519(&envelope, public_key)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    if !valid {
        return Err("invalid signature".into());
    }

    // The signature covers envelope.body.content, NOT the sibling "payload"
    // field. Returning it unchecked meant an attacker could take any validly
    // signed message, swap the payload for anything, and the signature would
    // still verify while the consumer acted on attacker-controlled data — a
    // complete integrity bypass on a transport whose whole purpose is integrity.
    // Serialized exactly as sign_queue_message does, so honest messages match.
    let payload = wrapper["payload"].clone();
    let presented = serde_json::to_string(&payload)
        .map_err(|e| -> Box<dyn std::error::Error> { format!("malformed payload: {e}").into() })?;
    if presented != envelope.body.content {
        return Err(
            "queue message payload does not match the signed content — the payload field was modified in transit"
                .into(),
        );
    }

    Ok((payload, envelope))
}
