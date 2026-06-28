//! HTTP binding for 7h3 Protocol — signs and verifies per-request envelopes.
//!
//! The signed envelope rides in the `x-7h3-envelope` request header.

use crate::{
    create_envelope, sign_envelope_ed25519, validate_envelope, verify_envelope_ed25519,
    ProtocolBody, ProtocolEnvelope,
};
use std::collections::HashMap;

pub const DEFAULT_HEADER: &str = "x-7h3-envelope";

/// Reason an HTTP envelope verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyFailReason {
    MissingHeader,
    MalformedEnvelope(String),
    UnknownSender(String),
    InvalidSignature,
    TtlExpired,
}

impl std::fmt::Display for VerifyFailReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader => write!(f, "missing-header"),
            Self::MalformedEnvelope(d) => write!(f, "malformed-envelope: {d}"),
            Self::UnknownSender(s) => write!(f, "unknown-sender: {s}"),
            Self::InvalidSignature => write!(f, "invalid-signature"),
            Self::TtlExpired => write!(f, "ttl-expired"),
        }
    }
}

/// Simple in-memory key registry mapping sender_id → base64url-encoded SPKI public key.
pub struct StaticKeyRegistry {
    keys: HashMap<String, String>,
}

impl StaticKeyRegistry {
    pub fn new(keys: HashMap<String, String>) -> Self {
        Self { keys }
    }

    pub fn get_public_key(&self, sender_id: &str) -> Option<&str> {
        self.keys.get(sender_id).map(|s| s.as_str())
    }
}

/// Input for signing an outbound HTTP request.
pub struct EnvelopeInput {
    pub sender: String,
    pub recipient: Option<String>,
    pub ttl_ms: i64,
    pub body: ProtocolBody,
    pub key_id: String,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Verify a 7h3 envelope from HTTP headers (generic over header map type).
/// `headers` is a flat map of lowercase header names → values.
pub fn verify_http_envelope(
    headers: &HashMap<String, String>,
    registry: &StaticKeyRegistry,
    header_name: Option<&str>,
    strict_ttl: bool,
) -> Result<ProtocolEnvelope, VerifyFailReason> {
    let hname = header_name.unwrap_or(DEFAULT_HEADER);
    let raw = headers
        .get(hname)
        .or_else(|| headers.get(&hname.to_lowercase()))
        .ok_or(VerifyFailReason::MissingHeader)?;

    let envelope: ProtocolEnvelope = serde_json::from_str(raw)
        .map_err(|e| VerifyFailReason::MalformedEnvelope(e.to_string()))?;

    let sig = envelope
        .signature
        .as_ref()
        .ok_or_else(|| VerifyFailReason::MalformedEnvelope("missing signature".into()))?;

    if strict_ttl {
        let now = now_ms();
        let diags = validate_envelope(&envelope, Some(now));
        if diags.iter().any(|d| d.level == "error") {
            return Err(VerifyFailReason::TtlExpired);
        }
    }

    let sender = &envelope.header.sender;
    match sig.alg.as_str() {
        "ED25519" => {
            let pub_key = registry
                .get_public_key(sender)
                .ok_or_else(|| VerifyFailReason::UnknownSender(sender.clone()))?;
            let valid = verify_envelope_ed25519(&envelope, pub_key)
                .map_err(|e| VerifyFailReason::MalformedEnvelope(e))?;
            if !valid {
                return Err(VerifyFailReason::InvalidSignature);
            }
        }
        "HS256" => {
            let key_id = &sig.key_id;
            return Err(VerifyFailReason::UnknownSender(format!(
                "HMAC key {key_id}: use StaticHmacRegistry"
            )));
        }
        alg => {
            return Err(VerifyFailReason::MalformedEnvelope(format!(
                "unsupported alg: {alg}"
            )));
        }
    }

    Ok(envelope)
}

/// Sign an outbound HTTP request — returns the header name and JSON-serialized envelope value.
pub fn sign_http_request(
    input: &EnvelopeInput,
    private_key: &str,
    header_name: Option<&str>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let now = now_ms();
    let envelope = create_envelope(
        &input.sender,
        input.recipient.as_deref(),
        &input.body.intent,
        &input.body.content,
        input.body.capability.as_deref(),
        input.body.correlation_id.as_deref(),
        now,
        input.ttl_ms,
    );
    let signed = sign_envelope_ed25519(&envelope, private_key, &input.key_id)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let value = serde_json::to_string(&signed)?;
    Ok((header_name.unwrap_or(DEFAULT_HEADER).to_string(), value))
}
