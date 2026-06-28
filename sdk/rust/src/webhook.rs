//! Webhook binding — lightweight per-payload Ed25519/HMAC signing.
//! Signs "${timestamp_ms}.${body}" to bind time and content together.

use crate::{
    sign_canonical_payload_ed25519, sign_canonical_payload_hmac, verify_canonical_payload_ed25519,
    verify_canonical_payload_hmac,
};

pub const SIG_HEADER: &str = "x-7h3-sig";
pub const TS_HEADER: &str = "x-7h3-ts";
pub const DEFAULT_TTL_MS: u64 = 300_000;

fn signing_payload(timestamp_ms: u64, body: &str) -> String {
    format!("{timestamp_ms}.{body}")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Sign a webhook payload with Ed25519. Returns (sig_header_value, ts_header_value).
pub fn sign_webhook(
    body: &str,
    private_key: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let ts = now_ms();
    let payload = signing_payload(ts, body);
    let sig = sign_canonical_payload_ed25519(&payload, private_key)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    Ok((sig, ts.to_string()))
}

/// Verify a webhook Ed25519 signature. Returns true if valid and not expired.
pub fn verify_webhook(
    body: &str,
    sig: &str,
    ts_str: &str,
    public_key: &str,
    max_age_ms: Option<u64>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let ts: u64 = ts_str
        .parse()
        .map_err(|_| -> Box<dyn std::error::Error> { "invalid timestamp".into() })?;
    let max_age = max_age_ms.unwrap_or(DEFAULT_TTL_MS);
    let now = now_ms();
    if now.saturating_sub(ts) > max_age {
        return Ok(false);
    }
    let payload = signing_payload(ts, body);
    verify_canonical_payload_ed25519(&payload, sig, public_key)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
}

/// Sign a webhook payload with HMAC-SHA256 shared secret.
/// Returns (sig_header_value, ts_header_value).
pub fn sign_webhook_hmac(
    body: &str,
    secret: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let ts = now_ms();
    let payload = signing_payload(ts, body);
    let sig = sign_canonical_payload_hmac(&payload, secret);
    Ok((sig, ts.to_string()))
}

/// Verify an HMAC webhook signature.
pub fn verify_webhook_hmac(
    body: &str,
    sig: &str,
    ts_str: &str,
    secret: &str,
    max_age_ms: Option<u64>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let ts: u64 = ts_str
        .parse()
        .map_err(|_| -> Box<dyn std::error::Error> { "invalid timestamp".into() })?;
    let max_age = max_age_ms.unwrap_or(DEFAULT_TTL_MS);
    if now_ms().saturating_sub(ts) > max_age {
        return Ok(false);
    }
    let payload = signing_payload(ts, body);
    Ok(verify_canonical_payload_hmac(&payload, sig, secret))
}
