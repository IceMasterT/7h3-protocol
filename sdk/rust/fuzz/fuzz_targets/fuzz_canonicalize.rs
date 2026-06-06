#![no_main]

use libfuzzer_sys::fuzz_target;

// Invariant: canonicalize_envelope must be pure — calling it twice on the same
// input must return the same string. We construct minimal envelopes from the
// fuzz input and verify idempotence.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // Carve the fuzz bytes into two string fields to avoid heavy JSON parsing
    let mid_len = (data[0] as usize % 32) + 1;
    let content_len = (data[1] as usize % 64).min(data.len().saturating_sub(2 + mid_len));

    let mid_bytes = &data[2..2 + mid_len.min(data.len().saturating_sub(2))];
    let content_bytes = &data[2 + mid_len..2 + mid_len + content_len.min(
        data.len().saturating_sub(2 + mid_len),
    )];

    let mid = String::from_utf8_lossy(mid_bytes).to_string();
    let content = String::from_utf8_lossy(content_bytes).to_string();

    let envelope = aip7h3::ProtocolEnvelope {
        header: aip7h3::ProtocolHeader {
            version: "aip/0.1".to_string(),
            message_id: mid,
            timestamp_ms: 1_700_000_000_000,
            ttl_ms: 30_000,
            sender: "fuzzer".to_string(),
            recipient: None,
            nonce: "nonce-fuzz".to_string(),
        },
        body: aip7h3::ProtocolBody {
            intent: "PING".to_string(),
            content,
            capability: None,
            correlation_id: None,
        },
        signature: None,
    };

    let c1 = aip7h3::canonicalize_envelope(&envelope);
    let c2 = aip7h3::canonicalize_envelope(&envelope);
    assert_eq!(c1, c2, "canonicalize_envelope must be idempotent");
});
