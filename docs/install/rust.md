# Install: Rust

```bash
cargo add protocol-7h3
```

or in `Cargo.toml`:

```toml
[dependencies]
protocol-7h3 = "0.5"
```

## Sign and verify

Verified against this repository:

```rust
use protocol_7h3::{
    random_nonce, sign_envelope_hmac, validate_envelope, verify_envelope_hmac,
    ProtocolBody, ProtocolEnvelope, ProtocolHeader,
};

fn main() {
    let now = 1_700_000_000_000i64;

    let envelope = ProtocolEnvelope {
        header: ProtocolHeader {
            version: "7h3/0.1".to_string(),
            message_id: "msg-1".to_string(),
            timestamp_ms: now,
            ttl_ms: 60_000,
            sender: "agent@example.com".to_string(),
            recipient: Some("peer@example.com".to_string()),
            nonce: random_nonce(),          // CSPRNG — never a timestamp
        },
        body: ProtocolBody {
            intent: "TASK".to_string(),
            content: "process order #42".to_string(),
            capability: None,
            correlation_id: None,
        },
        signature: None,
    };

    let secret = "shared-secret-at-least-32-bytes-long";
    let signed = sign_envelope_hmac(&envelope, secret, "k1");   // returns the envelope

    assert!(verify_envelope_hmac(&signed, secret));             // returns bool
    assert!(validate_envelope(&signed, Some(now)).is_empty());
}
```

Note the return types: `sign_envelope_hmac` returns a `ProtocolEnvelope`
directly and `verify_envelope_hmac` returns a `bool` — neither is a `Result`.

Ed25519 is the same shape via `sign_envelope_ed25519` /
`verify_envelope_ed25519`.

## Generating keys

The Rust SDK **parses** PKCS8/SPKI keys but has no keygen helper. Generate a
keypair with the CLI and pass the base64url strings in:

```bash
npx 7h3 keygen --output keys.json
```

## Security properties

- HMAC verification is **constant-time** (`hmac::Mac::verify_slice`), not a
  string comparison.
- Private keys are **zeroized on drop** and redacted from `Debug` output.
- `random_nonce()` uses `getrandom`. Never build a nonce from a timestamp — two
  messages in the same millisecond would collide and defeat replay protection.

## Validation

`validate_envelope(&envelope, Some(now_ms))` returns a `Vec<ProtocolDiagnostic>`.
Time-based checks run only when you pass `Some(now)`. It enforces the wire
version, presence of messageId / sender / nonce, the 24h `MAX_TTL_MS` ceiling,
the 30s `MAX_CLOCK_SKEW_MS` future-timestamp ceiling, and expiry.

## Run the conformance suite

```bash
cargo test --manifest-path sdk/rust/Cargo.toml
```
