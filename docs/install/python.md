# Install: Python

```bash
pip install 7h3-protocol
```

**Requires** Python 3.9+. The SDK itself has **no runtime dependencies** — it
uses only the standard library. `cryptography` is needed only for Ed25519, and
only if you use it.

```bash
pip install '7h3-protocol[crypto]'   # cryptography — needed for Ed25519
pip install '7h3-protocol[nacl]'     # PyNaCl alternative
```

## Sign and verify

Verified against this repository:

```python
import time, uuid, secrets
from protocol_7h3 import sign_envelope_hmac, verify_envelope_hmac, validate_envelope

envelope = {
    "header": {
        "version": "7h3/0.1",
        "messageId": f"msg-{uuid.uuid4()}",
        "timestampMs": int(time.time() * 1000),
        "ttlMs": 60_000,
        "sender": "agent@example.com",
        "nonce": secrets.token_hex(12),
    },
    "body": {"intent": "TASK", "content": "process order #42"},
}

secret = secrets.token_hex(32)
signed = sign_envelope_hmac(envelope, secret, "k1")

verify_envelope_hmac(signed, secret)                        # → True
validate_envelope(signed, int(time.time() * 1000))          # → []
```

> **Nonces must come from a CSPRNG.** Use `secrets`, never `random`. The nonce
> is the replay-protection primitive.

Ed25519 is the same shape via `sign_envelope_ed25519` /
`verify_envelope_ed25519`.

## Generating keys

The Python SDK **has no keygen helper** — it parses PKCS8/SPKI keys but does not
create them. Either use the CLI:

```bash
npx 7h3 keygen --output keys.json
```

or generate them with `cryptography` directly:

```python
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

b64 = lambda b: base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

priv = Ed25519PrivateKey.generate()
private_key = b64(priv.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
))
public_key = b64(priv.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
))
```

## Verify an incoming HTTP request

`verify_http_envelope` returns a **tuple** of `(ok, envelope, fail_reason)`:

```python
from protocol_7h3 import StaticKeyRegistry, verify_http_envelope

registry = StaticKeyRegistry({"peer-agent@example.com": PEER_PUBLIC_KEY})

ok, envelope, reason = verify_http_envelope(headers, registry)
if not ok:
    return 401, reason
```

## Other bindings

| Import | Provides |
|---|---|
| `protocol_7h3.http` | `verify_http_envelope`, `sign_http_request` |
| `protocol_7h3.webhook` | `sign_webhook`, `verify_webhook`, `consume_webhook` |
| `protocol_7h3.queue` | `sign_queue_message`, `verify_queue_message` |
| `protocol_7h3.encryption` | X25519 + ChaCha20-Poly1305 |
| `protocol_7h3.keys` | Key handling helpers |
| `protocol_7h3.pq` | ML-DSA post-quantum signatures |

## Validation notes

`validate_envelope(envelope, now_ms)` returns a list of diagnostics. Time-based
checks — expiry and the future-timestamp ceiling — run **only when you pass
`now_ms`**; presence and type checks always run.

Identity fields must be actual strings: `None`, `0`, `False` and objects are
rejected, matching the TypeScript and Go SDKs. Malformed numbers produce a
diagnostic rather than raising.

## Run the conformance suite

```bash
PYTHONPATH=sdk/python python3 -m unittest discover -s sdk/python/tests -v
```
