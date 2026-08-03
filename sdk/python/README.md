# 7h3 Protocol AIP Python SDK (Skeleton)

Minimal reference SDK for `7h3/0.1` parity with the TypeScript implementation.

## Included

- deterministic canonicalization
- HS256 HMAC signing and verification
- ED25519 signing and verification (requires `cryptography` package)
- compact wire encode/decode
- envelope validation helpers (version, required fields, TTL)
- conformance tests using shared vectors from `conformance/7h3_v0_1.json`

## Run conformance tests

```bash
PYTHONPATH=sdk/python python3 -m unittest discover -s sdk/python/tests -v
```
