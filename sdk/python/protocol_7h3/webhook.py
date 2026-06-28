"""Webhook binding for 7h3 Protocol — lightweight per-payload signing."""
from __future__ import annotations
import json
import time
from typing import Any, Dict, Optional, TypeVar, Union

WEBHOOK_SIG_HEADER = "x-7h3-sig"
WEBHOOK_TS_HEADER = "x-7h3-ts"
WEBHOOK_DEFAULT_TTL_MS = 300_000  # 5 minutes


def _webhook_signing_payload(timestamp_ms: int, body: str) -> str:
    return f"{timestamp_ms}.{body}"


def sign_webhook(
    payload: Union[str, bytes],
    private_key: str,
    *,
    ttl_ms: int = WEBHOOK_DEFAULT_TTL_MS,
) -> Dict[str, str]:
    """Sign a webhook payload. Returns headers dict with x-7h3-sig and x-7h3-ts."""
    from .protocol import sign_canonical_payload_ed25519

    body = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    ts = int(time.time() * 1000)
    signing_payload = _webhook_signing_payload(ts, body)
    sig = sign_canonical_payload_ed25519(signing_payload, private_key)
    return {WEBHOOK_SIG_HEADER: sig, WEBHOOK_TS_HEADER: str(ts)}


def sign_webhook_hmac(
    payload: Union[str, bytes],
    secret: str,
    *,
    ttl_ms: int = WEBHOOK_DEFAULT_TTL_MS,
) -> Dict[str, str]:
    """Sign a webhook payload with HMAC-SHA256 shared secret."""
    from .protocol import sign_canonical_payload_hmac

    body = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    ts = int(time.time() * 1000)
    signing_payload = _webhook_signing_payload(ts, body)
    sig = sign_canonical_payload_hmac(signing_payload, secret)
    return {WEBHOOK_SIG_HEADER: sig, WEBHOOK_TS_HEADER: str(ts)}


def verify_webhook(
    payload: Union[str, bytes],
    headers: Dict[str, str],
    public_key: str,
    *,
    max_age_ms: int = WEBHOOK_DEFAULT_TTL_MS,
) -> bool:
    """Verify an Ed25519 webhook signature. Returns True/False."""
    from .protocol import verify_canonical_payload_ed25519

    body = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    # normalise header keys
    normalised = {k.lower(): v for k, v in headers.items()}
    sig = normalised.get(WEBHOOK_SIG_HEADER.lower())
    ts_str = normalised.get(WEBHOOK_TS_HEADER.lower())
    if not sig or not ts_str:
        return False
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    now_ms = int(time.time() * 1000)
    if now_ms - ts > max_age_ms:
        return False
    signing_payload = _webhook_signing_payload(ts, body)
    return verify_canonical_payload_ed25519(signing_payload, sig, public_key)


def verify_webhook_hmac(
    payload: Union[str, bytes],
    headers: Dict[str, str],
    secret: str,
    *,
    max_age_ms: int = WEBHOOK_DEFAULT_TTL_MS,
) -> bool:
    """Verify an HMAC webhook signature."""
    from .protocol import verify_canonical_payload_hmac

    body = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    normalised = {k.lower(): v for k, v in headers.items()}
    sig = normalised.get(WEBHOOK_SIG_HEADER.lower())
    ts_str = normalised.get(WEBHOOK_TS_HEADER.lower())
    if not sig or not ts_str:
        return False
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    now_ms = int(time.time() * 1000)
    if now_ms - ts > max_age_ms:
        return False
    signing_payload = _webhook_signing_payload(ts, body)
    return verify_canonical_payload_hmac(signing_payload, sig, secret)


T = TypeVar("T")


def consume_webhook(
    payload: str,
    headers: Dict[str, str],
    public_key: str,
    *,
    max_age_ms: int = WEBHOOK_DEFAULT_TTL_MS,
) -> Any:
    """Parse and verify a JSON webhook payload. Raises ValueError on failure."""
    if not verify_webhook(payload, headers, public_key, max_age_ms=max_age_ms):
        raise ValueError("7h3: webhook signature verification failed")
    return json.loads(payload)
