"""HTTP binding for 7h3 Protocol — signs/verifies per-request envelopes."""
from __future__ import annotations

import json
import time
import uuid
import os
from typing import Any, Callable, Dict, Optional, Tuple

from .protocol import (
    verify_envelope_ed25519,
    verify_envelope_hmac,
    sign_envelope_ed25519,
    validate_envelope,
    ProtocolDiagnostic,
)

DEFAULT_HEADER = "x-7h3-envelope"

VerifyFailReason = str  # 'missing-header' | 'malformed-envelope' | 'unknown-sender' | 'invalid-signature' | 'ttl-expired'


class KeyRegistry:
    """Abstract key registry — subclass to implement custom lookup."""

    def get_public_key(self, sender_id: str) -> Optional[str]:
        raise NotImplementedError

    def get_shared_secret(self, key_id: str) -> Optional[str]:
        return None


class StaticKeyRegistry(KeyRegistry):
    """In-memory registry backed by a dict {sender_id: public_key_b64url}."""

    def __init__(self, keys: Dict[str, str]):
        self._keys = keys

    def get_public_key(self, sender_id: str) -> Optional[str]:
        return self._keys.get(sender_id)


def _make_envelope(
    sender: str,
    ttl_ms: int,
    body: Dict[str, Any],
    recipient: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an unsigned envelope dict."""
    header: Dict[str, Any] = {
        "version": "7h3/0.1",
        "messageId": str(uuid.uuid4()),
        "timestampMs": int(time.time() * 1000),
        "ttlMs": ttl_ms,
        "sender": sender,
        "nonce": os.urandom(8).hex(),
    }
    if recipient is not None:
        header["recipient"] = recipient
    return {"header": header, "body": body}


def verify_http_envelope(
    headers: Dict[str, str],
    registry: KeyRegistry,
    *,
    header_name: str = DEFAULT_HEADER,
    strict_ttl: bool = True,
) -> Tuple[bool, Optional[dict], Optional[VerifyFailReason]]:
    """
    Verify a 7h3 envelope from HTTP headers.
    Returns (ok, envelope_dict, reason).
    reason is None on success, a VerifyFailReason string on failure.
    """
    # Headers may arrive with mixed case — normalise
    normalised = {k.lower(): v for k, v in headers.items()}
    raw = normalised.get(header_name.lower())
    if not raw:
        return False, None, "missing-header"

    try:
        envelope = json.loads(raw)
    except Exception:
        return False, None, "malformed-envelope"

    if not isinstance(envelope, dict) or "header" not in envelope or "signature" not in envelope:
        return False, None, "malformed-envelope"

    if strict_ttl:
        now_ms = int(time.time() * 1000)
        diags: list[ProtocolDiagnostic] = validate_envelope(envelope, now_ms=now_ms)
        errors = [d for d in diags if d.level == "error"]
        if errors:
            return False, None, "ttl-expired"

    sender = envelope.get("header", {}).get("sender", "")
    alg = envelope.get("signature", {}).get("alg", "")

    if alg == "ED25519":
        pub_key = registry.get_public_key(sender)
        if not pub_key:
            return False, None, "unknown-sender"
        valid = verify_envelope_ed25519(envelope, pub_key)
        if not valid:
            return False, None, "invalid-signature"
    elif alg == "HS256":
        key_id = envelope.get("signature", {}).get("keyId", "")
        secret = registry.get_shared_secret(key_id)
        if not secret:
            return False, None, "unknown-sender"
        valid = verify_envelope_hmac(envelope, secret)
        if not valid:
            return False, None, "invalid-signature"
    else:
        return False, None, "malformed-envelope"

    return True, envelope, None


def sign_http_request(
    envelope_without_sig: dict,
    private_key: str,
    *,
    header_name: str = DEFAULT_HEADER,
) -> Dict[str, str]:
    """Sign an envelope and return HTTP headers dict to add to your request."""
    signed = sign_envelope_ed25519(envelope_without_sig, private_key)
    return {header_name: json.dumps(signed, separators=(",", ":"))}


def build_signed_request_headers(
    sender: str,
    private_key: str,
    *,
    recipient: Optional[str] = None,
    ttl_ms: int = 60_000,
    content: str = "",
    header_name: str = DEFAULT_HEADER,
) -> Dict[str, str]:
    """Convenience: build envelope + sign in one call. Returns headers dict."""
    envelope = _make_envelope(
        sender=sender,
        ttl_ms=ttl_ms,
        body={"intent": "TASK", "content": content},
        recipient=recipient,
    )
    return sign_http_request(envelope, private_key, header_name=header_name)


# --- Framework integrations ---


def starlette_middleware_factory(registry: KeyRegistry, *, header_name: str = DEFAULT_HEADER):
    """
    Returns an ASGI middleware class for Starlette/FastAPI.

    Usage:
        app.add_middleware(starlette_middleware_factory(registry))
    """
    try:
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request
        from starlette.responses import JSONResponse
    except ImportError as e:
        raise ImportError("starlette is required: pip install starlette") from e

    class Protocol7h3Middleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Callable) -> Any:
            headers = dict(request.headers)
            ok, envelope, reason = verify_http_envelope(
                headers, registry, header_name=header_name
            )
            if not ok:
                return JSONResponse(
                    {"error": "7h3: request verification failed", "reason": reason},
                    status_code=401,
                )
            request.state.envelope_7h3 = envelope
            return await call_next(request)

    return Protocol7h3Middleware


def flask_before_request_factory(registry: KeyRegistry, *, header_name: str = DEFAULT_HEADER):
    """
    Returns a Flask before_request handler.

    Usage:
        app.before_request(flask_before_request_factory(registry))
    """

    def before_request():
        try:
            from flask import request as flask_req, g
        except ImportError as e:
            raise ImportError("flask is required: pip install flask") from e

        headers = dict(flask_req.headers)
        ok, envelope, reason = verify_http_envelope(headers, registry, header_name=header_name)
        if not ok:
            from flask import make_response

            resp = make_response(
                json.dumps({"error": "7h3: request verification failed", "reason": reason}),
                401,
            )
            resp.headers["Content-Type"] = "application/json"
            return resp
        g.envelope_7h3 = envelope
        return None  # continue

    return before_request
