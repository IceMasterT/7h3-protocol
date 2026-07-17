"""Queue message binding for 7h3 Protocol — Kafka/SQS/Pub-Sub/RabbitMQ."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any, Dict, List, Optional

QUEUE_DEFAULT_TTL_MS = 3_600_000  # 1 hour


def _create_envelope(
    sender: str,
    content: str,
    ttl_ms: int,
    *,
    recipient: Optional[str] = None,
    intent: str = "TASK",
) -> Dict[str, Any]:
    """Build a bare (unsigned) protocol envelope dict."""
    now_ms = int(time.time() * 1000)
    message_id = secrets.token_hex(16)
    nonce = secrets.token_hex(8)
    header: Dict[str, Any] = {
        "version": "7h3/0.1",
        "messageId": message_id,
        "timestampMs": now_ms,
        "ttlMs": ttl_ms,
        "sender": sender,
        "nonce": nonce,
    }
    if recipient is not None:
        header["recipient"] = recipient

    body: Dict[str, Any] = {
        "intent": intent,
        "content": content,
    }
    return {"header": header, "body": body}


def sign_queue_message(
    payload: Any,
    private_key: str,
    sender: str,
    *,
    recipient: Optional[str] = None,
    ttl_ms: int = QUEUE_DEFAULT_TTL_MS,
) -> str:
    """
    Sign a payload for queue transit.
    Returns a JSON string: {"envelope": {...}, "payload": payload}
    """
    from .protocol import sign_envelope_ed25519

    content = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
    envelope = _create_envelope(
        sender=sender,
        content=content,
        ttl_ms=ttl_ms,
        recipient=recipient,
    )
    signed = sign_envelope_ed25519(envelope, private_key)
    return json.dumps({"envelope": signed, "payload": payload}, separators=(",", ":"))


def verify_queue_message(
    message: str,
    public_key: str,
    *,
    replay_store: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Verify and unwrap a queue message.
    Returns {"payload": Any, "envelope": dict}.
    Raises ValueError on failure.

    replay_store: optional object exposing check(key: str, ttl_ms: int) -> bool
        (e.g. InMemoryReplayStore or RedisReplayStore from .replay). Construct
        ONE instance per consumer process and pass the same instance to every
        call — a fresh instance per call provides no protection at all, since
        a replayed nonce would never be recognized as already-seen.
    """
    from .protocol import verify_envelope_ed25519, validate_envelope

    try:
        wrapper = json.loads(message)
    except Exception as e:
        raise ValueError(f"7h3: malformed queue message: {e}") from e

    envelope = wrapper.get("envelope")
    payload = wrapper.get("payload")
    if not envelope or not isinstance(envelope, dict):
        raise ValueError("7h3: missing envelope in queue message")

    # validate_envelope returns list[ProtocolDiagnostic] (dataclass objects).
    # now_ms must be passed explicitly — validate_envelope silently skips its
    # TTL-expiry check when now_ms is None.
    now_ms = int(time.time() * 1000)
    diags = validate_envelope(envelope, now_ms=now_ms)
    errors = [d for d in diags if d.level == "error"]
    if errors:
        raise ValueError(
            f"7h3: envelope validation failed: {'; '.join(d.message for d in errors)}"
        )

    valid = verify_envelope_ed25519(envelope, public_key)
    if not valid:
        raise ValueError("7h3: invalid signature on queue message")

    if replay_store is not None:
        header = envelope["header"]
        if replay_store.check(header["nonce"], header["ttlMs"]):
            raise ValueError("7h3: replay detected — nonce already seen")

    return {"payload": payload, "envelope": envelope}


def verify_queue_batch(
    messages: List[str],
    public_key: str,
    *,
    replay_store: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """
    Verify a batch of queue messages without throwing.
    Each result is {"ok": True, "payload": ..., "envelope": ...} or
    {"ok": False, "raw": ..., "error": "..."}.
    """
    results = []
    for msg in messages:
        try:
            result = verify_queue_message(msg, public_key, replay_store=replay_store)
            results.append(
                {"ok": True, "payload": result["payload"], "envelope": result["envelope"]}
            )
        except Exception as e:
            results.append({"ok": False, "raw": msg, "error": str(e)})
    return results
