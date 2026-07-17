"""
Redis-backed replay store for the 7h3 Protocol Python SDK.

Provides atomic nonce deduplication using Redis SET NX PX semantics.
The ``redis`` package is optional — an ImportError is raised at construction
time (not at module import) when it is absent, so the rest of the SDK remains
usable without installing Redis dependencies.
"""

from __future__ import annotations

import time
from typing import Optional, Any, Dict


class InMemoryReplayStore:
    """
    Zero-dependency in-memory replay store — same ``check(key, ttl_ms) -> bool``
    interface as :class:`RedisReplayStore`, so it's a drop-in default for a
    single long-lived consumer process. For a horizontally-scaled consumer
    group (multiple processes/machines), use :class:`RedisReplayStore` instead
    so nonce state is actually shared.

    Construct ONE instance per consumer process and reuse it across every
    verify call — a fresh instance per call provides no protection at all,
    since a replayed nonce would never be recognized as already-seen.
    """

    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}

    def check(self, key: str, ttl_ms: int) -> bool:
        """
        Returns ``False`` if the key is fresh (first time seen), or ``True``
        if it's a replay (already seen and not yet expired).
        """
        now = time.monotonic()
        self._prune(now)
        if key in self._seen:
            return True  # replay
        self._seen[key] = now + max(0.001, ttl_ms / 1000)
        return False  # fresh

    def _prune(self, now: float) -> None:
        expired = [k for k, expires_at in self._seen.items() if expires_at <= now]
        for k in expired:
            del self._seen[k]


class RedisReplayStore:
    """
    Atomic replay detection backed by Redis.

    Uses ``SET key value NX PX ttl_ms`` so the first caller atomically claims
    the nonce and all subsequent callers are identified as replays — safe
    across multiple horizontally-scaled gateway instances.

    Parameters
    ----------
    redis_url:
        Redis connection URL passed to ``redis.from_url()``.  Ignored when
        *client* is provided.
    key_prefix:
        Namespace prefix prepended to every nonce key. Default ``'7h3:nonce:'``.
    client:
        Pre-constructed Redis client (any object that exposes ``set`` and
        ``close``).  When supplied, *redis_url* is ignored.

    Raises
    ------
    ImportError
        At construction time when *redis_url* is provided but the ``redis``
        package is not installed.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        key_prefix: str = "7h3:nonce:",
        client: Optional[Any] = None,
    ) -> None:
        self.key_prefix = key_prefix

        if client is not None:
            self._client = client
        else:
            try:
                import redis  # type: ignore[import]
            except ImportError as exc:
                raise ImportError(
                    "The 'redis' package is required to use RedisReplayStore. "
                    "Install it with: pip install redis"
                ) from exc

            url = redis_url or "redis://localhost:6379"
            self._client = redis.from_url(url, decode_responses=True)

    def check(self, key: str, ttl_ms: int) -> bool:
        """
        Atomically check and register a nonce.

        Returns
        -------
        bool
            ``False`` if the nonce is fresh (first time seen — the key was set
            in Redis), or ``True`` if the nonce is a replay (the key already
            existed in Redis and SET NX was blocked).
        """
        redis_key = f"{self.key_prefix}{key}"
        px = max(1, ttl_ms)
        result = self._client.set(redis_key, "1", nx=True, px=px)
        # redis-py returns True when the key was set, None when NX blocked it
        return result is None

    def close(self) -> None:
        """Close the underlying Redis connection."""
        close = getattr(self._client, "close", None)
        if close is not None:
            close()


def create_redis_replay_store(redis_url: str, key_prefix: str = "7h3:nonce:") -> RedisReplayStore:
    """
    Convenience factory — create a :class:`RedisReplayStore` from a Redis URL.

    Parameters
    ----------
    redis_url:
        Redis connection URL, e.g. ``'redis://localhost:6379'``.
    key_prefix:
        Key namespace prefix. Default ``'7h3:nonce:'``.
    """
    return RedisReplayStore(redis_url=redis_url, key_prefix=key_prefix)
