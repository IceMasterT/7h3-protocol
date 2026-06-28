"""Key infrastructure for 7h3 Protocol — discovery, rotation, revocation."""
from __future__ import annotations
import json
import time
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

WELL_KNOWN_PATH = "/.well-known/7h3-keys"
REVOCATION_PATH = "/.well-known/7h3-revoked"

@dataclass
class KeyEntry:
    id: str
    algorithm: str  # 'Ed25519'
    public_key: str  # SPKI base64url
    created: int     # Unix ms
    expires: Optional[int] = None
    revoked: bool = False
    revoked_at: Optional[int] = None

@dataclass
class WellKnownKeysDocument:
    version: str  # '7h3/0.1'
    updated: int
    keys: List[KeyEntry]

    def to_json(self) -> str:
        keys_list = []
        for k in self.keys:
            entry = {
                "id": k.id, "algorithm": k.algorithm, "publicKey": k.public_key,
                "created": k.created,
            }
            if k.expires is not None: entry["expires"] = k.expires
            if k.revoked: entry["revoked"] = True
            if k.revoked_at is not None: entry["revokedAt"] = k.revoked_at
            keys_list.append(entry)
        return json.dumps({"version": self.version, "updated": self.updated, "keys": keys_list}, separators=(",", ":"))

    @classmethod
    def from_json(cls, data: str) -> "WellKnownKeysDocument":
        d = json.loads(data)
        keys = []
        for k in d.get("keys", []):
            keys.append(KeyEntry(
                id=k["id"], algorithm=k["algorithm"], public_key=k["publicKey"],
                created=k["created"], expires=k.get("expires"), revoked=k.get("revoked", False),
                revoked_at=k.get("revokedAt"),
            ))
        return cls(version=d["version"], updated=d["updated"], keys=keys)


def fetch_well_known_keys(base_url: str, *, timeout: float = 5.0) -> WellKnownKeysDocument:
    """Fetch the /.well-known/7h3-keys document from a base URL."""
    import urllib.request
    url = base_url.rstrip("/") + WELL_KNOWN_PATH
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        data = resp.read().decode("utf-8")
    return WellKnownKeysDocument.from_json(data)


@dataclass
class ManagedKeyPair:
    id: str
    public_key: str   # SPKI base64url
    private_key: str  # PKCS8 base64url
    created: int
    expires_at: Optional[int] = None


class KeyRotationManager:
    """Manages Ed25519 key pairs with automatic rotation."""

    def __init__(self, max_age_ms: int = 86_400_000, overlap_ms: int = 3_600_000):
        self.max_age_ms = max_age_ms
        self.overlap_ms = overlap_ms
        self._keys: List[ManagedKeyPair] = []
        self._lock = threading.Lock()

    def add_key(self, pair: ManagedKeyPair) -> None:
        with self._lock:
            self._keys.append(pair)

    def get_current_key(self) -> Optional[ManagedKeyPair]:
        """Return the most recently created non-expired key."""
        now = int(time.time() * 1000)
        with self._lock:
            active = [k for k in self._keys if not k.expires_at or k.expires_at > now]
            if not active:
                return None
            return sorted(active, key=lambda k: k.created, reverse=True)[0]

    def rotate_if_needed(self) -> Optional[ManagedKeyPair]:
        """Generate a new key if the current one is too old.

        NOTE: generate_ed25519_keypair does not exist in protocol.py.
        Callers should supply keys externally via add_key() rather than
        relying on this method.
        """
        raise NotImplementedError(
            "rotate_if_needed requires generate_ed25519_keypair which is not "
            "implemented in protocol.py. Supply new keys externally via add_key()."
        )

    def get_well_known_document(self) -> WellKnownKeysDocument:
        now = int(time.time() * 1000)
        with self._lock:
            entries = []
            for k in self._keys:
                entry = KeyEntry(
                    id=k.id, algorithm="Ed25519", public_key=k.public_key,
                    created=k.created, expires=k.expires_at,
                    revoked=bool(k.expires_at and k.expires_at < now),
                )
                entries.append(entry)
        return WellKnownKeysDocument(version="7h3/0.1", updated=now, keys=entries)


class RevocationRegistry:
    """Tracks revoked key IDs."""

    def __init__(self):
        self._revoked: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def revoke(self, key_id: str, reason: Optional[str] = None) -> None:
        with self._lock:
            self._revoked[key_id] = {"revokedAt": int(time.time() * 1000), "reason": reason}

    def is_revoked(self, key_id: str) -> bool:
        with self._lock:
            return key_id in self._revoked

    def get_list(self) -> dict:
        now = int(time.time() * 1000)
        with self._lock:
            revoked = [
                {"id": kid, "revokedAt": v["revokedAt"], **({"reason": v["reason"]} if v["reason"] else {})}
                for kid, v in self._revoked.items()
            ]
        return {"version": "7h3/0.1", "updated": now, "revokedKeys": revoked}

    def import_list(self, revocation_list: dict) -> None:
        with self._lock:
            for entry in revocation_list.get("revokedKeys", []):
                kid = entry["id"]
                if kid not in self._revoked:
                    self._revoked[kid] = {"revokedAt": entry["revokedAt"], "reason": entry.get("reason")}
