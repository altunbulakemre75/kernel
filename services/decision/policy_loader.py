import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


@dataclass
class LoadedPolicy:
    version_id: str
    version_short: str
    path: str
    loaded_at: datetime
    rules: dict[str, Any]
    raw_bytes: bytes


_CACHE: dict[str, LoadedPolicy] = {}


def clear_policy_cache() -> None:
    """Clear the policy cache for testing."""
    _CACHE.clear()


def canonical_policy_bytes(policy: dict[str, Any]) -> bytes:
    """Sorted keys, no whitespace, UTF-8. Identical YAML in different key order must produce identical bytes."""
    return json.dumps(policy, separators=(",", ":"), sort_keys=True).encode("utf-8")


def policy_hash(policy: dict[str, Any]) -> str:
    """SHA-256 hex digest of canonical bytes. Returns full 64-char hex."""
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


def policy_version_short(full_hash: str) -> str:
    """First 16 chars (like Git short hash)."""
    return full_hash[:16]


def load_policy(path: str) -> LoadedPolicy:
    """Reads YAML, validates schema (must have "rules" key with list), 
    computes hash, returns LoadedPolicy. Caches by hash so multiple 
    calls with same content return same object."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    
    if not isinstance(data, dict) or "rules" not in data or not isinstance(data["rules"], list):
        raise ValueError("Invalid policy schema: must have 'rules' key with a list")
        
    raw_bytes = canonical_policy_bytes(data)
    version_id = hashlib.sha256(raw_bytes).hexdigest()
    
    if version_id in _CACHE:
        return _CACHE[version_id]
        
    loaded = LoadedPolicy(
        version_id=version_id,
        version_short=policy_version_short(version_id),
        path=str(p),
        loaded_at=datetime.now(timezone.utc),
        rules=data,
        raw_bytes=raw_bytes
    )
    
    _CACHE[version_id] = loaded
    return loaded
