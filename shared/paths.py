"""
shared/paths.py — Where Kyvern keeps per-user state (signing keys, default chain).
"""

from __future__ import annotations

import os
from pathlib import Path

HOME_DIR_NAME = ".kyvern"
LEGACY_HOME_DIR_NAME = ".kernel"  # used before the kernel -> Kyvern rename
CHAIN_PATH_ENV = "KYVERN_CHAIN_PATH"


class LegacyHomeError(RuntimeError):
    """Only the pre-rename ~/.kernel directory exists."""


def kyvern_home() -> Path:
    """Return ~/.kyvern, refusing to continue if only the pre-rename ~/.kernel exists.

    Without this check load_or_create_keypair() would find no key under ~/.kyvern
    and silently start signing with a brand-new one.
    """
    home = Path.home()
    current = home / HOME_DIR_NAME
    legacy = home / LEGACY_HOME_DIR_NAME
    if not current.exists() and legacy.exists():
        raise LegacyHomeError(
            f"Found {legacy} from before the kernel -> Kyvern rename, but {current} "
            f"does not exist. Move it to keep your signing key and chain: "
            f"mv {legacy} {current}"
        )
    return current


def default_chain_path() -> Path:
    """The audit chain file used when none is given: $KYVERN_CHAIN_PATH, else ~/.kyvern/chain.jsonl."""
    override = os.environ.get(CHAIN_PATH_ENV)
    return Path(override) if override else kyvern_home() / "chain.jsonl"
