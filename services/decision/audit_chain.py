import base64
import hashlib
import json
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from shared.paths import kyvern_home
from shared.schemas import RuntimeEvent

if TYPE_CHECKING:
    from services.decision.policy_loader import LoadedPolicy


def load_or_create_keypair() -> ed25519.Ed25519PrivateKey:
    keys_dir = str(kyvern_home() / "keys")
    priv_path = os.path.join(keys_dir, "signing.key")
    pub_path = os.path.join(keys_dir, "signing.pub")
    
    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            priv_bytes = f.read()
        return serialization.load_pem_private_key(priv_bytes, password=None)
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    os.makedirs(keys_dir, exist_ok=True)
    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    os.chmod(priv_path, 0o600)
    
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    return private_key


def key_id(public_key: ed25519.Ed25519PublicKey) -> str:
    """First 16 hex chars of SHA-256 over the raw 32-byte public key."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


class Keyring:
    """Public keys a verifier trusts, looked up by the key_id stored in each record."""

    def __init__(self, public_keys: Iterable[ed25519.Ed25519PublicKey]) -> None:
        self._keys = {key_id(k): k for k in public_keys}

    @classmethod
    def from_pem_files(cls, paths: Iterable[str | Path]) -> "Keyring":
        return cls(serialization.load_pem_public_key(Path(p).read_bytes()) for p in paths)

    def get(self, kid: str) -> ed25519.Ed25519PublicKey | None:
        return self._keys.get(kid)

    def ids(self) -> list[str]:
        return list(self._keys)

    def __iter__(self) -> Iterator[ed25519.Ed25519PublicKey]:
        return iter(self._keys.values())

    def __len__(self) -> int:
        return len(self._keys)


PublicKeys = ed25519.Ed25519PublicKey | Keyring


def _candidate_keys(record: dict[str, Any], keys: PublicKeys) -> list[ed25519.Ed25519PublicKey]:
    """Keys allowed to have signed `record`. Records from before key_id existed may be
    signed by any trusted key; records with a key_id only by that key."""
    rid = record.get("key_id")
    if isinstance(keys, Keyring):
        if rid is None:
            return list(keys)
        key = keys.get(rid)
        return [key] if key is not None else []
    if rid is None or rid == key_id(keys):
        return [keys]
    return []

def canonical_json(decision: dict[str, Any]) -> bytes:
    clean_dict = {k: v for k, v in decision.items() if k not in ("signature", "payload_hash")}
    return json.dumps(clean_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

def sign_decision(decision: dict[str, Any], prev_hash: str | None, signing_key: ed25519.Ed25519PrivateKey) -> dict[str, Any]:
    """Sign an audit chain entry with Ed25519 + SHA-256 hash linking.

    Polymorphic: works for Decision dicts AND RuntimeEvent dicts. The
    function does not inspect record type; it canonicalizes the dict
    (excluding signature/payload_hash), computes payload_hash, signs the
    canonical JSON, and returns the dict with signature, payload_hash,
    prev_hash, and chain_index set. It also sets key_id, which is covered by
    the signature.
    """
    signed_decision = decision.copy()
    signed_decision["prev_hash"] = prev_hash
    signed_decision["chain_index"] = decision.get("chain_index", 0)
    signed_decision["key_id"] = key_id(signing_key.public_key())

    payload = canonical_json(signed_decision)
    payload_hash = sha256_hex(payload)
    
    sig = signing_key.sign(payload)
    
    signed_decision["payload_hash"] = payload_hash
    signed_decision["signature"] = base64.b64encode(sig).decode("utf-8")
    
    return signed_decision

def verify_decision(decision: dict[str, Any], public_key: PublicKeys) -> bool:
    """Verify an audit chain entry's signature.

    Polymorphic: works for Decision dicts AND RuntimeEvent dicts. `public_key` is a
    single Ed25519 public key or a Keyring; see _candidate_keys for key selection.
    """
    try:
        signature = decision.get("signature")
        if not signature:
            return False

        payload = canonical_json(decision)
        if decision.get("payload_hash") != sha256_hex(payload):
            return False

        sig_bytes = base64.b64decode(signature)
        for key in _candidate_keys(decision, public_key):
            try:
                key.verify(sig_bytes, payload)
                return True
            except InvalidSignature:
                continue
        return False
    except (ValueError, TypeError):
        return False

def verify_chain(
    decisions: list[dict[str, Any]],
    public_key: PublicKeys,
    prev_hash: str | None = None,
) -> tuple[bool, int | None]:
    """Verify a contiguous slice of the audit chain.

    Handles mixed Decision + RuntimeEvent chains. `chain_index` is a single
    monotonically increasing counter shared across both record types — this
    function walks it linearly and verifies each entry's signature + hash-link.
    public_key may be a Keyring for chains signed by several keys.

    prev_hash is the prev_hash the first entry must carry: None for a slice that
    starts at genesis, else the payload_hash of the entry just before the slice.
    Verifying a slice that does not start at genesis trusts that link.

    Returns:
        (True, None) if all entries verify.
        (False, first_bad_index) if any entry fails verification or breaks the
        prev_hash chain or chain_index sequence.
    """
    if not decisions:
        return True, None

    expected_index = decisions[0].get("chain_index", 0)
    
    for i, decision in enumerate(decisions):
        if decision.get("chain_index") != expected_index:
            return False, i
            
        if decision.get("prev_hash") != prev_hash:
            return False, i
            
        if not verify_decision(decision, public_key):
            return False, i
            
        prev_hash = decision.get("payload_hash")
        expected_index += 1

    return True, None


def describe_chain_failure(
    records: list[dict[str, Any]],
    index: int,
    public_key: PublicKeys,
    prev_hash: str | None = None,
) -> str:
    """Explain why records[index] failed verify_chain() (called with the same prev_hash)."""
    record = records[index]
    expected_index = records[0].get("chain_index", 0) + index
    if record.get("chain_index") != expected_index:
        return f"chain_index gap: expected {expected_index}, found {record.get('chain_index')}"
    expected_prev = prev_hash if index == 0 else records[index - 1].get("payload_hash")
    if record.get("prev_hash") != expected_prev:
        return "broken prev_hash link"
    rid = record.get("key_id")
    if rid is not None and not _candidate_keys(record, public_key):
        return f"signed by unknown key {rid}"
    return "bad signature"


def record_type_of(record: dict[str, Any]) -> str:
    """"runtime_event" or "decision"; records written before RuntimeEvent existed are Decisions."""
    return "runtime_event" if record.get("record_type") == "runtime_event" else "decision"


@dataclass
class PolicyCheck:
    """Whether every Decision in a chain is bound to one of the policies an auditor supplied.

    Positions are offsets into the list passed to check_policy_binding(). RuntimeEvents
    are not checked: their policy_version_id only records the policy in force when the
    event was appended. A chain with no Decision fails: nothing in it is bound to a policy.
    """

    per_policy: dict[str, int] = field(default_factory=dict)
    unbound: list[int] = field(default_factory=list)
    unknown: dict[int, str] = field(default_factory=dict)

    @property
    def decision_count(self) -> int:
        return sum(self.per_policy.values()) + len(self.unbound) + len(self.unknown)

    @property
    def ok(self) -> bool:
        return self.decision_count > 0 and not self.unbound and not self.unknown

    def reason(self) -> str:
        """One line explaining a failed check; empty when it passed."""
        if self.decision_count == 0:
            return "no decisions in the chain to check against a policy"
        parts = []
        if self.unbound:
            parts.append(
                f"{len(self.unbound)} decision(s) not bound to any policy "
                f"(recorded without policy_path) at {_positions(self.unbound)}"
            )
        if self.unknown:
            versions = sorted({v[:16] for v in self.unknown.values()})
            parts.append(
                f"{len(self.unknown)} decision(s) bound to a policy not given with --policy "
                f"({', '.join(versions)}) at {_positions(list(self.unknown))}"
            )
        return "; ".join(parts)


def _positions(indices: list[int], limit: int = 10) -> str:
    shown = ", ".join(str(i) for i in indices[:limit])
    more = f" and {len(indices) - limit} more" if len(indices) > limit else ""
    return f"[{shown}]{more}"


def check_policy_binding(
    records: list[dict[str, Any]], policies: "list[LoadedPolicy]"
) -> PolicyCheck:
    """Check that each Decision's policy_version_id matches one of `policies`."""
    known = {p.version_id for p in policies}
    check = PolicyCheck(per_policy={p.version_id: 0 for p in policies})
    for i, record in enumerate(records):
        if record_type_of(record) != "decision":
            continue
        version = record.get("policy_version_id")
        if not version:
            check.unbound.append(i)
        elif version in known:
            check.per_policy[version] += 1
        else:
            check.unknown[i] = version
    return check


def verify_decision_against_policy(decision: dict[str, Any], policy_path: str, public_key: PublicKeys) -> tuple[bool, str]:
    from services.decision.policy_loader import load_policy
    
    if not verify_decision(decision, public_key):
        return False, "Invalid decision signature"
        
    try:
        policy = load_policy(policy_path)
    except Exception as e:
        return False, f"Failed to load policy: {e}"
        
    decision_policy_version = decision.get("policy_version_id")
    if not decision_policy_version:
        return False, "Decision does not contain a policy_version_id"
        
    if policy.version_id != decision_policy_version:
        return False, f"Policy version mismatch: decision has {decision_policy_version}, loaded policy has {policy.version_id}"

    return True, "Match"


def _read_last_entry(chain_path: Path) -> dict[str, Any] | None:
    """Read and parse the last JSONL line of chain_path, or None if file missing/empty."""
    if not chain_path.exists():
        return None
    lines = [
        line for line in chain_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not lines:
        return None
    return json.loads(lines[-1])


def append_runtime_event(
    event: RuntimeEvent,
    chain_path: Path,
    signing_key: ed25519.Ed25519PrivateKey,
    policy_version_id: str | None = None,
) -> RuntimeEvent:
    """Sign and append a RuntimeEvent to the JSONL audit chain.

    policy_version_id records which policy was in force when the event was
    appended. It is informational: auditor tools show it but only check
    Decisions against a policy.

    All chain fields on the input event (signature, prev_hash, payload_hash,
    chain_index, key_id, policy_version_id) are overwritten by this function —
    caller values are discarded. This is a security contract: caller cannot
    pre-set chain_index or signature to compromise integrity. Raises
    AuditWriteError if the event cannot be appended.

    See spec: docs/superpowers/specs/2026-05-20-runtime-event-design.md §6.
    """
    # Imported here: chain_writer imports this module.
    from services.decision.chain_writer import ChainWriter

    # Pydantic validators have already run at construction time, so the event
    # is structurally valid.
    record: dict[str, Any] = event.model_dump()
    record["policy_version_id"] = policy_version_id
    # ChainWriter discards caller-supplied signature/payload_hash/key_id/prev_hash/
    # chain_index, holds the chain lock, checks the tail and fsyncs.
    signed = ChainWriter(Path(chain_path), signing_key).append(record)
    return RuntimeEvent(**signed)


def verify_runtime_event(event: dict[str, Any], public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verify a RuntimeEvent's signature. Thin alias over verify_decision
    (which is already type-agnostic) — exists so calling code can express
    intent explicitly."""
    return verify_decision(event, public_key)
