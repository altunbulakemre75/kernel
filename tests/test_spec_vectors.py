"""docs/verification-spec.md: its test vectors match the implementation.

The vectors are rebuilt from the published test key and compared with
tests/fixtures/spec/; the values quoted in the spec are recomputed. A change to
the canonical form, the hashes or the anchor statement fails here first.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from services.decision.anchors import anchor_statement
from services.decision.audit_chain import canonical_json, key_id, sha256_hex, verify_chain
from services.decision.policy_loader import clear_policy_cache, load_policy

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "spec"
SPEC = ROOT / "docs" / "verification-spec.md"


def _generator():
    spec = importlib.util.spec_from_file_location(
        "generate_spec_vectors", ROOT / "scripts" / "generate_spec_vectors.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _raw_public_key(path: Path) -> bytes:
    """The key itself: git may have turned the PEM file's line ends into CRLF."""
    key = serialization.load_pem_public_key(path.read_bytes())
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _pem_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n").strip()


def _vectors() -> dict[str, str]:
    """The fenced block after each <!-- vector:NAME --> marker in the spec."""
    text = SPEC.read_text(encoding="utf-8").replace("\r\n", "\n")
    return {
        name: body.strip()
        for name, body in re.findall(r"<!-- vector:([a-z0-9-]+) -->\n```text\n(.*?)```", text, re.S)
    }


@pytest.fixture(autouse=True)
def _fresh_policy_cache():
    clear_policy_cache()
    yield
    clear_policy_cache()


def test_the_vectors_are_reproduced_from_the_test_key(tmp_path):
    _generator().build(tmp_path)
    assert _records(tmp_path / "chain.jsonl") == _records(FIXTURE / "chain.jsonl")
    assert _raw_public_key(tmp_path / "signing.pub") == _raw_public_key(FIXTURE / "signing.pub")


def test_the_vector_chain_verifies():
    public_key = serialization.load_pem_public_key((FIXTURE / "signing.pub").read_bytes())
    assert verify_chain(_records(FIXTURE / "chain.jsonl"), public_key) == (True, None)


def test_the_values_quoted_in_the_spec_are_current():
    records = _records(FIXTURE / "chain.jsonl")
    public_key = serialization.load_pem_public_key((FIXTURE / "signing.pub").read_bytes())
    statement = anchor_statement(1, records[1]["payload_hash"])
    expected = {
        "public-key": _pem_text(FIXTURE / "signing.pub"),
        "key-id": key_id(public_key),
        "policy-version-id": load_policy(str(FIXTURE / "policy.yaml")).version_id,
        "canonical-0": canonical_json(records[0]).decode("ascii"),
        "payload-hash-0": records[0]["payload_hash"],
        "signature-0": records[0]["signature"],
        "payload-hash-1": records[1]["payload_hash"],
        "statement-1": statement.decode("ascii"),
        "imprint-1": hashlib.sha256(statement).hexdigest(),
    }
    assert _vectors() == expected
    assert sha256_hex(canonical_json(records[0])) == records[0]["payload_hash"]
