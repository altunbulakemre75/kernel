import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.audit_chain import sign_decision

_BASE_TS = datetime(2026, 5, 18, 14, 32, 0, tzinfo=timezone.utc)


@pytest.fixture
def signing_keypair(tmp_path: Path):
    sk = ed25519.Ed25519PrivateKey.generate()
    pub_path = tmp_path / "signing.pub"
    pub_path.write_bytes(
        sk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return sk, sk.public_key(), pub_path


def _raw_events() -> list[dict]:
    return [
        {
            "chain_index": 0,
            "timestamp_iso": _BASE_TS.isoformat(),
            "action": "allow",
            "threat_level": "low",
            "policy_version_id": "p_test",
            "metadata": {"target": {"ip": "10.0.0.5"}, "rule_id": "r_001"},
        },
        {
            "chain_index": 1,
            "timestamp_iso": (_BASE_TS + timedelta(seconds=10)).isoformat(),
            "action": "block",
            "threat_level": "high",
            "policy_version_id": "p_test",
            "metadata": {"target": {"ip": "10.0.0.6"}, "rule_id": "r_002"},
        },
        {
            "chain_index": 2,
            "timestamp_iso": (_BASE_TS + timedelta(hours=2)).isoformat(),
            "action": "flag",
            "threat_level": "medium",
            "policy_version_id": "p_test",
            "metadata": {"target": {"ip": "10.0.0.7"}, "rule_id": "r_003"},
        },
        {
            "chain_index": 3,
            "timestamp_iso": (_BASE_TS + timedelta(days=2)).isoformat(),
            "action": "allow",
            "threat_level": "low",
            "policy_version_id": "p_test",
            "metadata": {"target": {"ip": "10.0.0.8"}, "rule_id": "r_001"},
        },
    ]


def _write_chain(path: Path, events: list[dict], sk) -> None:
    lines = []
    prev_hash = None
    for ev in events:
        signed = sign_decision(ev, prev_hash=prev_hash, signing_key=sk)
        lines.append(json.dumps(signed))
        prev_hash = signed["payload_hash"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def sample_chain_file(tmp_path: Path, signing_keypair) -> Path:
    sk, _, _ = signing_keypair
    chain_file = tmp_path / "chain.jsonl"
    _write_chain(chain_file, _raw_events(), sk)
    return chain_file


@pytest.fixture
def tampered_chain_file(tmp_path: Path, signing_keypair) -> Path:
    """Chain where event[1].action was flipped after signing — breaks chain."""
    sk, _, _ = signing_keypair
    chain_file = tmp_path / "chain_tampered.jsonl"
    _write_chain(chain_file, _raw_events(), sk)
    raw = chain_file.read_text(encoding="utf-8").splitlines()
    ev1 = json.loads(raw[1])
    ev1["action"] = "allow"  # tamper — signature now invalid
    raw[1] = json.dumps(ev1)
    chain_file.write_text("\n".join(raw) + "\n", encoding="utf-8")
    return chain_file
