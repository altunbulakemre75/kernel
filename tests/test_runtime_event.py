"""Tests for RuntimeEvent — upstream evidence events signed into the audit chain."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError

from shared.schemas import RUNTIME_EVENT_PAYLOAD_MAX_BYTES, RuntimeEvent


@pytest.fixture
def signing_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def public_key(signing_key):
    return signing_key.public_key()


def _valid_event_kwargs() -> dict:
    return {
        "event_type": "sensor_anomaly",
        "source": "lidar_monitor",
        "source_id": "lidar-front-01",
        "timestamp_iso": "2026-05-20T12:00:00+00:00",
        "payload": {"distance_m": 4.2, "object_class": "vehicle"},
    }


def test_runtime_event_creation():
    ev = RuntimeEvent(**_valid_event_kwargs())

    # Discriminator and defaults
    assert ev.record_type == "runtime_event"
    assert ev.context == {}
    assert ev.chain_index == 0
    assert ev.signature is None
    assert ev.prev_hash is None
    assert ev.payload_hash is None
    assert ev.policy_version_id is None

    # User-supplied fields preserved verbatim
    assert ev.event_type == "sensor_anomaly"
    assert ev.source == "lidar_monitor"
    assert ev.source_id == "lidar-front-01"
    assert ev.payload == {"distance_m": 4.2, "object_class": "vehicle"}


def test_payload_size_limit_enforced():
    # 1 byte under the limit must pass
    just_under = "x" * (RUNTIME_EVENT_PAYLOAD_MAX_BYTES - 100)
    kwargs = _valid_event_kwargs() | {"payload": {"blob": just_under}}
    ev = RuntimeEvent(**kwargs)
    assert ev.payload["blob"] == just_under

    # Over the limit must raise PayloadTooLargeError (wrapped in ValidationError)
    too_big = "x" * (RUNTIME_EVENT_PAYLOAD_MAX_BYTES + 1)
    kwargs = _valid_event_kwargs() | {"payload": {"blob": too_big}}
    with pytest.raises(ValidationError) as exc_info:
        RuntimeEvent(**kwargs)

    # The original PayloadTooLargeError must be in the error context
    errors = exc_info.value.errors()
    assert any("payload exceeds" in str(e.get("msg", "")).lower() for e in errors)


def test_source_id_constraints():
    # Empty source_id rejected
    kwargs = _valid_event_kwargs() | {"source_id": ""}
    with pytest.raises(ValidationError):
        RuntimeEvent(**kwargs)

    # 257-char source_id rejected (one over max)
    kwargs = _valid_event_kwargs() | {"source_id": "x" * 257}
    with pytest.raises(ValidationError):
        RuntimeEvent(**kwargs)

    # 1-char source_id accepted (min boundary)
    kwargs = _valid_event_kwargs() | {"source_id": "x"}
    assert RuntimeEvent(**kwargs).source_id == "x"

    # 256-char source_id accepted (max boundary)
    kwargs = _valid_event_kwargs() | {"source_id": "x" * 256}
    assert RuntimeEvent(**kwargs).source_id == "x" * 256


def test_append_single_runtime_event(tmp_path: Path, signing_key, public_key):
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_decision,
    )

    chain_path = tmp_path / "chain.jsonl"
    ev = RuntimeEvent(**_valid_event_kwargs())

    signed = append_runtime_event(
        event=ev,
        chain_path=chain_path,
        signing_key=signing_key,
        policy_version_id="p_test_v1",
    )

    # Returned instance has chain fields filled
    assert signed.chain_index == 0
    assert signed.prev_hash is None
    assert signed.payload_hash is not None
    assert len(signed.payload_hash) == 64  # SHA-256 hex
    assert signed.signature is not None
    assert len(signed.signature) > 0
    assert signed.policy_version_id == "p_test_v1"
    assert signed.record_type == "runtime_event"

    # File contains exactly one signed line, which verifies
    lines = chain_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    on_disk = json.loads(lines[0])
    assert on_disk["record_type"] == "runtime_event"
    assert verify_decision(on_disk, public_key) is True


def test_caller_provided_chain_fields_are_overwritten(
    tmp_path: Path, signing_key, public_key
):
    """Security contract: caller-supplied chain fields must be discarded.
    Malicious or buggy callers cannot break chain integrity."""
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_decision,
    )

    chain_path = tmp_path / "chain.jsonl"

    # Caller tries to inject bogus chain fields
    ev = RuntimeEvent(
        **_valid_event_kwargs(),
        signature="fakefakefake==",
        prev_hash="ff" * 32,
        payload_hash="bad" * 21 + "b",  # 64 chars
        chain_index=999,
        policy_version_id="injected_by_caller",
    )

    signed = append_runtime_event(
        event=ev,
        chain_path=chain_path,
        signing_key=signing_key,
        policy_version_id="legitimate_v1",
    )

    # All five caller-provided values must have been overwritten
    assert signed.chain_index == 0  # not 999
    assert signed.prev_hash is None  # not "ff"*32 (first entry, genesis)
    assert signed.payload_hash != "bad" * 21 + "b"  # real SHA-256 of canonical bytes
    assert signed.signature != "fakefakefake=="  # real Ed25519 signature
    assert signed.policy_version_id == "legitimate_v1"  # from function param

    # And the signed line on disk verifies correctly
    on_disk = json.loads(chain_path.read_text(encoding="utf-8").strip())
    assert verify_decision(on_disk, public_key) is True
