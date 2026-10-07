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


def _append_decision_directly(
    chain_path: Path,
    decision: dict,
    signing_key,
) -> dict:
    """Test helper: sign a Decision-like dict and append to chain.
    Uses the same primitives as append_runtime_event for chain continuity."""
    from services.decision.audit_chain import _read_last_entry, sign_decision

    last = _read_last_entry(chain_path)
    if last is None:
        prev_hash = None
        next_index = 0
    else:
        prev_hash = last.get("payload_hash")
        next_index = int(last.get("chain_index", -1)) + 1

    payload_dict = dict(decision)
    payload_dict["chain_index"] = next_index
    payload_dict["prev_hash"] = prev_hash
    payload_dict.pop("signature", None)
    payload_dict.pop("payload_hash", None)

    signed = sign_decision(
        decision=payload_dict,
        prev_hash=prev_hash,
        signing_key=signing_key,
    )

    with open(chain_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(signed, separators=(",", ":")) + "\n")

    return signed


def _decision_dict(timestamp_iso: str, action: str = "allow") -> dict:
    return {
        "timestamp_iso": timestamp_iso,
        "action": action,
        "threat_level": "low",
        "policy_version_id": "p_test",
        "metadata": {"rule_id": "r_001"},
    }


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


def test_mixed_chain_decision_then_runtime(
    tmp_path: Path, signing_key, public_key
):
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_chain,
    )

    chain_path = tmp_path / "chain.jsonl"

    # idx=0: Decision
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:00+00:00", "allow"),
        signing_key,
    )

    # idx=1: RuntimeEvent
    ev1 = RuntimeEvent(**_valid_event_kwargs())
    append_runtime_event(ev1, chain_path, signing_key, "p_test")

    # idx=2: Decision
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:02+00:00", "block"),
        signing_key,
    )

    # Read the full chain and verify integrity
    lines = chain_path.read_text(encoding="utf-8").strip().splitlines()
    entries = [json.loads(line) for line in lines]
    assert len(entries) == 3

    # Chain indices are a single shared sequence: 0, 1, 2
    assert [e["chain_index"] for e in entries] == [0, 1, 2]

    # verify_chain returns (True, None) for the whole mixed chain
    ok, broken_idx = verify_chain(entries, public_key)
    assert ok is True
    assert broken_idx is None


def test_prev_hash_integrity_mixed(
    tmp_path: Path, signing_key, public_key
):
    """Each entry's prev_hash must equal the previous entry's payload_hash,
    regardless of record_type. This is the explicit single-monotonic-chain rule."""
    from services.decision.audit_chain import append_runtime_event

    chain_path = tmp_path / "chain.jsonl"

    # idx=0: RuntimeEvent (genesis)
    ev0 = RuntimeEvent(**(_valid_event_kwargs() | {"event_type": "boot"}))
    append_runtime_event(ev0, chain_path, signing_key, "p_test")

    # idx=1: Decision
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:01+00:00", "allow"),
        signing_key,
    )

    # idx=2: RuntimeEvent
    ev2 = RuntimeEvent(**(_valid_event_kwargs() | {"event_type": "shutdown"}))
    append_runtime_event(ev2, chain_path, signing_key, "p_test")

    entries = [
        json.loads(line)
        for line in chain_path.read_text(encoding="utf-8").strip().splitlines()
    ]

    # Walk the chain: each prev_hash matches the previous payload_hash
    assert entries[0]["prev_hash"] is None  # genesis
    assert entries[1]["prev_hash"] == entries[0]["payload_hash"]
    assert entries[2]["prev_hash"] == entries[1]["payload_hash"]

    # And the record types are interleaved as expected
    types = [e.get("record_type", "decision") for e in entries]
    assert types == ["runtime_event", "decision", "runtime_event"]


def test_payload_tampering_detected(
    tmp_path: Path, signing_key, public_key
):
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_decision,
    )

    chain_path = tmp_path / "chain.jsonl"
    ev = RuntimeEvent(**_valid_event_kwargs())
    append_runtime_event(ev, chain_path, signing_key, "p_test")

    # Read the signed line, tamper with payload, write it back
    line = chain_path.read_text(encoding="utf-8").strip()
    entry = json.loads(line)
    assert verify_decision(entry, public_key) is True  # baseline

    entry["payload"]["object_class"] = "pedestrian"  # was "vehicle" — tamper
    chain_path.write_text(json.dumps(entry, separators=(",", ":")) + "\n", encoding="utf-8")

    # Re-read and verify — signature must no longer match
    tampered = json.loads(chain_path.read_text(encoding="utf-8").strip())
    assert verify_decision(tampered, public_key) is False


def test_verify_runtime_event_alias(tmp_path: Path, signing_key, public_key):
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_runtime_event,
    )

    chain_path = tmp_path / "chain.jsonl"
    ev = RuntimeEvent(**_valid_event_kwargs())
    append_runtime_event(ev, chain_path, signing_key, "p_test")

    entry = json.loads(chain_path.read_text(encoding="utf-8").strip())
    assert verify_runtime_event(entry, public_key) is True


def test_mcp_query_events_filters_by_event_type(
    tmp_path: Path, signing_key, public_key
):
    """End-to-end: MCP query_events with event_type filter returns only
    matching RuntimeEvents from a mixed chain; action filter returns only Decisions."""
    from cryptography.hazmat.primitives import serialization
    from mcp.server.fastmcp import FastMCP

    from kyvern.audit.store import AuditChainStore
    from kyvern.mcp.tools import register_tools
    from services.decision.audit_chain import append_runtime_event

    chain_path = tmp_path / "chain.jsonl"
    pub_path = tmp_path / "signing.pub"
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # idx=0: Decision (allow)
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:00+00:00", "allow"),
        signing_key,
    )

    # idx=1: RuntimeEvent (sensor_anomaly)
    append_runtime_event(
        RuntimeEvent(**(_valid_event_kwargs() | {"event_type": "sensor_anomaly"})),
        chain_path, signing_key, "p_test",
    )

    # idx=2: RuntimeEvent (guardrail_downgrade)
    append_runtime_event(
        RuntimeEvent(**(_valid_event_kwargs() | {
            "event_type": "guardrail_downgrade",
            "source": "kinematic_guard",
        })),
        chain_path, signing_key, "p_test",
    )

    # idx=3: Decision (block)
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:03+00:00", "block"),
        signing_key,
    )

    store = AuditChainStore(chain_path, public_key_path=pub_path)
    store.load()
    app = FastMCP("test-runtime-event")
    register_tools(app, store)

    # Use the canonical access pattern from tests/mcp/test_tools.py
    def _call_tool(name, **kwargs):
        return app._tool_manager.get_tool(name).fn(**kwargs)

    # event_type filter -> only that RuntimeEvent
    results = _call_tool("query_events", event_type="sensor_anomaly", limit=100)
    assert len(results) == 1
    assert results[0]["event_type"] == "sensor_anomaly"
    assert results[0]["record_type"] == "runtime_event"

    # action filter -> only Decisions
    results = _call_tool("query_events", action="allow", limit=100)
    assert len(results) == 1
    assert results[0]["action"] == "allow"
    assert results[0]["record_type"] == "decision"

    # No filter -> all 4 entries, mixed record_types present
    results = _call_tool("query_events", limit=100)
    types = {r["record_type"] for r in results}
    assert types == {"decision", "runtime_event"}
    assert len(results) == 4
