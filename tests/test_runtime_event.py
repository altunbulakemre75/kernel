"""Tests for RuntimeEvent — upstream evidence events signed into the audit chain."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from shared.schemas import RUNTIME_EVENT_PAYLOAD_MAX_BYTES, RuntimeEvent


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
