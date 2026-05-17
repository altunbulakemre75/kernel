from datetime import datetime, timezone, timedelta

from kernel.audit.store import AuditChainStore


def test_store_loads_jsonl(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    assert len(store.events()) == 4
    assert store.events()[0]["action"] == "allow"


def test_filter_by_action(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    blocks = store.filter(action="block")
    assert len(blocks) == 1
    assert blocks[0]["chain_index"] == 1


def test_filter_by_threat_level(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    highs = store.filter(threat_level="high")
    assert len(highs) == 1
    assert highs[0]["chain_index"] == 1


def test_filter_by_time_window(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    start = datetime(2026, 5, 18, 14, 32, 0, tzinfo=timezone.utc)
    end = start + timedelta(minutes=5)
    inside = store.filter(start_time=start, end_time=end)
    assert {e["chain_index"] for e in inside} == {0, 1}


def test_filter_limit_returns_newest_first(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    last_two = store.filter(limit=2)
    assert [e["chain_index"] for e in last_two] == [3, 2]


def test_get_event_by_id(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    ev = store.get(2)
    assert ev is not None
    assert ev["action"] == "flag"


def test_get_event_unknown_id_returns_none(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    assert store.get(999) is None


import time

import pytest


def test_verify_event_clean(sample_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    store = AuditChainStore(sample_chain_file, public_key_path=pub_path)
    store.load()
    assert store.verify_event(0) is True
    assert store.verify_event(2) is True


def test_verify_event_tampered(tampered_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    store = AuditChainStore(tampered_chain_file, public_key_path=pub_path)
    store.load()
    assert store.verify_event(1) is False


def test_verify_event_without_key_returns_none(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    assert store.verify_event(0) is None


def test_verify_chain_range_clean(sample_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    store = AuditChainStore(sample_chain_file, public_key_path=pub_path)
    store.load()
    result = store.verify_chain_range(0, None)
    assert result.integrity == "OK"
    assert result.verified_count == 4
    assert result.first_break is None


def test_verify_chain_range_tampered(tampered_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    store = AuditChainStore(tampered_chain_file, public_key_path=pub_path)
    store.load()
    result = store.verify_chain_range(0, None)
    assert result.integrity == "BROKEN"
    assert result.first_break is not None
    assert result.first_break["id"] == 1


def test_verify_chain_range_without_key_unknown(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    result = store.verify_chain_range(0, None)
    assert result.integrity == "UNKNOWN"


def test_reload_debounce_skips_within_window(sample_chain_file):
    store = AuditChainStore(
        sample_chain_file, verify_on_query=False, reload_debounce_seconds=10.0
    )
    store.load()
    initial_mtime = store._mtime
    # Append a new event by hand
    sample_chain_file.write_text(
        sample_chain_file.read_text(encoding="utf-8") + '{"chain_index": 99}\n',
        encoding="utf-8",
    )
    # Force a fresh mtime
    new_time = (initial_mtime or 0) + 100
    import os
    os.utime(sample_chain_file, (new_time, new_time))
    # Within debounce window — should NOT reload
    store.reload_if_stale()
    assert len(store.events()) == 4


def test_reload_debounce_picks_up_changes_after_window(sample_chain_file):
    store = AuditChainStore(
        sample_chain_file, verify_on_query=False, reload_debounce_seconds=0.05
    )
    store.load()
    initial_mtime = store._mtime
    sample_chain_file.write_text(
        sample_chain_file.read_text(encoding="utf-8")
        + '{"chain_index": 99, "action": "allow"}\n',
        encoding="utf-8",
    )
    import os
    os.utime(sample_chain_file, ((initial_mtime or 0) + 100, (initial_mtime or 0) + 100))
    time.sleep(0.1)
    store.reload_if_stale()
    assert len(store.events()) == 5
