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
