"""Generic anchoring: statement, receipts file, anchor_head, check_anchors."""
from __future__ import annotations

import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision import anchors
from services.decision.anchors import (
    AnchorError,
    anchor_head,
    anchor_statement,
    anchors_path_for,
    append_receipt,
    check_anchors,
    read_receipts,
)
from services.decision.chain_writer import ChainWriter
from tests.decision.fake_anchor import FakeAnchor


@pytest.fixture
def chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    writer = ChainWriter(path, ed25519.Ed25519PrivateKey.generate())
    writer.append({"n": 0})
    writer.append({"n": 1})
    return path, writer


def _entries(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_statement_is_deterministic_and_names_the_entry():
    s = anchor_statement(4, "ab" * 32)
    assert s == anchor_statement(4, "ab" * 32)
    assert s == b'{"chain_index":4,"kyvern_anchor":1,"payload_hash":"' + b"ab" * 32 + b'"}'
    assert s != anchor_statement(5, "ab" * 32)
    assert s != anchor_statement(4, "cd" * 32)


def test_anchors_path_sits_next_to_the_chain(tmp_path):
    assert anchors_path_for(tmp_path / "chain.jsonl") == tmp_path / "chain.anchors.jsonl"


def test_receipts_round_trip_and_are_fsynced(tmp_path, monkeypatch):
    calls = []
    real_fsync = os.fsync
    monkeypatch.setattr(anchors.os, "fsync", lambda fd: (calls.append(fd), real_fsync(fd)))
    path = tmp_path / "chain.anchors.jsonl"
    append_receipt(path, {"anchor": "fake", "chain_index": 0})
    append_receipt(path, {"anchor": "fake", "chain_index": 1})
    assert read_receipts(path) == [
        {"anchor": "fake", "chain_index": 0},
        {"anchor": "fake", "chain_index": 1},
    ]
    assert len(calls) == 2
    assert read_receipts(tmp_path / "missing.jsonl") == []


def test_anchor_head_anchors_the_last_entry(chain):
    path, _ = chain
    fake = FakeAnchor()
    receipt = anchor_head(path, fake)
    head = _entries(path)[-1]
    assert receipt["anchor"] == "fake"
    assert (receipt["chain_index"], receipt["payload_hash"]) == (1, head["payload_hash"])
    assert fake.statements == [anchor_statement(1, head["payload_hash"])]
    assert read_receipts(anchors_path_for(path)) == [receipt]


def test_anchor_head_skips_an_already_anchored_head(chain):
    path, _ = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    assert anchor_head(path, fake) is None
    assert len(fake.statements) == 1


def test_anchor_head_anchors_again_after_new_entries(chain):
    path, writer = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    writer.append({"n": 2})
    assert anchor_head(path, fake)["chain_index"] == 2
    assert len(read_receipts(anchors_path_for(path))) == 2


def test_anchor_head_on_an_empty_chain_returns_none(tmp_path):
    fake = FakeAnchor()
    assert anchor_head(tmp_path / "chain.jsonl", fake) is None
    assert fake.statements == []


def test_anchor_failure_writes_nothing(chain):
    path, _ = chain
    with pytest.raises(AnchorError):
        anchor_head(path, FakeAnchor(fail=True))
    assert not anchors_path_for(path).exists()


def test_check_anchors_counts_valid_receipts_and_the_unanchored_tail(chain):
    path, writer = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    writer.append({"n": 2})
    writer.append({"n": 3})
    report = check_anchors(_entries(path), read_receipts(anchors_path_for(path)), {"fake": fake})
    assert report.valid == 1
    assert report.failures == []
    assert (report.latest_index, report.latest_time) == (1, "2026-10-07T12:00:00Z")
    assert report.unanchored_tail == 2


def test_check_anchors_detects_a_rewritten_entry(chain):
    path, _ = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    entries = _entries(path)
    entries[1]["payload_hash"] = "ff" * 32  # rewritten after it was anchored
    report = check_anchors(entries, read_receipts(anchors_path_for(path)), {"fake": fake})
    assert report.valid == 0
    assert "does not match the anchored hash" in report.failures[0]


def test_check_anchors_reports_a_missing_entry(chain):
    path, _ = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    report = check_anchors(_entries(path)[:1], read_receipts(anchors_path_for(path)), {"fake": fake})
    assert report.failures == ["receipt 0: chain entry 1 is missing"]


def test_check_anchors_reports_an_unknown_anchor_type(chain):
    path, _ = chain
    anchor_head(path, FakeAnchor())
    report = check_anchors(_entries(path), read_receipts(anchors_path_for(path)), {})
    assert report.failures == ["receipt 0: unknown anchor type 'fake'"]


def test_check_anchors_reports_a_receipt_that_does_not_verify(chain):
    path, _ = chain
    anchor_head(path, FakeAnchor())
    report = check_anchors(
        _entries(path), read_receipts(anchors_path_for(path)), {"fake": FakeAnchor(valid=False)}
    )
    assert report.failures == ["receipt 0: fake says no"]
    assert report.latest_index is None
    assert report.unanchored_tail == 2
