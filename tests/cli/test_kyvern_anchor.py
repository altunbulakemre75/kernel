"""kyvern-anchor, run in-process with the TSA replaced by FakeAnchor."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from cli import kyvern_anchor
from services.decision.anchors import anchors_path_for, read_receipts
from services.decision.chain_writer import ChainWriter
from tests.decision.fake_anchor import FakeAnchor


@pytest.fixture
def fake_tsa(monkeypatch):
    def make(fail=False):
        monkeypatch.setattr(kyvern_anchor, "RFC3161Anchor", lambda *a, **k: FakeAnchor(fail=fail))
        monkeypatch.setattr(kyvern_anchor, "load_roots", lambda paths=None: [])
    return make


@pytest.fixture
def chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    ChainWriter(path, ed25519.Ed25519PrivateKey.generate()).append({"n": 0})
    return path


def test_anchors_the_head_then_reports_it_is_already_anchored(chain, fake_tsa, capsys):
    fake_tsa()
    assert kyvern_anchor.main([str(chain)]) == 0
    assert "Anchored chain_index 0 at 2026-10-07T12:00:00Z via fake://tsa" in capsys.readouterr().out
    assert len(read_receipts(anchors_path_for(chain))) == 1

    assert kyvern_anchor.main([str(chain)]) == 0
    assert "Chain head 0 is already anchored" in capsys.readouterr().out
    assert len(read_receipts(anchors_path_for(chain))) == 1


def test_empty_chain_is_not_an_error(tmp_path, fake_tsa, capsys):
    fake_tsa()
    assert kyvern_anchor.main([str(tmp_path / "chain.jsonl")]) == 0
    assert "Nothing to anchor" in capsys.readouterr().out


def test_failure_exits_one(chain, fake_tsa, capsys):
    fake_tsa(fail=True)
    assert kyvern_anchor.main([str(chain)]) == 1
    assert "Anchoring failed: fake TSA is down" in capsys.readouterr().err
    assert not anchors_path_for(chain).exists()


def test_default_chain_comes_from_the_environment(chain, fake_tsa, monkeypatch, capsys):
    fake_tsa()
    monkeypatch.setenv("KYVERN_CHAIN_PATH", str(chain))
    assert kyvern_anchor.main([]) == 0
    assert "Anchored chain_index 0" in capsys.readouterr().out
