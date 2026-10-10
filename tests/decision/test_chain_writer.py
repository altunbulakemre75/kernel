"""ChainWriter: the only code that appends to the audit chain."""
from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from filelock import FileLock

from services.decision import chain_writer
from services.decision.audit_chain import key_id, verify_chain, verify_decision
from services.decision.chain_writer import AuditWriteError, ChainWriter


@pytest.fixture
def signing_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_first_and_second_entries_link(tmp_path, signing_key):
    chain = tmp_path / "nested" / "chain.jsonl"  # parent directory is created on demand
    writer = ChainWriter(chain, signing_key)
    first = writer.append({"n": 1})
    second = writer.append({"n": 2})
    assert (first["chain_index"], first["prev_hash"]) == (0, None)
    assert (second["chain_index"], second["prev_hash"]) == (1, first["payload_hash"])
    assert _lines(chain) == [first, second]


def test_caller_chain_fields_are_replaced(tmp_path, signing_key):
    signed = ChainWriter(tmp_path / "chain.jsonl", signing_key).append({
        "n": 1, "chain_index": 99, "prev_hash": "ff" * 32,
        "payload_hash": "x", "signature": "y", "key_id": "evil",
    })
    assert (signed["chain_index"], signed["prev_hash"]) == (0, None)
    assert signed["key_id"] == key_id(signing_key.public_key())
    assert verify_decision(signed, signing_key.public_key()) is True


def test_each_append_is_fsynced(tmp_path, signing_key, monkeypatch):
    calls = []
    real_fsync = os.fsync

    def counting_fsync(fd):
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(chain_writer.os, "fsync", counting_fsync)
    writer = ChainWriter(tmp_path / "chain.jsonl", signing_key)
    writer.append({"n": 1})
    writer.append({"n": 2})
    assert len(calls) == 2


def test_corrupt_tail_is_refused_and_file_left_untouched(tmp_path, signing_key):
    chain = tmp_path / "chain.jsonl"
    writer = ChainWriter(chain, signing_key)
    writer.append({"n": 1})
    with open(chain, "ab") as f:
        f.write(b'{"chain_index": 1, "payload_')  # torn write: no newline, no closing brace
    before = chain.read_bytes()
    with pytest.raises(AuditWriteError, match="corrupt"):
        writer.append({"n": 2})
    assert chain.read_bytes() == before


def test_append_times_out_while_another_writer_holds_the_lock(tmp_path, signing_key):
    chain = tmp_path / "chain.jsonl"
    with FileLock(str(chain) + ".lock"):
        with pytest.raises(AuditWriteError):
            ChainWriter(chain, signing_key, lock_timeout_s=0.2).append({"n": 1})
    assert not chain.exists()


def _append_many(chain_path: str, key_pem: bytes, worker: int, count: int) -> None:
    key = serialization.load_pem_private_key(key_pem, password=None)
    writer = ChainWriter(Path(chain_path), key)
    for i in range(count):
        writer.append({"worker": worker, "n": i})


def test_concurrent_processes_keep_one_unbroken_chain(tmp_path, signing_key):
    chain = tmp_path / "chain.jsonl"
    key_pem = signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_append_many, args=(str(chain), key_pem, w, 25)) for w in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=180)
    assert [p.exitcode for p in procs] == [0, 0, 0, 0]
    entries = _lines(chain)
    assert [e["chain_index"] for e in entries] == list(range(100))
    assert verify_chain(entries, signing_key.public_key()) == (True, None)


def test_open_refuses_to_mint_a_key_for_an_existing_chain(tmp_path, isolated_home, signing_key):
    chain = tmp_path / "chain.jsonl"
    ChainWriter(chain, signing_key).append({"n": 1})
    with pytest.raises(AuditWriteError, match="refusing to create a new signing key"):
        ChainWriter.open(chain)
    assert not (isolated_home / ".kyvern" / "keys" / "signing.key").exists()


def test_open_creates_a_key_for_a_new_chain(tmp_path, isolated_home):
    writer = ChainWriter.open(tmp_path / "chain.jsonl")
    assert (isolated_home / ".kyvern" / "keys" / "signing.key").is_file()
    assert writer.append({"n": 1})["chain_index"] == 0


def test_open_without_a_path_uses_the_env_override(tmp_path, monkeypatch):
    target = tmp_path / "env-chain.jsonl"
    monkeypatch.setenv("KYVERN_CHAIN_PATH", str(target))
    ChainWriter.open().append({"n": 1})
    assert len(_lines(target)) == 1


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_a_value_json_cannot_represent_is_refused(tmp_path, signing_key, value):
    """NaN and Infinity would be written as bare NaN/Infinity, which only Python parses."""
    path = tmp_path / "chain.jsonl"
    writer = ChainWriter(path, signing_key)
    writer.append({"n": 0})
    before = path.read_bytes()
    with pytest.raises(AuditWriteError, match="NaN or Infinity"):
        writer.append({"inputs": {"distance_m": value}})
    assert path.read_bytes() == before
