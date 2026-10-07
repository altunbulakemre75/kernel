"""Tests for shared.paths — the per-user Kyvern directory and its pre-rename guard."""
import os
from pathlib import Path

import pytest

from services.decision.audit_chain import load_or_create_keypair
from shared.paths import LegacyHomeError, kyvern_home


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    return tmp_path


def test_returns_kyvern_dir_when_nothing_exists(fake_home):
    assert kyvern_home() == fake_home / ".kyvern"
    # The helper only resolves the path; callers create it.
    assert not (fake_home / ".kyvern").exists()


def test_returns_kyvern_dir_when_it_exists(fake_home):
    (fake_home / ".kyvern").mkdir()
    assert kyvern_home() == fake_home / ".kyvern"


def test_prefers_kyvern_dir_when_both_exist(fake_home):
    (fake_home / ".kyvern").mkdir()
    (fake_home / ".kernel").mkdir()
    assert kyvern_home() == fake_home / ".kyvern"


def test_refuses_when_only_legacy_dir_exists(fake_home):
    (fake_home / ".kernel").mkdir()
    with pytest.raises(LegacyHomeError) as exc_info:
        kyvern_home()
    message = str(exc_info.value)
    assert str(fake_home / ".kernel") in message
    assert str(fake_home / ".kyvern") in message


def test_keypair_refuses_legacy_key_and_writes_nothing(fake_home):
    legacy_keys = fake_home / ".kernel" / "keys"
    legacy_keys.mkdir(parents=True)
    (legacy_keys / "signing.key").write_bytes(b"pre-rename key")
    with pytest.raises(LegacyHomeError):
        load_or_create_keypair()
    assert not (fake_home / ".kyvern").exists()


def test_keypair_created_under_kyvern_dir(fake_home):
    load_or_create_keypair()
    assert (fake_home / ".kyvern" / "keys" / "signing.key").is_file()
    assert (fake_home / ".kyvern" / "keys" / "signing.pub").is_file()


def test_suite_runs_with_an_isolated_home(isolated_home):
    assert Path.home() == isolated_home
    assert "KYVERN_CHAIN_PATH" not in os.environ


def test_default_chain_path_lives_in_kyvern_home(isolated_home):
    from shared.paths import default_chain_path

    assert default_chain_path() == isolated_home / ".kyvern" / "chain.jsonl"


def test_default_chain_path_honours_the_env_override(tmp_path, monkeypatch):
    from shared.paths import default_chain_path

    monkeypatch.setenv("KYVERN_CHAIN_PATH", str(tmp_path / "elsewhere.jsonl"))
    assert default_chain_path() == tmp_path / "elsewhere.jsonl"
