"""Re-export audit fixtures so tests/mcp/ can use them."""
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from kernel.audit import AuditChainStore

# Re-export tests/audit fixtures
from tests.audit.conftest import (  # noqa: F401
    signing_keypair,
    sample_chain_file,
    tampered_chain_file,
)

# Stable "now" for get_stats window tests: after all day-1 events (14:32–16:32 UTC
# on 2026-05-18) but well before event 3 (2026-05-20T14:32 UTC).  Without this
# freeze, tests that assert on a 24h window would pass or fail depending on the
# UTC hour at which the test suite runs.
_FROZEN_NOW = datetime(2026, 5, 18, 23, 59, 59, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def freeze_tools_now():
    """Patch datetime.now inside kernel.mcp.tools to return _FROZEN_NOW."""
    with patch("kernel.mcp.tools.datetime") as mock_dt:
        mock_dt.now.return_value = _FROZEN_NOW
        mock_dt.fromisoformat.side_effect = datetime.fromisoformat
        yield mock_dt


@pytest.fixture
def store(sample_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    s = AuditChainStore(sample_chain_file, public_key_path=pub_path)
    s.load()
    return s


@pytest.fixture
def store_unverified(sample_chain_file):
    s = AuditChainStore(sample_chain_file, verify_on_query=False)
    s.load()
    return s


@pytest.fixture
def store_tampered(tampered_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    s = AuditChainStore(tampered_chain_file, public_key_path=pub_path)
    s.load()
    return s
