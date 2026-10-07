"""RFC 3161 anchor, tested offline against a recorded IdenTrust receipt."""
from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path

import pytest

from services.decision import rfc3161_anchor
from services.decision.anchors import AnchorError, anchor_statement
from services.decision.rfc3161_anchor import RFC3161Anchor

FIXTURE = Path(__file__).parent.parent / "fixtures" / "rfc3161"


@pytest.fixture(scope="module")
def recorded():
    receipt = json.loads((FIXTURE / "chain.anchors.jsonl").read_text(encoding="utf-8").splitlines()[0])
    statement = anchor_statement(receipt["chain_index"], receipt["payload_hash"])
    return statement, receipt


@pytest.fixture(scope="module")
def tsa():
    return RFC3161Anchor()  # default roots: certifi bundle


def test_recorded_receipt_verifies_with_default_roots(recorded, tsa):
    statement, receipt = recorded
    result = tsa.verify(statement, receipt)
    assert result.ok, result.reason
    assert result.anchored_at == receipt["anchored_at"]
    assert receipt["tsa_url"] == rfc3161_anchor.DEFAULT_TSA_URL


def test_receipt_does_not_cover_another_statement(recorded, tsa):
    statement, receipt = recorded
    result = tsa.verify(statement + b" ", receipt)
    assert not result.ok
    assert result.reason.startswith("timestamp does not verify")


def test_receipt_fails_without_trusted_roots(recorded):
    statement, receipt = recorded
    assert not RFC3161Anchor(roots=[]).verify(statement, receipt).ok


def test_corrupted_token_is_reported_not_raised(recorded, tsa):
    statement, receipt = recorded
    broken = dict(receipt, token=base64.b64encode(b"not a timestamp").decode())
    result = tsa.verify(statement, broken)
    assert not result.ok
    assert result.reason.startswith("timestamp does not verify")


class _FakeHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _serve(body: bytes):
    return lambda request, timeout: _FakeHTTPResponse(body)


def _anchor_ignoring_nonce(monkeypatch) -> RFC3161Anchor:
    """The recorded token carries the nonce of the original request, not of a new one,
    so request() is exercised with nonce checking switched off."""
    tsa = RFC3161Anchor()
    real_verify = tsa.verify
    monkeypatch.setattr(tsa, "verify", lambda s, r, nonce=None: real_verify(s, r))
    return tsa


def test_request_returns_receipt_fields(recorded, monkeypatch):
    statement, receipt = recorded
    monkeypatch.setattr(
        rfc3161_anchor.urllib.request, "urlopen", _serve(base64.b64decode(receipt["token"]))
    )
    fields = _anchor_ignoring_nonce(monkeypatch).request(statement)
    assert fields == {
        "anchored_at": receipt["anchored_at"],
        "tsa_url": rfc3161_anchor.DEFAULT_TSA_URL,
        "token": receipt["token"],
    }


def test_request_wraps_network_errors(monkeypatch):
    def down(request, timeout):
        raise OSError("connection refused")

    monkeypatch.setattr(rfc3161_anchor.urllib.request, "urlopen", down)
    with pytest.raises(AnchorError, match="could not reach"):
        RFC3161Anchor().request(b"statement")


def test_request_refuses_a_timestamp_for_another_statement(recorded, monkeypatch):
    statement, receipt = recorded
    monkeypatch.setattr(
        rfc3161_anchor.urllib.request, "urlopen", _serve(base64.b64decode(receipt["token"]))
    )
    with pytest.raises(AnchorError, match="does not verify"):
        _anchor_ignoring_nonce(monkeypatch).request(statement + b" ")


def test_load_roots_skips_certificates_that_cannot_be_loaded(tmp_path):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now).not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    bundle = tmp_path / "roots.pem"
    bundle.write_bytes(
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        + cert.public_bytes(serialization.Encoding.PEM)
    )
    assert rfc3161_anchor.load_roots([bundle]) == [cert]


def test_default_roots_load_without_warnings():
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        roots = rfc3161_anchor.load_roots()
    assert len(roots) > 100


@pytest.mark.skipif(not os.environ.get("KYVERN_TSA_E2E"), reason="set KYVERN_TSA_E2E=1 to call IdenTrust")
def test_live_identrust_timestamp(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from services.decision.anchors import (
        anchor_head,
        anchors_path_for,
        check_anchors,
        read_receipts,
    )
    from services.decision.chain_writer import ChainWriter

    chain = tmp_path / "chain.jsonl"
    ChainWriter(chain, ed25519.Ed25519PrivateKey.generate()).append({"n": 1})
    receipt = anchor_head(chain, RFC3161Anchor())
    entries = [json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines()]
    report = check_anchors(entries, read_receipts(anchors_path_for(chain)), {"rfc3161": RFC3161Anchor()})
    assert receipt is not None
    assert report.valid == 1
    assert report.failures == []
