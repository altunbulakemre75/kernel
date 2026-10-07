"""RFC 3161 anchor — timestamps from an external Time Stamping Authority (TSA).

The TSA signs the SHA-256 of the anchor statement together with its own time.
Requests and responses use rfc3161-client; the HTTP POST uses the standard
library. Responses are verified against trusted roots at the token's genTime,
so receipts remain verifiable after the TSA certificate expires.
"""
from __future__ import annotations

import base64
import urllib.error
import urllib.request
import warnings
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.utils import CryptographyDeprecationWarning
from rfc3161_client import (
    TimestampRequestBuilder,
    VerificationError,
    VerifierBuilder,
    decode_timestamp_response,
)

from services.decision.anchors import AnchorError, AnchorResult

# IdenTrust's TSA chains to a root in the certifi bundle. DigiCert, Sectigo,
# GlobalSign and Entrust return non-strict DER that rfc3161-client rejects
# (see docs/superpowers/specs/2026-10-07-anchoring-design.md §2.1).
DEFAULT_TSA_URL = "http://timestamp.identrust.com"


_PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
_PEM_END = b"-----END CERTIFICATE-----"


def _load_pem_certificates(data: bytes) -> list[x509.Certificate]:
    """Load each certificate of a PEM bundle on its own and skip the ones cryptography
    rejects. The certifi bundle contains a root with a non-positive serial number,
    which cryptography already warns about and will refuse to load in a future
    release; loading the bundle in one call would then fail for every root."""
    certs = []
    for block in data.split(_PEM_END):
        start = block.find(_PEM_BEGIN)
        if start == -1:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                certs.append(x509.load_pem_x509_certificate(block[start:] + _PEM_END + b"\n"))
        except ValueError:
            continue
    return certs


def load_roots(pem_paths: Iterable[str | Path] | None = None) -> list[x509.Certificate]:
    """Trusted TSA roots from the given PEM files, else from the certifi bundle."""
    paths = list(pem_paths) if pem_paths else [certifi.where()]
    roots: dict[bytes, x509.Certificate] = {}
    for path in paths:
        for cert in _load_pem_certificates(Path(path).read_bytes()):
            roots[cert.fingerprint(hashes.SHA256())] = cert
    return list(roots.values())


def _iso_utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RFC3161Anchor:
    name = "rfc3161"

    def __init__(
        self,
        tsa_url: str = DEFAULT_TSA_URL,
        roots: list[x509.Certificate] | None = None,
        timeout_s: float = 30.0,
    ) -> None:
        self.tsa_url = tsa_url
        self._roots = roots if roots is not None else load_roots()
        self._timeout_s = timeout_s

    def request(self, statement: bytes) -> dict[str, Any]:
        tsq = (
            TimestampRequestBuilder()
            .data(statement)
            .nonce(nonce=True)
            .cert_request(cert_request=True)
            .build()
        )
        http_request = urllib.request.Request(
            self.tsa_url,
            data=tsq.as_bytes(),
            headers={"Content-Type": "application/timestamp-query"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=self._timeout_s) as response:
                body = response.read()
        except OSError as exc:  # URLError, HTTPError, timeouts
            raise AnchorError(f"could not reach {self.tsa_url}: {exc}") from exc

        receipt = {"tsa_url": self.tsa_url, "token": base64.b64encode(body).decode("ascii")}
        result = self.verify(statement, receipt, nonce=tsq.nonce)
        if not result.ok:
            raise AnchorError(
                f"{self.tsa_url} returned a timestamp that does not verify: {result.reason}"
            )
        return {"anchored_at": result.anchored_at, **receipt}

    def verify(
        self, statement: bytes, receipt: dict[str, Any], nonce: int | None = None
    ) -> AnchorResult:
        try:
            response = decode_timestamp_response(base64.b64decode(receipt["token"]))
            verifier = VerifierBuilder(roots=list(self._roots), nonce=nonce).build()
            verifier.verify_message(response, statement)
        except (VerificationError, ValueError, KeyError, TypeError) as exc:
            return AnchorResult(ok=False, reason=f"timestamp does not verify: {exc}")
        return AnchorResult(ok=True, anchored_at=_iso_utc(response.tst_info.gen_time))
