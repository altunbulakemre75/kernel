"""A deterministic in-memory Anchor for tests that must not touch the network."""
from __future__ import annotations

import hashlib
from typing import Any

from services.decision.anchors import AnchorError, AnchorResult


class FakeAnchor:
    name = "fake"

    def __init__(self, *args: Any, fail: bool = False, valid: bool = True, **kwargs: Any) -> None:
        self.statements: list[bytes] = []
        self.fail = fail
        self.valid = valid

    def request(self, statement: bytes) -> dict[str, Any]:
        if self.fail:
            raise AnchorError("fake TSA is down")
        self.statements.append(statement)
        return {
            "anchored_at": "2026-10-07T12:00:00Z",
            "tsa_url": "fake://tsa",
            "proof": hashlib.sha256(statement).hexdigest(),
        }

    def verify(self, statement: bytes, receipt: dict[str, Any]) -> AnchorResult:
        if not self.valid:
            return AnchorResult(ok=False, reason="fake says no")
        if receipt.get("proof") != hashlib.sha256(statement).hexdigest():
            return AnchorResult(ok=False, reason="proof does not cover the statement")
        return AnchorResult(ok=True, anchored_at=receipt["anchored_at"])
