from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel


@runtime_checkable
class LLMProvider(Protocol):
    def complete(
        self,
        messages: list[dict],
        response_format: type[BaseModel] | None = None,
    ) -> "str | BaseModel": ...


class MockLLMProvider:
    """Deterministic mock: returns pre-configured responses in sequence.

    Records all calls in self.calls for assertion in tests.
    """

    def __init__(self, responses: "list[str | BaseModel]") -> None:
        self._responses = list(responses)
        self._index = 0
        self.calls: list[list[dict]] = []

    def complete(
        self,
        messages: list[dict],
        response_format: "type[BaseModel] | None" = None,
    ) -> "str | BaseModel":
        self.calls.append(messages)
        if self._index >= len(self._responses):
            raise RuntimeError(
                f"MockLLMProvider exhausted after {len(self._responses)} calls"
            )
        resp = self._responses[self._index]
        self._index += 1
        return resp


class InMemoryAuditStore:
    """Append-only audit event log. Signs events with Ed25519 when signing_key provided."""

    def __init__(self, signing_key: Any = None) -> None:
        self.events: list[dict] = []
        self._signing_key = signing_key
        self._prev_hash: "str | None" = None

    def log(self, event_type: str, data: dict) -> dict:
        from services.decision.audit_chain import sign_decision

        event: dict[str, Any] = {
            "event_type": event_type,
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "chain_index": len(self.events),
            **data,
        }
        if self._signing_key is not None:
            signed = sign_decision(
                event, prev_hash=self._prev_hash, signing_key=self._signing_key
            )
            self.events.append(signed)
            self._prev_hash = signed["payload_hash"]
        else:
            self.events.append(event)
        return self.events[-1]

    def verify(self, public_key: Any) -> "tuple[bool, int | None]":
        from services.decision.audit_chain import verify_chain

        if self._signing_key is None:
            return True, None
        return verify_chain(self.events, public_key)

    def event_types(self) -> list[str]:
        return [e["event_type"] for e in self.events]
