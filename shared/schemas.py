import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# Upper bound on the compact-JSON size of RuntimeEvent.payload, so upstream evidence
# cannot bloat the audit chain; larger artifacts should be referenced, not embedded.
RUNTIME_EVENT_PAYLOAD_MAX_BYTES = 64 * 1024  # 64 KB


class PayloadTooLargeError(ValueError):
    """Raised when RuntimeEvent.payload exceeds RUNTIME_EVENT_PAYLOAD_MAX_BYTES.

    Subclass of ValueError so Pydantic wraps it in ValidationError when raised
    inside a field_validator. The original exception type is preserved in the
    error context for test assertions and structured logging.
    """


class RuntimeEvent(BaseModel):
    """Upstream evidence event from external systems (sensor monitors,
    guard middleware, external policy adapters). Signed verbatim into
    the audit chain alongside Decision records."""

    record_type: Literal["runtime_event"] = "runtime_event"

    event_type: str
    source: str
    source_id: str = Field(min_length=1, max_length=256)
    timestamp_iso: str
    payload: dict[str, Any]
    context: dict[str, Any] = Field(default_factory=dict)

    # Audit chain fields (filled by chain when signed)
    signature: str | None = None
    prev_hash: str | None = None
    payload_hash: str | None = None
    key_id: str | None = None
    chain_index: int = 0
    policy_version_id: str | None = None

    @field_validator("payload")
    @classmethod
    def _validate_payload_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        size = len(json.dumps(v, separators=(",", ":")).encode("utf-8"))
        if size > RUNTIME_EVENT_PAYLOAD_MAX_BYTES:
            raise PayloadTooLargeError(
                f"payload exceeds {RUNTIME_EVENT_PAYLOAD_MAX_BYTES} bytes "
                f"(got {size} bytes); use file references or chunking for "
                f"larger evidence."
            )
        return v
