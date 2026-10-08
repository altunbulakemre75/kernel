import json
from datetime import datetime
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
        return _check_evidence_size("payload", v)


def _check_evidence_size(field_name: str, v: dict[str, Any]) -> dict[str, Any]:
    size = len(json.dumps(v, separators=(",", ":")).encode("utf-8"))
    if size > RUNTIME_EVENT_PAYLOAD_MAX_BYTES:
        raise PayloadTooLargeError(
            f"{field_name} exceeds {RUNTIME_EVENT_PAYLOAD_MAX_BYTES} bytes "
            f"(got {size} bytes); use file references or chunking for "
            f"larger evidence."
        )
    return v


class RecordedDecision(BaseModel):
    """A decision made by the user's own system (a robot's safety controller, a
    planner, an operator), recorded into the audit chain by record_decision().

    Unlike a RuntimeEvent ("I observed this"), it is a decision ("I did this"):
    the auditor tools count it as one and check its policy_version_id against
    the policies given with --policy. Field names are domain-neutral; Kyvern's
    own engine decisions (services.decision.schemas.Decision) carry no
    record_type.
    """

    record_type: Literal["decision"] = "decision"

    action: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1, max_length=256)  # who decided; "operator" for a person
    reasoning: str = Field(default="", max_length=2000)
    inputs: dict[str, Any] = Field(default_factory=dict)  # what the decision was based on
    rule_id: str | None = Field(default=None, max_length=256)
    subject_id: str | None = Field(default=None, max_length=256)
    requires_operator_approval: bool = False
    timestamp_iso: str

    # Set by record_decision() from policy_path
    policy_version_id: str | None = None
    policy_path: str | None = None

    # Audit chain fields (filled by chain when signed)
    signature: str | None = None
    prev_hash: str | None = None
    payload_hash: str | None = None
    key_id: str | None = None
    chain_index: int = 0

    @field_validator("inputs")
    @classmethod
    def _validate_inputs_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _check_evidence_size("inputs", v)

    @field_validator("timestamp_iso")
    @classmethod
    def _validate_utc(cls, v: str) -> str:
        try:
            # Python 3.10's fromisoformat does not accept a trailing "Z".
            dt = datetime.fromisoformat(v[:-1] + "+00:00" if v.endswith("Z") else v)
        except ValueError as exc:
            raise ValueError(f"timestamp_iso is not ISO 8601: {v!r}") from exc
        offset = dt.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            raise ValueError(f"timestamp_iso must be in UTC (+00:00 or Z): {v!r}")
        return v
