"""Q-LLM (quarantined) caller.

Receives raw untrusted content + a Pydantic schema. Returns validated dict.
Retries up to max_retries when the answer does not fit the schema, logging each
violation. Raises SandwichSchemaError after all retries are exhausted; any other
error (the audit store failing, say) propagates at once.
"""
from pydantic import BaseModel

from kyvern.sandwich.providers import AuditLog, LLMProvider
from kyvern.sandwich.schemas import SandwichSchemaError


class QLLMCaller:
    def __init__(self, llm: LLMProvider, audit_store: AuditLog, max_retries: int = 2) -> None:
        self._llm = llm
        self._audit = audit_store
        self._max_retries = max_retries

    def call(
        self,
        ref_id: str,
        content: str,
        extraction_prompt: str,
        schema: "type[BaseModel] | None",
    ) -> "dict | str":
        messages: list[dict] = [
            {"role": "system", "content": (
                "You are a structured data extractor. "
                "Extract information from the provided content. "
                "Return ONLY valid JSON matching the required schema."
            )},
            {"role": "user", "content": (
                f"Content:\n{content}\n\nTask: {extraction_prompt}"
            )},
        ]
        if schema is None:
            resp = self._llm.complete(messages, response_format=None)
            self._audit.log("q_llm_call", {
                "ref_id": ref_id, "schema_name": None, "attempt": 0,
            })
            return resp if isinstance(resp, str) else str(resp)

        last_exc: ValueError | None = None
        for attempt in range(self._max_retries + 1):
            if last_exc is not None:
                messages.append({"role": "assistant", "content": "[invalid response]"})
                messages.append({
                    "role": "user",
                    "content": f"Validation failed: {last_exc}. Please correct and retry.",
                })

            resp = self._llm.complete(messages, response_format=schema)
            # Only a bad answer is a schema violation and retried. Anything else (the
            # audit store failing, a bug) propagates instead of being logged as one.
            try:
                validated = _validate(resp, schema)
            except ValueError as exc:  # pydantic's ValidationError is a ValueError
                last_exc = exc
                self._audit.log("schema_violation", {
                    "ref_id": ref_id,
                    "schema_name": schema.__name__,
                    "errors": f"{type(exc).__name__}: {exc}",
                    "retry_count": attempt,
                })
                continue

            self._audit.log("q_llm_call", {
                "ref_id": ref_id,
                "schema_name": schema.__name__,
                "attempt": attempt,
            })
            return validated.model_dump()

        self._audit.log("schema_failed", {
            "ref_id": ref_id,
            "schema_name": schema.__name__,
        })
        raise SandwichSchemaError(
            f"Q-LLM failed to produce valid {schema.__name__} after "
            f"{self._max_retries + 1} attempts. Last error: {last_exc}"
        ) from last_exc


def _validate(resp: object, schema: "type[BaseModel]") -> BaseModel:
    """`resp` validated against `schema`; ValueError if it does not fit."""
    if isinstance(resp, BaseModel):  # validated again: model_construct() skips it
        return schema.model_validate(resp.model_dump(warnings=False))
    if isinstance(resp, str):
        return schema.model_validate_json(resp)
    if isinstance(resp, dict):
        return schema.model_validate(resp)
    raise ValueError(f"Unexpected response type: {type(resp).__name__}")
