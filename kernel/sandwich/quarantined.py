"""Q-LLM (quarantined) caller.

Receives raw untrusted content + a Pydantic schema. Returns validated dict.
Retries up to max_retries on ValidationError, logging each violation.
Raises SandwichSchemaError after all retries exhausted.
"""
from pydantic import BaseModel, ValidationError

from kernel.sandwich.schemas import SandwichSchemaError


class QLLMCaller:
    def __init__(self, llm: object, audit_store: object, max_retries: int = 2) -> None:
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
        last_error: "str | None" = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0 and last_error:
                messages.append({"role": "assistant", "content": "[invalid response]"})
                messages.append({
                    "role": "user",
                    "content": f"Validation failed: {last_error}. Please correct and retry.",
                })

            resp = self._llm.complete(messages, response_format=schema)

            if schema is None:
                self._audit.log("q_llm_call", {
                    "ref_id": ref_id, "schema_name": None, "attempt": attempt,
                })
                return resp if isinstance(resp, str) else str(resp)

            try:
                if isinstance(resp, BaseModel):
                    validated = resp
                elif isinstance(resp, str):
                    validated = schema.model_validate_json(resp)
                elif isinstance(resp, dict):
                    validated = schema.model_validate(resp)
                else:
                    raise ValueError(f"Unexpected response type: {type(resp)}")

                self._audit.log("q_llm_call", {
                    "ref_id": ref_id,
                    "schema_name": schema.__name__,
                    "attempt": attempt,
                })
                return validated.model_dump()

            except (ValidationError, ValueError, Exception) as exc:
                last_error = str(exc)
                self._audit.log("schema_violation", {
                    "ref_id": ref_id,
                    "schema_name": schema.__name__,
                    "errors": last_error,
                    "retry_count": attempt,
                })

        self._audit.log("schema_failed", {
            "ref_id": ref_id,
            "schema_name": schema.__name__ if schema else None,
        })
        raise SandwichSchemaError(
            f"Q-LLM failed to produce valid {schema.__name__} after "
            f"{self._max_retries + 1} attempts. Last error: {last_error}"
        )
