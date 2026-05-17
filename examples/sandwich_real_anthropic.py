"""Real Anthropic API example. Requires ANTHROPIC_API_KEY env var."""
import os

from pydantic import BaseModel

from kernel.sandwich import InMemoryAuditStore, Sandwich


class EmailSummary(BaseModel):
    subject: str
    urgent: bool


class AnthropicProvider:
    def __init__(self, model: str = "claude-haiku-4-5-20251001") -> None:
        import anthropic
        self._client = anthropic.Anthropic()
        self._model = model

    def complete(self, messages, response_format=None):
        import anthropic
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        user_msgs = [m for m in messages if m["role"] != "system"]
        resp = self._client.messages.create(
            model=self._model, max_tokens=1024,
            system=system, messages=user_msgs,
        )
        text = resp.content[0].text
        if response_format is not None:
            return response_format.model_validate_json(text)
        return text


if __name__ == "__main__":
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("Set ANTHROPIC_API_KEY first")

    provider = AnthropicProvider()
    store = InMemoryAuditStore()
    sandwich = Sandwich(
        privileged_llm=provider,
        quarantined_llm=provider,
        audit_store=store,
    )
    result = sandwich.run(
        task="Summarize and flag if urgent",
        untrusted_inputs={"email": "Hi team, the deploy is failing. Please fix ASAP!"},
        output_schema=EmailSummary,
    )
    print("Result:", result)
    print("Events:", store.event_types())
