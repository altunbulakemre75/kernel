"""Mock-provider email triage example. No API keys needed."""
from pydantic import BaseModel

from kernel.sandwich import (
    InMemoryAuditStore,
    MockLLMProvider,
    QLLMInstruction,
    Sandwich,
    SandwichDecision,
    SandwichPlan,
)


class EmailSummary(BaseModel):
    subject: str
    urgent: bool
    action_required: str | None = None


def notify_oncall(message: str) -> None:
    print(f"[NOTIFIED ONCALL] {message}")


if __name__ == "__main__":
    plan = SandwichPlan(
        reasoning="Process email via Q-LLM",
        q_llm_instructions=[
            QLLMInstruction(
                ref_id="$INPUT_1",
                extraction_prompt="Extract email subject, urgency, and required action.",
            )
        ],
    )
    decision = SandwichDecision(
        reasoning="Email is urgent — notify oncall",
        tool_invocations=[],
        result={"subject": "Server down", "urgent": True, "action_required": "Page oncall"},
    )
    q_response = EmailSummary(
        subject="Server down", urgent=True, action_required="Page oncall"
    )

    store = InMemoryAuditStore()
    sandwich = Sandwich(
        privileged_llm=MockLLMProvider([plan, decision]),
        quarantined_llm=MockLLMProvider([q_response]),
        audit_store=store,
    )
    result = sandwich.run(
        task="Triage this email and notify oncall if urgent",
        untrusted_inputs={"email": "URGENT: Production server is down!"},
        output_schema=EmailSummary,
        tools=[notify_oncall],
    )
    print("Result:", result)
    print("Audit events:", store.event_types())
