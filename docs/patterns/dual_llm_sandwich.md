# Dual-LLM Sandwich Pattern

## What and why

Simon Willison's Dual-LLM Sandwich isolates untrusted content from the
privileged execution context. kernel extends the pattern with mandatory
Ed25519 signing of every step.

**Threat model priority:** prompt injection > tool misuse > data exfiltration.

## Architecture

```
Untrusted input → ReferenceStore ($INPUT_1)
                       │
                  P-LLM plan           ← sees ONLY $INPUT_1 key + metadata
                       │
              Q-LLM extraction call    ← receives raw value + schema
                       │
             Pydantic-validated dict   ← typed fields only
                       │
               P-LLM decide           ← sees typed dict, not raw value
                       │
              Tool call (validated)    ← args must come from validated dict
```

## Why this, not naive LLM-with-tools

| Approach | Prompt injection risk | Tool misuse risk |
|---|---|---|
| Single LLM with tools | HIGH — injection in user input can hijack tool calls | HIGH |
| Dual-LLM Sandwich | LOW — P-LLM never sees raw content | LOW — tool args validated |
| kernel Sandwich | LOW | LOW + every step audited + Ed25519 signed |

## Key invariants

1. **P-LLM isolation:** `ReferenceStore.metadata_summary()` never returns values.
2. **Schema enforcement:** Q-LLM output must pass Pydantic validation; retried ≤2 times.
3. **Tool arg safety:** any arg matching a symbolic ref or raw value raises `SandwichToolMisuseError`.
4. **Audit completeness:** every `sandwich_start`, `p_llm_call`, `q_llm_call`, `schema_violation`, `tool_call`, `sandwich_end` is signed with Ed25519 and chained with SHA-256.

## Quick start

```python
from pydantic import BaseModel
from kernel.sandwich import Sandwich, MockLLMProvider, InMemoryAuditStore

class EmailSummary(BaseModel):
    subject: str
    urgent: bool

store = InMemoryAuditStore()
sandwich = Sandwich(
    privileged_llm=MockLLMProvider([plan, decision]),
    quarantined_llm=MockLLMProvider([q_response]),
    audit_store=store,
)
result = sandwich.run(
    task="Summarize this email",
    untrusted_inputs={"email": raw_email_content},
    output_schema=EmailSummary,
)
```

See [`examples/sandwich_email_triage.py`](../../examples/sandwich_email_triage.py) for a complete mock example
and [`examples/sandwich_real_anthropic.py`](../../examples/sandwich_real_anthropic.py) for real API usage.
