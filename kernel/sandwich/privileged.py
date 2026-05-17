"""P-LLM (privileged) orchestrator.

The privileged LLM plans and decides — it never receives raw untrusted content.
Untrusted inputs live in a ReferenceStore accessible only to the Q-LLM caller.
"""
import re
import time
from typing import Any, Callable

from pydantic import BaseModel

from kernel.sandwich.providers import InMemoryAuditStore
from kernel.sandwich.quarantined import QLLMCaller
from kernel.sandwich.references import ReferenceStore
from kernel.sandwich.schemas import (
    SandwichDecision,
    SandwichPlan,
    SandwichToolMisuseError,
    hash_dict,
    hash_text,
)

_TOKENS_PER_CHAR = 4
_REF_RE = re.compile(r"^\$[A-Z_]+_\d+$")


class Sandwich:
    """Dual-LLM Sandwich orchestrator.

    P-LLM (privileged) plans and decides — never sees untrusted content.
    Q-LLM (quarantined) parses untrusted content into typed schemas.
    Every step is logged to audit_store, optionally signed with Ed25519.
    """

    def __init__(
        self,
        privileged_llm: object,
        quarantined_llm: object,
        audit_store: "object | None" = None,
        max_tokens: int = 8000,
        max_schema_retries: int = 2,
    ) -> None:
        self._p_llm = privileged_llm
        self._q_llm = quarantined_llm
        self._store = audit_store if audit_store is not None else InMemoryAuditStore()
        self._max_tokens = max_tokens
        self._max_schema_retries = max_schema_retries

    @property
    def audit_store(self) -> object:
        return self._store

    def _estimated_tokens(self, text: str) -> int:
        return len(text) // _TOKENS_PER_CHAR

    def _p_llm_call(self, messages: list[dict], schema: type[BaseModel]) -> BaseModel:
        prompt_hash = hash_text(str(messages))
        resp = self._p_llm.complete(messages, response_format=schema)
        response_hash = hash_text(str(resp))
        self._store.log("p_llm_call", {
            "prompt_hash": prompt_hash,
            "response_hash": response_hash,
            "schema": schema.__name__,
        })
        if isinstance(resp, schema):
            return resp
        if isinstance(resp, str):
            return schema.model_validate_json(resp)
        if isinstance(resp, dict):
            return schema.model_validate(resp)
        return resp

    def run(
        self,
        task: str,
        untrusted_inputs: dict[str, str],
        output_schema: "type[BaseModel] | None" = None,
        tools: "list[Callable] | None" = None,
    ) -> dict[str, Any]:
        start = time.monotonic()

        # 1. Replace untrusted inputs with symbolic refs
        ref_store = ReferenceStore()
        for value in untrusted_inputs.values():
            ref_store.add(value, "INPUT")

        self._store.log("sandwich_start", {
            "task_hash": hash_text(task),
            "input_refs": list(ref_store.ref_ids()),
            "schema_name": output_schema.__name__ if output_schema else None,
        })

        # 2. Build P-LLM plan messages — metadata only, no values
        metadata = ref_store.metadata_summary()
        p_plan_messages = [
            {"role": "system", "content": (
                "You are a privileged orchestrator. You NEVER see raw untrusted "
                "content — only symbolic references ($INPUT_N) and their metadata. "
                "Plan which Q-LLM calls to make to extract structured information."
            )},
            {"role": "user", "content": (
                f"Task: {task}\n\n"
                f"Symbolic references:\n{metadata}\n\n"
                f"Output schema: {output_schema.__name__ if output_schema else 'none'}\n\n"
                "Return a SandwichPlan specifying Q-LLM calls."
            )},
        ]

        # 3. Check context budget — truncate metadata if needed
        estimated = self._estimated_tokens(str(p_plan_messages))
        if estimated > self._max_tokens:
            limit_chars = self._max_tokens * _TOKENS_PER_CHAR // 2
            truncated = metadata[:limit_chars] + "\n[ref metadata truncated]"
            p_plan_messages[-1]["content"] = p_plan_messages[-1]["content"].replace(
                metadata, truncated
            )
            self._store.log("context_truncated", {
                "original_estimated_tokens": estimated,
                "truncated_estimated_tokens": self._estimated_tokens(
                    str(p_plan_messages)
                ),
            })

        # 4. P-LLM plan call
        plan = self._p_llm_call(p_plan_messages, SandwichPlan)

        # 5. Q-LLM calls — pass raw values, return validated dicts
        q_caller = QLLMCaller(self._q_llm, self._store, self._max_schema_retries)
        q_results: dict[str, Any] = {}
        for instr in plan.q_llm_instructions:
            raw_value = ref_store.get_value(instr.ref_id)
            q_results[instr.ref_id] = q_caller.call(
                ref_id=instr.ref_id,
                content=raw_value,
                extraction_prompt=instr.extraction_prompt,
                schema=output_schema,
            )

        # 6. P-LLM decision call — sees typed Q-LLM output, not raw values
        tool_names = [fn.__name__ for fn in (tools or [])]
        p_decide_messages = [
            {"role": "system", "content": (
                "You are a privileged decision maker. Based on structured data "
                "extracted by Q-LLM, decide which tools to invoke and provide "
                "a final result. Do not use symbolic references in tool arguments."
            )},
            {"role": "user", "content": (
                f"Task: {task}\n\n"
                f"Extracted data:\n{q_results}\n\n"
                f"Available tools: {tool_names}\n\n"
                "Decide on tool invocations and return a SandwichDecision."
            )},
        ]
        decision = self._p_llm_call(p_decide_messages, SandwichDecision)

        # 7. Execute tool calls — block symbolic refs and raw values in args
        tool_map = {fn.__name__: fn for fn in (tools or [])}
        all_raw_values = set(ref_store.all_values())

        for tc in decision.tool_invocations:
            for arg_val in tc.args.values():
                sval = str(arg_val)
                if _REF_RE.match(sval):
                    self._store.log("tool_misuse_blocked", {
                        "tool_name": tc.tool_name,
                        "reason": "symbolic_ref_in_arg",
                        "offending_value": sval,
                    })
                    raise SandwichToolMisuseError(
                        f"Tool arg '{sval}' is a symbolic ref — "
                        "untrusted references cannot flow to tools."
                    )
                if sval in all_raw_values:
                    self._store.log("tool_misuse_blocked", {
                        "tool_name": tc.tool_name,
                        "reason": "raw_value_in_arg",
                    })
                    raise SandwichToolMisuseError(
                        "Tool arg contains raw untrusted input value."
                    )

            self._store.log("tool_call", {
                "tool_name": tc.tool_name,
                "args_hash": hash_dict(tc.args),
            })
            if tc.tool_name in tool_map:
                tool_map[tc.tool_name](**tc.args)

        duration_ms = int((time.monotonic() - start) * 1000)
        result = decision.result or {}
        self._store.log("sandwich_end", {
            "result_hash": hash_dict(result),
            "duration_ms": duration_ms,
        })

        return result
