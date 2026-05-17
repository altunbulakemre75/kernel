from dataclasses import dataclass
from typing import Iterator


@dataclass
class _Ref:
    value: str
    ref_type: str

    @property
    def length(self) -> int:
        return len(self.value)


class ReferenceStore:
    """Holds untrusted input values under symbolic keys ($INPUT_1 etc.).

    P-LLM only receives metadata (key, type, length) — never values.
    Q-LLM receives values when explicitly invoked by the orchestrator.
    """

    def __init__(self) -> None:
        self._store: dict[str, _Ref] = {}
        self._counters: dict[str, int] = {}

    def add(self, value: str, ref_type: str = "INPUT") -> str:
        count = self._counters.get(ref_type, 0) + 1
        self._counters[ref_type] = count
        ref_id = f"${ref_type}_{count}"
        self._store[ref_id] = _Ref(value=value, ref_type=ref_type)
        return ref_id

    def get_value(self, ref_id: str) -> str:
        return self._store[ref_id].value

    def all_values(self) -> list[str]:
        return [r.value for r in self._store.values()]

    def ref_ids(self) -> Iterator[str]:
        return iter(self._store.keys())

    def metadata_summary(self) -> str:
        """Returns ref metadata for P-LLM — no values included."""
        return "\n".join(
            f"{ref_id}: type={ref.ref_type}, length={ref.length} chars"
            for ref_id, ref in self._store.items()
        )
