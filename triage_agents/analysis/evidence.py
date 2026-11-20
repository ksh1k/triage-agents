"""Evidence ledger: every fact a tool observes gets a stable ID the report can cite.

IDs look like "SA-3" (Static Analysis), "LN-1" (Log/Network), "TI-2"
(Threat Intel). They are assigned by code, not by the LLM, so a report claim
can only cite evidence that a tool actually produced. The deterministic
report checker (step 6) rejects citations that aren't in the ledger.

Storage: the ledger lives in a dict-like `state`. That's a plain dict in tests
and ADK session state in the app. Each agent writes only its own key
(evidence_SA, evidence_LN, ...), so specialists running in parallel never
overwrite each other's entries.
"""

from __future__ import annotations

from typing import Any, Protocol

AGENT_PREFIXES: dict[str, str] = {
    "static_analyst": "SA",
    "log_network_analyst": "LN",
    "threat_intel_analyst": "TI",
}
KEY_PREFIX = "evidence_"
MAX_SUMMARY_CHARS = 500


class StateLike(Protocol):
    def get(self, key: str, default: Any = None) -> Any: ...
    def __setitem__(self, key: str, value: Any) -> None: ...


class EvidenceLedger:
    def __init__(self, state: StateLike):
        self.state = state

    @staticmethod
    def _key(prefix: str) -> str:
        return f"{KEY_PREFIX}{prefix}"

    def add(self, agent: str, tool: str, summary: str) -> str:
        """Record one observation and return its new ID."""
        prefix = AGENT_PREFIXES.get(agent)
        if prefix is None:
            raise ValueError(f"unknown agent {agent!r}; expected one of {sorted(AGENT_PREFIXES)}")
        key = self._key(prefix)
        # Copy, append, then assign the whole list back. ADK records state
        # changes when a key is *assigned*, so mutating the list in place
        # would be silently lost.
        items = list(self.state.get(key, []) or [])
        evidence_id = f"{prefix}-{len(items) + 1}"
        items.append({"id": evidence_id, "source_agent": agent, "tool": tool,
                      "summary": summary[:MAX_SUMMARY_CHARS]})
        self.state[key] = items
        return evidence_id

    def all(self) -> list[dict]:
        """All evidence, grouped by agent in a fixed order."""
        return [item for prefix in AGENT_PREFIXES.values()
                for item in (self.state.get(self._key(prefix), []) or [])]

    def get(self, evidence_id: str) -> dict | None:
        return next((e for e in self.all() if e["id"] == evidence_id), None)

    def ids(self) -> set[str]:
        return {e["id"] for e in self.all()}

    def exists(self, evidence_id: str) -> bool:
        return evidence_id in self.ids()
