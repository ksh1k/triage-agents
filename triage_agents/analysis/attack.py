"""Look up MITRE ATT&CK techniques in the pinned local index (v20.1).

Why a local copy instead of the model's memory? LLMs confidently cite
technique IDs that don't exist or have been renamed or revoked. Every ID the
agents use is checked here, against the exact dataset version we pinned.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

INDEX_PATH = Path(__file__).resolve().parents[2] / "data" / "attack" / "enterprise-attack-v20.1.json"
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_WORD = re.compile(r"[a-z0-9]+")
_STOPWORDS = {"a", "an", "the", "of", "to", "and", "or", "in", "on", "for", "with", "via", "by", "is"}


def _tokens(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in _STOPWORDS]


class AttackIndex:
    def __init__(self, path: Path = INDEX_PATH):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.version: str = data["attack_version"]
        self.tactics: dict[str, str] = data["tactics"]
        self.copyright: list[str] = data["copyright_statements"]
        self._by_id: dict[str, dict] = {t["id"]: t for t in data["techniques"]}
        self._revoked: dict[str, str] = data.get("revoked", {})
        # Pre-tokenize once so search is fast.
        self._name_tokens = {tid: set(_tokens(t["name"])) for tid, t in self._by_id.items()}
        self._desc_tokens = {tid: _tokens(t["description"]) for tid, t in self._by_id.items()}

    def __len__(self) -> int:
        return len(self._by_id)

    @staticmethod
    def normalize_id(technique_id: str) -> str:
        return technique_id.strip().upper()

    def get(self, technique_id: str) -> dict | None:
        """Full record for an ID like 'T1055' or 't1059.001', or None if it doesn't exist."""
        return self._by_id.get(self.normalize_id(technique_id))

    def is_valid(self, technique_id: str) -> bool:
        return self.get(technique_id) is not None

    def replacement_for(self, technique_id: str) -> str | None:
        """If MITRE revoked this ID, the ID that replaced it (e.g. T1562.001 -> T1685)."""
        return self._revoked.get(self.normalize_id(technique_id))

    def validate_ids(self, technique_ids: list[str]) -> dict:
        """Sort IDs into valid, revoked (with replacement), and invalid (never existed / malformed)."""
        valid, invalid, revoked = [], [], {}
        for tid in technique_ids:
            norm = self.normalize_id(tid)
            if self.is_valid(norm):
                valid.append(norm)
            elif replacement := self.replacement_for(norm):
                revoked[norm] = replacement
            else:
                invalid.append(norm)
        return {"valid": valid, "revoked": revoked, "invalid": invalid}

    def search(self, query: str, limit: int = 5, tactic: str | None = None) -> list[dict]:
        """Keyword search over technique names and descriptions.

        Scoring: an exact ID match wins outright. Otherwise each query word
        found in the name scores 5, and each occurrence in the description
        scores 1 (capped at 3 per word), so name matches dominate.
        """
        q = query.strip()
        if TECHNIQUE_ID_RE.match(q.upper()) and self.is_valid(q):
            return [self._summary(self.get(q), score=100.0)]
        words = _tokens(q)
        if not words:
            return []
        scored = []
        for tid, record in self._by_id.items():
            if tactic and tactic not in record["tactics"]:
                continue
            desc = self._desc_tokens[tid]
            score = sum(5 * (w in self._name_tokens[tid]) + min(desc.count(w), 3) for w in words)
            if score:
                scored.append((score, tid))
        scored.sort(key=lambda s: (-s[0], s[1]))
        return [self._summary(self._by_id[tid], score=float(score)) for score, tid in scored[:limit]]

    def _summary(self, record: dict, score: float) -> dict:
        return {
            "id": record["id"], "name": record["name"], "tactics": record["tactics"],
            "parent": record["parent"], "score": score,
            "description": record["description"][:240],
        }


@lru_cache(maxsize=1)
def get_index() -> AttackIndex:
    """Load the index once per process."""
    return AttackIndex()
