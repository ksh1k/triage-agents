"""Deterministic report checker: the part of self-reflection that doesn't need an LLM.

Before the Critic (an LLM) reviews a draft, this code checks facts that can be
verified exactly:

- every claim cites at least one evidence ID, and every cited ID exists in the ledger
- every technique ID exists in ATT&CK v20.1 (revoked IDs come with their replacement)
- every technique's tactic belongs to it in v20.1 (catches stale names like "Defense
  Evasion", which v20 replaced; seen live in step 4)
- every technique cites behavior evidence from Static or Log/Network (SA-/LN-), not
  just its TI- confirmation
- severity isn't obviously out of line with the strongest signal the specialists found

Its issues are handed to the Critic as facts, and the router forces a revision while
any remain (up to the round limit). The Critic adds the judgment calls code can't make,
such as "this claim says more than its evidence does".
"""

from __future__ import annotations

from pydantic import ValidationError

from .analysis.attack import get_index
from .schemas import SEVERITY_ORDER, ReportDraft

BEHAVIOR_PREFIXES = ("SA-", "LN-")
SIGNAL_ORDER = ["benign", "weak", "moderate", "strong"]


def _issue(kind: str, detail: str) -> dict:
    return {"kind": kind, "detail": detail}


def _clip(text: str, limit: int = 90) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def tactic_matches(given: str, tactic_shortnames: list[str], tactic_names: dict[str, str]) -> bool:
    """Accept the short name ("stealth", "command-and-control") or display name ("Command and Control")."""
    g = given.strip().lower()
    return (g.replace(" ", "-") in tactic_shortnames
            or g in {tactic_names.get(t, t).lower() for t in tactic_shortnames})


def strongest_signal(merged: dict | None) -> str | None:
    if not merged:
        return None
    signals = [f.get("signal") for f in (merged.get("key_findings") or []) + (merged.get("history") or [])
               if f.get("signal") in SIGNAL_ORDER]
    return max(signals, key=SIGNAL_ORDER.index) if signals else None


def find_issues(draft: dict | ReportDraft | None, ledger_ids: set[str], *,
                alert_id: str | None = None, merged: dict | None = None) -> list[dict]:
    """Return a list of {"kind", "detail"} problems with the draft (empty list = passes)."""
    if draft is None:
        return [_issue("other", "No draft report was produced.")]
    try:
        d = draft if isinstance(draft, ReportDraft) else ReportDraft.model_validate(draft)
    except ValidationError as exc:
        return [_issue("other", f"Draft does not match the report schema: {_clip(str(exc), 200)}")]

    index = get_index()
    issues: list[dict] = []
    if alert_id and d.alert_id != alert_id:
        issues.append(_issue("other", f"alert_id is {d.alert_id!r} but this alert is {alert_id!r}."))
    if not d.claims:
        issues.append(_issue("other", "The report makes no claims."))
    if not d.recommended_next_steps:
        issues.append(_issue("other", "The report has no recommended next steps."))

    for n, claim in enumerate(d.claims, 1):
        if not claim.evidence_ids:
            issues.append(_issue("uncited_claim", f"Claim {n} cites no evidence: {_clip(claim.text)!r}"))
        unknown = [e for e in claim.evidence_ids if e not in ledger_ids]
        if unknown:
            issues.append(_issue("unknown_evidence_id",
                                 f"Claim {n} cites {', '.join(unknown)}, which are not in the evidence ledger."))

    for t in d.techniques:
        record = index.get(t.technique_id)
        if record is None:
            replacement = index.replacement_for(t.technique_id)
            detail = (f"{t.technique_id} was revoked in ATT&CK v{index.version}; the replacement is {replacement}."
                      if replacement else f"{t.technique_id} does not exist in ATT&CK v{index.version}.")
            issues.append(_issue("invalid_technique_id", detail))
        elif not tactic_matches(t.tactic, record["tactics"], index.tactics):
            names = ", ".join(f"{s} ({index.tactics.get(s, s)})" for s in record["tactics"])
            issues.append(_issue("wrong_tactic", f"{record['id']} '{record['name']}' belongs to {names} in "
                                                 f"ATT&CK v{index.version}, not {t.tactic!r}."))
        unknown = [e for e in t.evidence_ids if e not in ledger_ids]
        if unknown:
            issues.append(_issue("unknown_evidence_id",
                                 f"Technique {t.technique_id} cites {', '.join(unknown)}, which are not in the ledger."))
        if not any(e.startswith(BEHAVIOR_PREFIXES) for e in t.evidence_ids if e in ledger_ids):
            issues.append(_issue("unsupported_technique",
                                 f"Technique {t.technique_id} cites no behavior evidence (SA- or LN-)."))

    strongest = strongest_signal(merged)
    sev = SEVERITY_ORDER.index(d.severity)
    if strongest in ("benign", "weak") and sev >= SEVERITY_ORDER.index("high"):
        issues.append(_issue("severity_mismatch", f"Severity is {d.severity} but the strongest finding signal "
                                                  f"is only {strongest!r}."))
    if strongest == "strong" and sev <= SEVERITY_ORDER.index("low"):
        issues.append(_issue("severity_mismatch", f"Severity is {d.severity} although a specialist reported a "
                                                  "strong signal; explain why or raise it."))
    return issues


def cited_ids(draft: dict | ReportDraft) -> list[str]:
    """Evidence IDs cited anywhere in the draft, in first-seen order."""
    d = draft if isinstance(draft, ReportDraft) else ReportDraft.model_validate(draft)
    ids = [e for c in d.claims for e in c.evidence_ids] + [e for t in d.techniques for e in t.evidence_ids]
    return list(dict.fromkeys(ids))
