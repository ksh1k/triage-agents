"""Shared data shapes (the "contract" between the user, the agents, and the API).

There are three groups:

1. Input: `AlertBundle`, the security alert we are asked to triage.
2. Evidence: `Evidence`, one fact produced by a tool, with an ID like "SA-3".
3. Output:
   - `ReportDraft` is what the Report Writer LLM fills in. It cites evidence IDs
     but never contains the evidence text itself.
   - `TriageReport` is the final report. Code (not the LLM) attaches the real
     evidence records, so the model cannot invent evidence.
   - `Critique` is the Critic's verdict on a draft.

Pydantic checks the *shape* of the data (types, required fields, allowed
values). Checks that need context, like "does evidence SA-7 exist?" or "is
T1055 a real ATT&CK ID?", happen later in the deterministic report checker.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]
SEVERITY_ORDER: list[str] = ["informational", "low", "medium", "high", "critical"]

Confidence = Literal["low", "medium", "high"]


class _Strict(BaseModel):
    # Reject unknown fields, so a typo in an alert file fails loudly.
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- 1. Input


class PESection(_Strict):
    name: str
    virtual_size: int = Field(ge=0)
    raw_size: int = Field(ge=0)
    entropy: float | None = Field(default=None, ge=0.0, le=8.0)
    max_window_entropy: float | None = Field(default=None, ge=0.0, le=8.0)
    executable: bool | None = None
    writable: bool | None = None


class FileMetadata(_Strict):
    """Static metadata about one file. Everything here comes from parsing the
    file, never from running it."""

    file_name: str
    sha256: str | None = None
    md5: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    file_type: str | None = None  # e.g. "PE32+ executable (DLL)"
    compile_timestamp: datetime | None = None
    signed: bool | None = None
    imports: dict[str, list[str]] = Field(default_factory=dict)  # DLL name -> functions
    sections: list[PESection] = Field(default_factory=list)
    strings: list[str] = Field(default_factory=list)
    sample_path: str | None = None  # optional path to a benign binary to parse locally


class ProcessEvent(_Strict):
    timestamp: datetime
    pid: int
    ppid: int
    image: str  # full path of the executable
    command_line: str = ""
    user: str | None = None


class NetworkConnection(_Strict):
    timestamp: datetime
    pid: int | None = None
    src_ip: str
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    bytes_out: int | None = Field(default=None, ge=0)
    bytes_in: int | None = Field(default=None, ge=0)
    domain: str | None = None


class DnsQuery(_Strict):
    timestamp: datetime
    query: str
    response_ips: list[str] = Field(default_factory=list)


class AlertBundle(_Strict):
    """One alert to triage. Any combination of the optional parts may be present."""

    alert_id: str
    title: str
    source: str  # e.g. "EDR", "NDR", "SIEM"
    host: str | None = None
    description: str = ""
    file: FileMetadata | None = None
    process_events: list[ProcessEvent] = Field(default_factory=list)
    network_connections: list[NetworkConnection] = Field(default_factory=list)
    dns_queries: list[DnsQuery] = Field(default_factory=list)


# ---------------------------------------------------------------- 2. Evidence


class Evidence(_Strict):
    """One fact a tool observed, e.g. "section .text has entropy 7.9"."""

    id: str  # "SA-1", "LN-2", "TI-1", ... assigned by the evidence ledger, not by the LLM
    source_agent: str  # which specialist's tool produced it
    tool: str
    summary: str


# ---------------------------------------------------------------- Specialist output


def _to_str_list(value):
    """Accept ["a", "b"] but also [{"technique_id": "T1547.001", "reason": "..."}]: models sometimes
    return objects where a list of strings is expected (seen live for rejected_hints). Objects are
    flattened to "value: value" text instead of failing validation and costing a retry."""
    if not isinstance(value, list):
        return value
    return [item if isinstance(item, str) else
            ": ".join(str(v) for v in item.values()) if isinstance(item, dict) else str(item)
            for item in value]


# Same JSON schema as list[str] (so the model is still asked for strings); just forgiving on input.
StrList = Annotated[list[str], BeforeValidator(_to_str_list)]


class _LlmOut(BaseModel):
    """Base for shapes an LLM fills in. Lenient on purpose: unknown keys are ignored and
    list fields default to empty. In the first live Supervisor run, Threat Intel's first
    answer failed strict validation and ADK had to ask again, which cost an extra call.
    Missing citations are still caught, by the report checker, where they become
    feedback for revision instead of a crash."""

    model_config = ConfigDict(extra="ignore")


class Finding(_LlmOut):
    description: str
    evidence_ids: list[str] = Field(default_factory=list)  # e.g. ["SA-2", "SA-4"]
    technique_hints: list[str] = Field(default_factory=list)  # Threat Intel confirms these
    signal: Literal["benign", "weak", "moderate", "strong"]


class SpecialistFindings(_LlmOut):
    """What each specialist agent hands back to the Supervisor."""

    agent: str
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    benign_explanations: StrList = Field(default_factory=list)  # innocent explanations that fit
    gaps: StrList = Field(default_factory=list)  # what the specialist could not check


class IntelAssessment(_LlmOut):
    """What the Threat Intel specialist hands back: confirmed ATT&CK mappings and history."""

    agent: str
    summary: str
    # Each mapping cites the behavior evidence (SA-/LN-) AND the TI- evidence
    # that confirmed the ID exists in the pinned ATT&CK version.
    techniques: list["TechniqueMapping"] = Field(default_factory=list)
    rejected_hints: StrList = Field(default_factory=list)  # unsupported hints, with reasons
    history: list[Finding] = Field(default_factory=list)  # past-alert matches and their verdicts
    gaps: StrList = Field(default_factory=list)


# ---------------------------------------------------------------- 3. Output


class Claim(_LlmOut):
    text: str
    evidence_ids: list[str] = Field(default_factory=list)  # the checker flags an empty list


class TechniqueMapping(_LlmOut):
    technique_id: str  # e.g. "T1055" or "T1055.012"
    name: str
    tactic: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Confidence


class ReportDraft(_LlmOut):
    """What the Report Writer LLM produces (and the Critic reviews)."""

    alert_id: str
    severity: Severity
    summary: str
    claims: list[Claim] = Field(default_factory=list)
    techniques: list[TechniqueMapping] = Field(default_factory=list)
    confidence: Confidence
    recommended_next_steps: StrList = Field(default_factory=list)


class TriageReport(ReportDraft):
    """The final report: the draft plus the evidence it cites, attached by code."""

    evidence: list[Evidence]
    revision_rounds: int = Field(ge=0)


IntelAssessment.model_rebuild()  # resolve the forward reference to TechniqueMapping


class Delegation(_LlmOut):
    agent: str
    called: bool
    brief: str  # the request sent to the specialist, or why it was skipped


class MergedFindings(_LlmOut):
    """What the Supervisor produces after delegating: the specialists' results merged."""

    alert_id: str
    delegations: list[Delegation] = Field(default_factory=list)
    key_findings: list[Finding] = Field(default_factory=list)  # each cites ledger evidence IDs
    techniques: list[TechniqueMapping] = Field(default_factory=list)  # confirmed by Threat Intel
    history: list[Finding] = Field(default_factory=list)
    conflicts: StrList = Field(default_factory=list)  # where specialists disagree
    preliminary_severity: Severity
    severity_rationale: str


IssueKind = Literal[
    "uncited_claim",          # a claim cites no evidence
    "unknown_evidence_id",    # a citation that isn't in the ledger
    "invalid_technique_id",   # not in ATT&CK v20.1 (or revoked)
    "wrong_tactic",           # tactic doesn't belong to that technique in v20.1
    "unsupported_technique",  # technique cites no behavior evidence (SA-/LN-)
    "unsupported_claim",      # cited evidence doesn't actually say what the claim says
    "severity_mismatch",      # severity doesn't fit the evidence / rubric
    "other",
]


class CriticIssue(_LlmOut):
    kind: IssueKind
    detail: str


class Critique(_LlmOut):
    verdict: Literal["approve", "revise"]
    issues: list[CriticIssue] = Field(default_factory=list)
