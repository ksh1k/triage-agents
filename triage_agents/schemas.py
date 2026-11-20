"""Shared data shapes (the "contract" between the user, the agents, and the API).

There are three groups:

1. Input: `AlertBundle`, the security alert we are asked to triage.
2. Evidence: `Evidence`, one fact produced by a tool, with an ID like "E3".
3. Output:
   - `ReportDraft` is what the Report Writer LLM fills in. It cites evidence IDs
     but never contains the evidence text itself.
   - `TriageReport` is the final report. Code (not the LLM) attaches the real
     evidence records, so the model cannot invent evidence.
   - `Critique` is the Critic's verdict on a draft.

Pydantic checks the *shape* of the data (types, required fields, allowed
values). Checks that need context, like "does evidence E7 exist?" or "is
T1055 a real ATT&CK ID?", happen later in the deterministic report checker.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

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

    id: str  # "E1", "E2", ... assigned by the evidence ledger, not by the LLM
    source_agent: str  # which specialist's tool produced it
    tool: str
    summary: str


# ---------------------------------------------------------------- 3. Output


class Claim(_Strict):
    text: str
    evidence_ids: list[str]  # must cite at least one existing evidence ID


class TechniqueMapping(_Strict):
    technique_id: str  # e.g. "T1055" or "T1055.012"
    name: str
    tactic: str
    evidence_ids: list[str]
    confidence: Confidence


class ReportDraft(_Strict):
    """What the Report Writer LLM produces (and the Critic reviews)."""

    alert_id: str
    severity: Severity
    summary: str
    claims: list[Claim]
    techniques: list[TechniqueMapping]
    confidence: Confidence
    recommended_next_steps: list[str]


class TriageReport(ReportDraft):
    """The final report: the draft plus the evidence it cites, attached by code."""

    evidence: list[Evidence]
    revision_rounds: int = Field(ge=0)


class CriticIssue(_Strict):
    kind: Literal[
        "uncited_claim",
        "unknown_evidence_id",
        "invalid_technique_id",
        "severity_mismatch",
        "unsupported_technique",
        "other",
    ]
    detail: str


class Critique(_Strict):
    verdict: Literal["approve", "revise"]
    issues: list[CriticIssue]
