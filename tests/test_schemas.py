"""Schemas: valid data parses, bad data is rejected."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from triage_agents.schemas import (
    SEVERITY_ORDER,
    AlertBundle,
    Critique,
    Evidence,
    ReportDraft,
    TriageReport,
)

FIXTURE = Path(__file__).parent / "fixtures" / "minimal_alert.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def make_draft(**overrides) -> dict:
    draft = {
        "alert_id": "TEST-0001",
        "severity": "high",
        "summary": "Word spawned hidden PowerShell that downloaded a payload.",
        "claims": [{"text": "PowerShell ran with an encoded command.", "evidence_ids": ["E1"]}],
        "techniques": [{
            "technique_id": "T1059.001", "name": "PowerShell", "tactic": "execution",
            "evidence_ids": ["E1"], "confidence": "high",
        }],
        "confidence": "medium",
        "recommended_next_steps": ["Isolate WS-TEST-01", "Decode the -enc argument"],
    }
    draft.update(overrides)
    return draft


def test_fixture_alert_parses():
    alert = AlertBundle.model_validate(load_fixture())
    assert alert.alert_id == "TEST-0001"
    assert alert.file is not None and "KERNEL32.dll" in alert.file.imports
    assert len(alert.process_events) == 2
    assert alert.process_events[1].ppid == alert.process_events[0].pid


def test_alert_with_only_required_fields():
    alert = AlertBundle(alert_id="A-1", title="t", source="SIEM")
    assert alert.file is None and alert.process_events == []


def test_unknown_field_is_rejected():
    data = load_fixture()
    data["severty"] = "high"  # typo on purpose
    with pytest.raises(ValidationError):
        AlertBundle.model_validate(data)


def test_port_out_of_range_is_rejected():
    data = load_fixture()
    data["network_connections"][0]["dst_port"] = 70000
    with pytest.raises(ValidationError):
        AlertBundle.model_validate(data)


def test_entropy_above_8_is_rejected():
    data = load_fixture()
    data["file"]["sections"][0]["entropy"] = 9.5  # byte entropy maxes out at 8 bits
    with pytest.raises(ValidationError):
        AlertBundle.model_validate(data)


def test_valid_draft_parses():
    draft = ReportDraft.model_validate(make_draft())
    assert draft.severity == "high"


@pytest.mark.parametrize("bad", ["severe", "HIGH", "5"])
def test_invalid_severity_is_rejected(bad):
    with pytest.raises(ValidationError):
        ReportDraft.model_validate(make_draft(severity=bad))


def test_severity_order_is_low_to_high():
    assert SEVERITY_ORDER.index("informational") < SEVERITY_ORDER.index("critical")
    assert len(SEVERITY_ORDER) == 5


def test_final_report_round_trips_through_json():
    evidence = [Evidence(id="E1", source_agent="log_network_analyst",
                         tool="build_process_tree", summary="powershell.exe -enc child of WINWORD.EXE")]
    report = TriageReport(**make_draft(), evidence=evidence, revision_rounds=1)
    again = TriageReport.model_validate_json(report.model_dump_json())
    assert again == report


def test_critique_verdict_must_be_approve_or_revise():
    Critique(verdict="approve", issues=[])
    with pytest.raises(ValidationError):
        Critique(verdict="maybe", issues=[])
