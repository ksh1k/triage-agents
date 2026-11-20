"""Deterministic report checker: each rule fires on a crafted bad draft and stays quiet on a good one."""

import pytest

from triage_agents.report_check import cited_ids, find_issues, strongest_signal, tactic_matches

LEDGER = {"AL-1", "SA-1", "LN-2", "LN-5", "TI-1", "TI-2"}


def draft(**overrides):
    d = {
        "alert_id": "A-1", "severity": "high", "confidence": "medium",
        "summary": "rundll32 runs a DLL from AppData that beacons to a known C2.",
        "claims": [{"text": "rundll32 loaded a DLL from AppData.", "evidence_ids": ["LN-2"]},
                   {"text": "The host beacons every ~60 s.", "evidence_ids": ["LN-5"]}],
        "techniques": [{"technique_id": "T1218.011", "name": "Rundll32", "tactic": "stealth",
                        "evidence_ids": ["LN-2", "TI-1"], "confidence": "high"},
                       {"technique_id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control",
                        "evidence_ids": ["LN-5", "TI-2"], "confidence": "high"}],
        "recommended_next_steps": ["Isolate the host", "Block 198.51.100.23"],
    }
    d.update(overrides)
    return d


def kinds(issues):
    return [i["kind"] for i in issues]


def test_good_draft_passes():
    assert find_issues(draft(), LEDGER, alert_id="A-1") == []


def test_uncited_and_unknown_evidence():
    bad = draft(claims=[{"text": "The file sits in Downloads.", "evidence_ids": []},
                        {"text": "It beacons.", "evidence_ids": ["LN-9"]}])
    assert kinds(find_issues(bad, LEDGER)) == ["uncited_claim", "unknown_evidence_id"]


def test_stale_tactic_name_is_caught():
    """The exact mistake from step 4: 'Defense Evasion' no longer exists in ATT&CK v20."""
    bad = draft(techniques=[{"technique_id": "T1218.011", "name": "Rundll32", "tactic": "Defense Evasion",
                             "evidence_ids": ["LN-2", "TI-1"], "confidence": "high"}])
    [issue] = find_issues(bad, LEDGER)
    assert issue["kind"] == "wrong_tactic" and "stealth" in issue["detail"]


@pytest.mark.parametrize("tid,expected", [("T1562.001", "replacement is T1685"), ("T9999", "does not exist")])
def test_revoked_and_fake_technique_ids(tid, expected):
    bad = draft(techniques=[{"technique_id": tid, "name": "x", "tactic": "stealth",
                             "evidence_ids": ["LN-2"], "confidence": "low"}])
    [issue] = find_issues(bad, LEDGER)
    assert issue["kind"] == "invalid_technique_id" and expected in issue["detail"]


def test_technique_needs_behavior_evidence_not_just_confirmation():
    bad = draft(techniques=[{"technique_id": "T1218.011", "name": "Rundll32", "tactic": "stealth",
                             "evidence_ids": ["TI-1"], "confidence": "high"}])
    assert kinds(find_issues(bad, LEDGER)) == ["unsupported_technique"]


def test_severity_sanity_against_strongest_signal():
    weak = {"key_findings": [{"description": "unsigned", "signal": "weak"}], "history": []}
    strong = {"key_findings": [{"description": "beacon", "signal": "strong"}], "history": []}
    assert kinds(find_issues(draft(severity="critical"), LEDGER, merged=weak)) == ["severity_mismatch"]
    assert kinds(find_issues(draft(severity="low"), LEDGER, merged=strong)) == ["severity_mismatch"]
    assert find_issues(draft(severity="high"), LEDGER, merged=strong) == []
    assert strongest_signal(None) is None


def test_missing_or_malformed_draft():
    assert kinds(find_issues(None, LEDGER)) == ["other"]
    assert "schema" in find_issues({"alert_id": "A-1"}, LEDGER)[0]["detail"]
    assert "alert_id" in find_issues(draft(), LEDGER, alert_id="B-2")[0]["detail"]


def test_tactic_matching_and_cited_ids():
    names = {"command-and-control": "Command and Control", "stealth": "Stealth"}
    assert tactic_matches("Command and Control", ["command-and-control"], names)
    assert tactic_matches("command-and-control", ["command-and-control"], names)
    assert not tactic_matches("Defense Evasion", ["stealth"], names)
    assert cited_ids(draft()) == ["LN-2", "LN-5", "TI-1", "TI-2"]
