"""Threat Intel tool wrappers: ATT&CK confirmation, revoked IDs, history, indicators."""

import json
from pathlib import Path
from types import SimpleNamespace

from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.tools import intel_tools as ti
from triage_agents.tools.common import ALERT_KEY

ROOT = Path(__file__).resolve().parent.parent
BEACON = json.loads((ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text(encoding="utf-8"))


def ctx(alert=BEACON, **state):
    return SimpleNamespace(state={ALERT_KEY: alert, **state})


def test_get_technique_confirms_once_and_records_evidence():
    c = ctx()
    first = ti.get_technique("t1218.011", c)
    again = ti.get_technique("T1218.011", c)
    assert first["status"] == "success" and first["name"] == "Rundll32"
    assert first["evidence_id"] == again["evidence_id"] == "TI-1"  # no duplicate evidence
    assert len(EvidenceLedger(c.state).all()) == 1


def test_revoked_and_unknown_ids_are_not_confirmed():
    c = ctx()
    revoked = ti.get_technique("T1562.001", c)
    assert revoked["status"] == "revoked" and revoked["replacement"] == "T1685"
    assert ti.get_technique("T9999", c)["status"] == "not_found"
    assert EvidenceLedger(c.state).all() == []


def test_search_attack_with_and_without_tactic():
    assert ti.search_attack("rundll32")["results"][0]["id"] == "T1218.011"
    persistence = ti.search_attack("scheduled task", tactic="persistence")["results"]
    assert persistence and all("persistence" in r["tactics"] for r in persistence)
    assert ti.search_attack("x", tactic="defense-evasion")["status"] == "error"  # tactic gone in v20


def test_indicators_skip_internal_ips_and_find_dropped_dll():
    found = ti.get_alert_indicators(ctx())["indicators"]
    assert "10.20.4.37" not in found["ip"] and "198.51.100.23" in found["ip"]
    assert "upd.dll" in found["filename"]
    assert "cdn-sync.badupdate.example" in found["domain"]


def test_history_matches_record_evidence_but_misses_do_not():
    c = ctx()
    hit = ti.check_indicator_history("domain", "cdn-sync.badupdate.example", c)
    miss = ti.check_indicator_history("ip", "203.0.113.10", c)
    assert hit["matches"][0]["verdict"] == "true_positive" and hit["evidence_id"] == "TI-1"
    assert miss["match_count"] == 0 and "evidence_id" not in miss
    assert ti.check_indicator_history("hostname", "x", c)["status"] == "error"


def test_technique_and_host_history():
    c = ctx()
    tech = ti.check_technique_history("T1071.001", c)
    assert tech["verdict_counts"]["false_positive"] == 2
    assert ti.check_host_history("WS-FIN-11", c)["alert_count"] == 0  # no past alerts on this host


def test_specialist_findings_read_from_state():
    assert ti.get_specialist_findings(ctx())["status"] == "no_findings"
    lognet = {"agent": "log_network_analyst", "summary": "s", "benign_explanations": [], "gaps": [],
              "findings": [{"description": "beacon", "evidence_ids": ["LN-5"],
                            "technique_hints": ["T1071.001"], "signal": "strong"}]}
    c = ctx(lognet_findings=lognet,
            evidence_LN=[{"id": "LN-5", "source_agent": "log_network_analyst", "tool": "check_beaconing",
                          "summary": "likely_beacon ..."}])
    r = ti.get_specialist_findings(c)
    assert r["technique_hints"] == ["T1071.001"]
    assert r["evidence"] == [{"id": "LN-5", "summary": "likely_beacon ..."}]
    assert list(r["specialist_reports"]) == ["log_network_analyst"]
