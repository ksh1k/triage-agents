"""Log/Network tool wrappers on the synthetic beacon alert and the Word-macro fixture."""

import json
from pathlib import Path
from types import SimpleNamespace

from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.tools import lognet_tools as ln
from triage_agents.tools.common import ALERT_KEY

ROOT = Path(__file__).resolve().parent.parent
BEACON = json.loads((ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text(encoding="utf-8"))
MACRO = json.loads((ROOT / "tests" / "fixtures" / "minimal_alert.json").read_text(encoding="utf-8"))


def ctx(alert):
    return SimpleNamespace(state={ALERT_KEY: alert})


def test_overview_counts_and_evidence():
    c = ctx(BEACON)
    r = ln.get_activity_overview(c)
    assert (r["process_event_count"], r["connection_count"], r["dns_query_count"]) == (6, 36, 2)
    assert r["evidence_id"] == "LN-1"


def test_no_logs_means_no_evidence():
    c = ctx({"alert_id": "F", "title": "file only", "source": "AV"})
    assert ln.get_activity_overview(c)["status"] == "no_logs"
    assert ln.analyze_process_tree(c)["status"] == "no_process_events"
    assert ln.check_beaconing(c)["status"] == "no_connections"
    assert ln.analyze_dns(c)["status"] == "no_dns"
    assert EvidenceLedger(c.state).all() == []


def test_process_tree_findings_on_beacon_alert():
    r = ln.analyze_process_tree(ctx(BEACON))
    ids = {f["rule_id"] for f in r["findings"]}
    assert {"rundll32_user_path", "recon_burst"} <= ids
    assert "rundll32.exe (pid 6120)" in r["process_tree"]
    assert all(f["evidence_id"].startswith("LN-") for f in r["findings"])


def test_decoded_powershell_shows_up_in_evidence():
    c = ctx(MACRO)
    ln.analyze_process_tree(c)
    summaries = [e["summary"] for e in EvidenceLedger(c.state).all()]
    assert any("decoded text 'IEX'" in s for s in summaries)
    assert any("Office application" in s and "parent winword.exe" in s for s in summaries)


def test_beaconing_finds_the_implant_not_the_browser():
    r = ln.check_beaconing(ctx(BEACON))
    verdicts = {x["dst_ip"]: x["verdict"] for x in r["results"]}
    assert verdicts == {"198.51.100.23": "likely_beacon", "203.0.113.10": "irregular"}


def test_network_summary_and_dns():
    c = ctx(BEACON)
    summary = ln.summarize_network(c)
    assert summary["external_destination_count"] == 2 and summary["flags"] == []
    assert ln.analyze_dns(c)["findings"] == []


def test_lookup_process_drill_down():
    c = ctx(BEACON)
    r = ln.lookup_process(6120, c)
    assert r["parent"]["image"].endswith("explorer.exe")
    assert [ch["pid"] for ch in r["children"]] == [6400, 6410, 6420]
    assert r["external_destinations"] == ["198.51.100.23:443"]
    assert ln.lookup_process(99999, c)["status"] == "not_found"
