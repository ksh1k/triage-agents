"""Supervisor delegation, offline. Every agent (Supervisor and the three specialists)
gets its own scripted fake model, so these tests check ADK's wiring, not LLM judgment:
briefs reach the specialists, results come back, state is shared, and the
trace shows who did what, nested by delegation."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from triage_agents.agents.log_network import build_log_network_analyst
from triage_agents.agents.static_analysis import build_static_analyst
from triage_agents.agents.supervisor import OUTPUT_KEY, build_supervisor
from triage_agents.agents.threat_intel import build_threat_intel_analyst
from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle, MergedFindings
from triage_agents.tools.supervisor_tools import alert_brief, alert_summary, attach_evidence_ledger

from .fakes import ScriptedLlm, call, calls, function_responses, user_texts

ROOT = Path(__file__).resolve().parent.parent
ALERT_JSON = json.loads((ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text(encoding="utf-8"))
ALERT = AlertBundle.model_validate(ALERT_JSON)


def findings(agent, eid, hint):
    return {"agent": agent, "summary": f"{agent} summary", "benign_explanations": [], "gaps": [],
            "findings": [{"description": f"{agent} finding", "evidence_ids": [eid],
                          "technique_hints": [hint], "signal": "strong"}]}


INTEL = {"agent": "threat_intel_analyst", "summary": "intel summary", "rejected_hints": [], "gaps": [],
         "techniques": [{"technique_id": "T1218.011", "name": "Rundll32", "tactic": "stealth",
                         "evidence_ids": ["LN-2", "TI-1"], "confidence": "high"}],
         "history": []}

MERGED = {
    "alert_id": "DEMO-LOGNET-01",
    "delegations": [
        {"agent": "static_analyst", "called": True, "brief": "Check upd.dll imports and sections."},
        {"agent": "log_network_analyst", "called": True, "brief": "Check rundll32 tree and beaconing."},
        {"agent": "threat_intel_analyst", "called": True, "brief": "Map findings to ATT&CK, check history."},
    ],
    "key_findings": [{"description": "rundll32 runs a DLL from AppData", "evidence_ids": ["LN-2"],
                      "technique_hints": ["T1218.011"], "signal": "strong"}],
    "techniques": INTEL["techniques"], "history": [], "conflicts": [],
    "preliminary_severity": "high", "severity_rationale": "LOLBin from user folder (LN-2).",
}


def build_team():
    static_llm = ScriptedLlm(script=[calls(("get_file_overview", {}), ("analyze_imports", {}),
                                           ("analyze_sections", {}), ("analyze_strings", {})),
                                     call("set_model_response", **findings("static_analyst", "SA-1", "T1027.007"))])
    lognet_llm = ScriptedLlm(script=[call("get_activity_overview"),
                                     calls(("analyze_process_tree", {}), ("summarize_network", {}),
                                           ("check_beaconing", {}), ("analyze_dns", {})),
                                     call("set_model_response", **findings("log_network_analyst", "LN-2", "T1218.011"))])
    intel_llm = ScriptedLlm(script=[calls(("get_specialist_findings", {}), ("get_alert_indicators", {})),
                                    call("get_technique", technique_id="T1218.011"),
                                    call("set_model_response", **INTEL)])
    sup_llm = ScriptedLlm(script=[  # three turns: plan + delegate, delegate intel, submit
        calls(("record_plan", {"plan": "1. static + lognet in parallel 2. intel 3. merge"}),
              ("static_analyst", {"request": "Check upd.dll imports and sections."}),
              ("log_network_analyst", {"request": "Check rundll32 tree and beaconing."})),
        call("threat_intel_analyst", request="Map findings to ATT&CK, check history."),
        call("set_model_response", **MERGED),
    ])
    supervisor = build_supervisor(model=sup_llm, sub_agents=[
        build_static_analyst(static_llm, as_subagent=True),
        build_log_network_analyst(lognet_llm, as_subagent=True),
        build_threat_intel_analyst(intel_llm, as_subagent=True),
    ])
    return SimpleNamespace(sup=sup_llm, static=static_llm, lognet=lognet_llm, intel=intel_llm, agent=supervisor)


def run_team():
    team = build_team()
    return team, asyncio.run(run_agent(team.agent, ALERT, prompt=alert_brief(ALERT)))


def test_supervisor_gets_one_delegation_tool_per_specialist():
    names = {getattr(t, "name", getattr(t, "__name__", "")) for t in build_team().agent.tools}
    assert names == {"record_plan", "static_analyst", "log_network_analyst", "threat_intel_analyst"}


def test_briefs_reach_the_specialists():
    team, _ = run_team()
    assert user_texts(team.static.requests[0]) == ["Check upd.dll imports and sections."]
    assert user_texts(team.lognet.requests[0]) == ["Check rundll32 tree and beaconing."]
    assert user_texts(team.intel.requests[0]) == ["Map findings to ATT&CK, check history."]


def test_specialist_results_come_back_to_the_supervisor():
    team, _ = run_team()
    returned = {r.name: r.response for r in function_responses(team.sup.requests[1])}
    assert returned["static_analyst"]["agent"] == "static_analyst"
    assert returned["log_network_analyst"]["findings"][0]["evidence_ids"] == ["LN-2"]
    # The evidence ledger rides along with the results (no separate model call needed).
    ledger_ids = {e["id"] for e in returned["log_network_analyst"]["evidence_ledger_so_far"]}
    assert {"SA-1", "LN-1", "LN-2"} <= ledger_ids


def test_supervisor_takes_three_turns_and_gets_the_summary_as_input():
    team, _ = run_team()
    assert len(team.sup.requests) == 3
    first_input = " ".join(user_texts(team.sup.requests[0]))
    assert '"connection_count": 36' in first_input and "UNTRUSTED DATA" in first_input


def test_intel_reads_the_other_specialists_from_shared_state():
    team, _ = run_team()
    seen = function_responses(team.intel.requests[1])[0].response
    assert set(seen["specialist_reports"]) == {"static_analyst", "log_network_analyst"}
    assert seen["technique_hints"] == ["T1027.007", "T1218.011"]


def test_merged_findings_and_full_ledger_in_state():
    _, result = run_team()
    merged = MergedFindings.model_validate(result.state[OUTPUT_KEY])
    assert merged.preliminary_severity == "high" and len(merged.delegations) == 3
    ids = EvidenceLedger(result.state).ids()
    assert {"SA-1", "LN-1", "LN-2", "TI-1"} <= ids
    assert {"static_findings", "lognet_findings", "intel_findings"} <= set(result.state)


def test_trace_shows_delegation_nesting():
    _, result = run_team()
    timeline = result.trace.format_timeline()
    sup_line = timeline.index("> supervisor started")
    for name in ("static_analyst", "log_network_analyst", "threat_intel_analyst"):
        line = next(l for l in timeline.splitlines() if f"> {name} started" in l)
        assert line.index(">") > timeline.splitlines()[0].index(">")  # indented under the supervisor
        assert timeline.index(f"> {name} started") > sup_line
    assert "[TOOL] threat_intel_analyst: returned findings" in timeline
    assert result.trace.totals()["agents"][0] == "supervisor"


def test_failed_specialist_does_not_crash_the_run():
    """If a specialist blows up, ADK hands the Supervisor an error string instead of crashing."""
    broken = ScriptedLlm(script=[])  # runs out of steps on its first call
    sup_llm = ScriptedLlm(script=[
        call("static_analyst", request="Check the file."),
        call("set_model_response", **{**MERGED, "delegations": MERGED["delegations"][:1]}),
    ])
    supervisor = build_supervisor(model=sup_llm, sub_agents=[build_static_analyst(broken, as_subagent=True)])
    result = asyncio.run(run_agent(supervisor, ALERT))
    returned = function_responses(sup_llm.requests[1])[0].response
    assert "Error running sub-agent" in json.dumps(returned)
    assert OUTPUT_KEY in result.state
    assert any(r["kind"] == "tool_result" and r["status"] == "error" for r in result.trace.records)


def test_alert_summary_and_ledger_attachment():
    summary = alert_summary(ALERT)
    assert summary["file"]["has_sample_binary"] is False
    assert (summary["process_event_count"], summary["connection_count"]) == (6, 36)
    assert alert_summary(ALERT.model_copy(update={"file": None}))["file"] is None
    ctx = SimpleNamespace(state={"evidence_SA": [{"id": "SA-1", "source_agent": "static_analyst",
                                                  "tool": "t", "summary": "s"}]})
    tool = SimpleNamespace(name="static_analyst")
    patched = attach_evidence_ledger(tool, {}, ctx, {"agent": "static_analyst"})
    assert patched["evidence_ledger_so_far"] == [{"id": "SA-1", "summary": "s"}]
    assert attach_evidence_ledger(SimpleNamespace(name="record_plan"), {}, ctx, {"status": "success"}) is None
