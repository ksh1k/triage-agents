"""The full graph Workflow, offline, with scripted fake models.

Covers the self-reflection loop: approve on the first review, the 2-revision cap,
deterministic issues forcing a revision even when the Critic approves, a Supervisor
that ends without findings being retried once, and the real Supervisor with its
specialists running as a node inside the graph.
"""

import asyncio
import json
from pathlib import Path

from google.adk import Agent

from triage_agents.agents.critic import build_critic
from triage_agents.agents.log_network import build_log_network_analyst
from triage_agents.agents.report_writer import build_report_writer
from triage_agents.agents.static_analysis import build_static_analyst
from triage_agents.agents.supervisor import build_supervisor
from triage_agents.agents.threat_intel import build_threat_intel_analyst
from triage_agents.pipeline import build_pipeline
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle, MergedFindings, TriageReport
from triage_agents.tools.planning import record_plan

from .fakes import ScriptedLlm, call, calls, say, user_texts

ROOT = Path(__file__).resolve().parent.parent
ALERT = AlertBundle.model_validate_json((ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text())


def ev(eid, agent, summary):
    return {"id": eid, "source_agent": agent, "tool": "t", "summary": summary}


SEEDED_EVIDENCE = {
    "evidence_SA": [ev("SA-1", "static_analyst", ".data section entropy 7.71")],
    "evidence_LN": [ev("LN-2", "log_network_analyst", "rundll32 loads upd.dll from AppData"),
                    ev("LN-5", "log_network_analyst", "likely_beacon every 59.5 s to 198.51.100.23")],
    "evidence_TI": [ev("TI-1", "threat_intel_analyst", "confirms T1218.011 Rundll32 (stealth)"),
                    ev("TI-2", "threat_intel_analyst", "confirms T1071.001 Web Protocols")],
}

MERGED = {
    "alert_id": "DEMO-LOGNET-01",
    "delegations": [{"agent": "log_network_analyst", "called": True, "brief": "check beaconing"}],
    "key_findings": [{"description": "60 s beacon", "evidence_ids": ["LN-5"], "signal": "strong"}],
    "techniques": [{"technique_id": "T1218.011", "name": "Rundll32", "tactic": "stealth",
                    "evidence_ids": ["LN-2", "TI-1"], "confidence": "high"}],
    "preliminary_severity": "high", "severity_rationale": "beacon (LN-5)",
}


def draft(tactic="stealth", severity="high"):
    return {
        "alert_id": "DEMO-LOGNET-01", "severity": severity, "confidence": "medium",
        "summary": "A DLL run by rundll32 from AppData beacons to an external host.",
        "claims": [{"text": "rundll32 loaded upd.dll from AppData.", "evidence_ids": ["LN-2"]},
                   {"text": "The host beacons every ~60 s.", "evidence_ids": ["LN-5"]},
                   {"text": "The EDR reported this alert.", "evidence_ids": ["AL-1"]}],
        "techniques": [{"technique_id": "T1218.011", "name": "Rundll32", "tactic": tactic,
                        "evidence_ids": ["LN-2", "TI-1"], "confidence": "high"}],
        "recommended_next_steps": ["Isolate WS-FIN-11", "Block 198.51.100.23", "Collect upd.dll"],
    }


APPROVE = {"verdict": "approve", "issues": []}
REVISE = {"verdict": "revise", "issues": [{"kind": "unsupported_claim", "detail": "Claim 1 overreaches."}]}


def fake_supervisor(script):
    """A Supervisor stand-in that submits merged findings directly (specialists are tested elsewhere)."""
    return Agent(name="supervisor", model=ScriptedLlm(script=script), instruction="merge",
                 tools=[record_plan], output_schema=MergedFindings, output_key="findings")


def run(writer_script, critic_script, supervisor_script=None):
    writer_llm, critic_llm = ScriptedLlm(script=writer_script), ScriptedLlm(script=critic_script)
    supervisor = fake_supervisor(supervisor_script or [call("set_model_response", **MERGED)])
    pipeline = build_pipeline(supervisor=supervisor, report_writer=build_report_writer(writer_llm),
                              critic=build_critic(critic_llm))
    result = asyncio.run(run_agent(pipeline, ALERT, initial_state=SEEDED_EVIDENCE))
    return writer_llm, critic_llm, supervisor.model, result


def test_approved_first_draft_is_finalized_without_revision():
    writer, critic, _, result = run([say(json.dumps(draft()))], [say(json.dumps(APPROVE))])
    assert result.ok, result.error
    report = TriageReport.model_validate(result.state["report"])
    assert report.revision_rounds == 0 and len(writer.requests) == 1 and len(critic.requests) == 1
    # Only evidence the report cites is attached, by code.
    assert {e.id for e in report.evidence} == {"LN-2", "LN-5", "AL-1", "TI-1"}
    assert result.state["final_issues"] == [] and result.state["review_log"][0]["critic_verdict"] == "approve"
    assert result.state["report_without_critic"]["revision_rounds"] == 0


def test_revision_loop_stops_after_two_rounds():
    writer, critic, _, result = run([say(json.dumps(draft()))] * 3, [say(json.dumps(REVISE))] * 3)
    assert result.ok, result.error
    assert len(writer.requests) == 3  # first draft + 2 revisions
    assert len(critic.requests) == 3  # reviews each version; the third verdict can't trigger a 3rd revision
    assert result.state["report"]["revision_rounds"] == 2
    assert [e["critic_verdict"] for e in result.state["review_log"]] == ["revise"] * 3
    routes = [r["route"] for r in result.trace.records if r["kind"] == "route" and r["agent"] == "route_after_critic"]
    assert routes == ["REVISE", "REVISE", "FINAL"]
    # The revision request carries the previous draft and the Critic's issues.
    revision_input = " ".join(user_texts(writer.requests[1]))
    assert "Claim 1 overreaches." in revision_input and "Your previous draft" in revision_input


def test_checker_issues_force_revision_even_if_critic_approves():
    """The step-4 mistake: a stale tactic name. The Critic misses it; the checker doesn't."""
    writer, critic, _, result = run(
        [say(json.dumps(draft(tactic="Defense Evasion"))), say(json.dumps(draft()))],
        [say(json.dumps(APPROVE)), say(json.dumps(APPROVE))])
    assert result.ok, result.error
    assert result.state["check_issues_v0"][0]["kind"] == "wrong_tactic"
    assert result.state["report"]["revision_rounds"] == 1
    assert result.state["final_issues"] == []
    assert "wrong_tactic" in " ".join(user_texts(writer.requests[1]))
    # The eval's "without Critic" baseline keeps the uncorrected first draft.
    assert result.state["report_without_critic"]["techniques"][0]["tactic"] == "Defense Evasion"


def test_supervisor_ending_with_plain_text_is_retried_by_the_node_retry_config():
    """Non-JSON final text fails output validation inside a workflow; RetryConfig reruns the node."""
    writer, critic, sup_llm, result = run(
        [say(json.dumps(draft()))], [say(json.dumps(APPROVE))],
        supervisor_script=[say("I think we are done."), call("set_model_response", **MERGED)])
    assert result.ok, result.error
    assert len(sup_llm.requests) == 2
    assert result.state["report"]["severity"] == "high"


def test_supervisor_ending_with_no_output_is_rerouted_by_check_findings():
    """A reply with only a hidden 'thought' produces no output and no error; check_findings retries."""
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types
    thought_only = LlmResponse(content=types.Content(role="model", parts=[types.Part(text="plan...", thought=True)]))
    writer, critic, sup_llm, result = run(
        [say(json.dumps(draft()))], [say(json.dumps(APPROVE))],
        supervisor_script=[thought_only, call("set_model_response", **MERGED)])
    assert result.ok, result.error
    assert len(sup_llm.requests) == 2
    assert "previous attempt ended without merged findings" in " ".join(user_texts(sup_llm.requests[1]))
    assert result.state["supervisor_attempts"] == 2


def test_trace_shows_checks_and_routes():
    *_, result = run([say(json.dumps(draft(tactic="Defense Evasion"))), say(json.dumps(draft()))],
                     [say(json.dumps(APPROVE)), say(json.dumps(APPROVE))])
    timeline = result.trace.format_timeline()
    assert "[CHECK] check_report: 1 issue(s) (wrong_tactic)" in timeline
    assert "[ROUTE] route_after_critic -> REVISE (revision 1)" in timeline
    assert "[ROUTE] route_after_critic -> FINAL" in timeline


def test_real_supervisor_and_specialists_run_inside_the_graph():
    """The actual Supervisor (with single_turn sub-agents) as a workflow node, end to end."""
    static_llm = ScriptedLlm(script=[
        calls(("record_plan", {"plan": "all checks"}), ("get_file_overview", {}), ("analyze_imports", {}),
              ("analyze_sections", {}), ("analyze_strings", {})),
        call("set_model_response", agent="static_analyst", summary="s", findings=[])])
    lognet_llm = ScriptedLlm(script=[
        calls(("record_plan", {"plan": "all checks"}), ("get_activity_overview", {}), ("analyze_process_tree", {}),
              ("summarize_network", {}), ("check_beaconing", {}), ("analyze_dns", {})),
        call("set_model_response", agent="log_network_analyst", summary="s",
             findings=[{"description": "beacon", "evidence_ids": ["LN-5"], "signal": "strong",
                        "technique_hints": ["T1071.001"]}])])
    intel_llm = ScriptedLlm(script=[
        calls(("record_plan", {"plan": "confirm"}), ("get_specialist_findings", {}), ("get_alert_indicators", {})),
        call("get_technique", technique_id="T1071.001"),
        call("set_model_response", agent="threat_intel_analyst", summary="s")])
    sup_llm = ScriptedLlm(script=[
        calls(("record_plan", {"plan": "static + lognet, then intel"}),
              ("static_analyst", {"request": "check the DLL"}), ("log_network_analyst", {"request": "check logs"})),
        call("threat_intel_analyst", request="confirm techniques"),
        call("set_model_response", **MERGED)])
    supervisor = build_supervisor(model=sup_llm, sub_agents=[
        build_static_analyst(static_llm, as_subagent=True), build_log_network_analyst(lognet_llm, as_subagent=True),
        build_threat_intel_analyst(intel_llm, as_subagent=True)])
    real_draft = draft()
    real_draft["techniques"][0]["evidence_ids"] = ["LN-2", "TI-1"]
    pipeline = build_pipeline(supervisor=supervisor,
                              report_writer=build_report_writer(ScriptedLlm(script=[say(json.dumps(real_draft))])),
                              critic=build_critic(ScriptedLlm(script=[say(json.dumps(APPROVE))])))
    result = asyncio.run(run_agent(pipeline, ALERT))
    assert result.ok, result.error
    assert user_texts(static_llm.requests[0]) == ["check the DLL"]  # delegation works inside the graph
    assert '"connection_count": 36' in " ".join(user_texts(sup_llm.requests[0]))  # intake briefed the Supervisor
    assert result.state["evidence_AL"][0]["id"] == "AL-1"
    assert result.state["report"]["severity"] == "high"
    agents = result.trace.totals()["agents"]
    assert agents[:2] == ["supervisor", "static_analyst"] or "supervisor" in agents
    assert {"report_writer", "critic"} <= set(agents)
