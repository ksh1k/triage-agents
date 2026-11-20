"""Checklist guard: a specialist can't submit before its core checks ran, and can't loop forever."""

import asyncio
from pathlib import Path

from triage_agents.agents import log_network, static_analysis, threat_intel
from triage_agents.agents.static_analysis import OUTPUT_KEY, build_static_analyst
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle

from .fakes import ScriptedLlm, call, calls, function_responses

ROOT = Path(__file__).resolve().parent.parent
BEACON = AlertBundle.model_validate_json((ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text())
LOADER = AlertBundle.model_validate_json((ROOT / "examples" / "alerts" / "loader_demo_sample.json").read_text())
FINDINGS = {"agent": "static_analyst", "summary": "s", "findings": [], "benign_explanations": [], "gaps": []}


def test_early_submit_is_refused_then_accepted_after_checks():
    llm = ScriptedLlm(script=[
        call("get_file_overview"),
        call("set_model_response", **FINDINGS),  # too early: refused
        calls(("analyze_imports", {}), ("analyze_sections", {}), ("analyze_strings", {})),
        call("set_model_response", **FINDINGS),  # now accepted
    ])
    result = asyncio.run(run_agent(build_static_analyst(model=llm), BEACON))
    refusal = function_responses(llm.requests[2])[-1].response  # latest tool result in the history
    assert refusal["status"] == "error"
    assert "analyze_imports, analyze_sections, analyze_strings" in refusal["error_message"]
    assert result.state[OUTPUT_KEY]["agent"] == "static_analyst"
    statuses = [r["status"] for r in result.trace.records
                if r["kind"] == "tool_result" and r["tool"] == "set_model_response"]
    assert statuses[0] == "error"  # the refusal is visible in the trace


def test_guard_gives_up_after_two_refusals():
    llm = ScriptedLlm(script=[call("set_model_response", **FINDINGS)] * 3)
    result = asyncio.run(run_agent(build_static_analyst(model=llm), BEACON))
    assert len(llm.requests) == 3  # refused twice, accepted the third time
    assert result.ok and result.state[OUTPUT_KEY]["agent"] == "static_analyst"


def test_required_checks_follow_the_alert_contents():
    assert static_analysis.required_checks(LOADER) >= {"parse_sample_binary", "analyze_strings"}
    assert "parse_sample_binary" not in static_analysis.required_checks(BEACON)
    no_file = BEACON.model_copy(update={"file": None})
    assert static_analysis.required_checks(no_file) == {"get_file_overview"}
    assert log_network.required_checks(BEACON) == {"get_activity_overview", "analyze_process_tree",
                                                  "summarize_network", "check_beaconing", "analyze_dns"}
    assert log_network.required_checks(LOADER) == {"get_activity_overview"}  # file-only alert
    assert threat_intel.required_checks(BEACON) == {"get_specialist_findings", "get_alert_indicators"}
