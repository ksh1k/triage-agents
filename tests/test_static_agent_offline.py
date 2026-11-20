"""The Static Analysis agent end to end, offline: a scripted fake model drives the real
ADK loop, the real tools, the evidence ledger and the trace plugin. No API calls."""

import asyncio
import json
from pathlib import Path

from triage_agents.agents.static_analysis import OUTPUT_KEY, build_static_analyst
from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle, SpecialistFindings

from .fakes import ScriptedLlm, call, function_responses

ROOT = Path(__file__).resolve().parent.parent
ALERT = AlertBundle.model_validate_json((ROOT / "examples" / "alerts" / "loader_demo_sample.json").read_text())

FINDINGS = {
    "agent": "static_analyst",
    "summary": "Harmless-looking console program with one planted prompt-injection string.",
    "findings": [
        {"description": "Resolves APIs at runtime", "evidence_ids": ["SA-3"],
         "technique_hints": ["T1027.007"], "signal": "weak"},
        {"description": "Contains text addressed to an AI analyst", "evidence_ids": ["SA-6"],
         "technique_hints": [], "signal": "moderate"},
    ],
    "benign_explanations": ["Plugin loaders resolve APIs dynamically"],
    "gaps": ["No dynamic analysis (by design)"],
}


def scripted_run(planner: str = "plan_react"):
    llm = ScriptedLlm(script=[
        call("get_file_overview"),
        call("parse_sample_binary"),
        call("analyze_imports"),
        call("analyze_sections"),
        call("analyze_strings"),
        call("set_model_response", **FINDINGS),  # ADK's tool for the structured final answer
    ])
    agent = build_static_analyst(model=llm, planner=planner)
    return llm, asyncio.run(run_agent(agent, ALERT))


def test_react_loop_runs_tools_and_feeds_results_back():
    llm, result = scripted_run()
    assert len(llm.requests) == 6
    # Observation step of ReAct: request 2 carries the result of the tool requested in turn 1.
    observed = function_responses(llm.requests[1])
    assert [r.name for r in observed] == ["get_file_overview"]
    assert observed[0].response["evidence_id"] == "SA-1"


def test_structured_output_lands_in_state():
    _, result = scripted_run()
    findings = SpecialistFindings.model_validate(result.state[OUTPUT_KEY])
    assert findings.agent == "static_analyst" and len(findings.findings) == 2


def test_evidence_ledger_persists_in_session_state():
    _, result = scripted_run()
    ids = EvidenceLedger(result.state).ids()
    assert {"SA-1", "SA-2", "SA-3"} <= ids
    assert "temp:static_parsed" not in result.state  # temp: state is discarded after the run


def test_trace_records_the_steps_in_order():
    _, result = scripted_run()
    kinds = [(r["kind"], r.get("tool")) for r in result.trace.records
             if r["kind"] in ("agent_start", "tool_call", "agent_end")]
    assert kinds == [("agent_start", None), ("tool_call", "get_file_overview"),
                     ("tool_call", "parse_sample_binary"), ("tool_call", "analyze_imports"),
                     ("tool_call", "analyze_sections"), ("tool_call", "analyze_strings"),
                     ("tool_call", "set_model_response"),
                     ("agent_end", None)]
    first_result = next(r for r in result.trace.records if r["kind"] == "tool_result")
    assert first_result["evidence_ids"] == ["SA-1"]
    totals = result.trace.totals()
    assert totals["model_calls"] == 6 and totals["input_tokens"] == 600 and totals["tool_calls"] == 6
    timeline = result.trace.format_timeline()
    assert "> static_analyst started" in timeline and "action:  analyze_imports" in timeline


def test_plan_react_planner_adds_reasoning_instructions():
    llm, _ = scripted_run(planner="plan_react")
    system = str(llm.requests[0].config.system_instruction)
    assert "PLANNING" in system  # the planner asked for explicit /*PLANNING*/ sections


def test_trace_jsonl_round_trip(tmp_path):
    _, result = scripted_run()
    path = result.trace.write_jsonl(tmp_path / "trace.jsonl")
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0]["kind"] == "agent_start" and rows[-1]["kind"] == "agent_end"
