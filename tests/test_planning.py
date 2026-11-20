"""record_plan: every agent has it, plans land in state per agent, and the timeline shows them."""

import asyncio
from pathlib import Path
from types import SimpleNamespace

from triage_agents.agents.log_network import build_log_network_analyst
from triage_agents.agents.static_analysis import build_static_analyst
from triage_agents.agents.supervisor import build_supervisor
from triage_agents.agents.threat_intel import build_threat_intel_analyst
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle
from triage_agents.tools.planning import record_plan

from .fakes import ScriptedLlm, call, calls

ROOT = Path(__file__).resolve().parent.parent
BEACON = AlertBundle.model_validate_json((ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text())


def tool_names(agent):
    return {getattr(t, "name", getattr(t, "__name__", "")) for t in agent.tools}


def test_every_agent_can_record_a_plan_and_uses_no_planner_by_default():
    for agent in (build_static_analyst(), build_log_network_analyst(), build_threat_intel_analyst(),
                  build_supervisor()):
        assert "record_plan" in tool_names(agent), agent.name
        assert agent.planner is None, agent.name


def test_plans_are_stored_per_agent():
    ctx = SimpleNamespace(state={}, agent_name="static_analyst")
    assert record_plan("1. overview 2. imports", ctx)["status"] == "success"
    ctx.agent_name = "log_network_analyst"
    record_plan("1. tree 2. beaconing", ctx)
    assert ctx.state == {"plan_static_analyst": "1. overview 2. imports",
                         "plan_log_network_analyst": "1. tree 2. beaconing"}


def test_plan_shows_in_state_and_timeline_during_a_run():
    findings = {"agent": "static_analyst", "summary": "s", "findings": [], "benign_explanations": [], "gaps": []}
    llm = ScriptedLlm(script=[
        call("record_plan", plan="1. overview 2. imports, sections, strings 3. submit"),
        calls(("get_file_overview", {}), ("analyze_imports", {}), ("analyze_sections", {}), ("analyze_strings", {})),
        call("set_model_response", **findings),
    ])
    result = asyncio.run(run_agent(build_static_analyst(model=llm), BEACON))
    assert result.state["plan_static_analyst"].startswith("1. overview")
    assert "plan:    1. overview 2. imports, sections, strings 3. submit" in result.trace.format_timeline()
