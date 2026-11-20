"""Shared builder for the specialist agents (Static, Log/Network, Threat Intel).

All three follow the same ReAct recipe: tools + a planner + a structured
final answer saved to session state. Only the name, instructions, tools and
output schema differ.
"""

from __future__ import annotations

from typing import Callable

from google.adk import Agent
from google.adk.models.base_llm import BaseLlm
from google.adk.planners import BasePlanner, BuiltInPlanner, PlanReActPlanner
from google.genai import types
from pydantic import BaseModel

from ..models import make_model
from ..schemas import AlertBundle
from ..tools.common import load_alert
from ..tools.planning import record_plan


DEFAULT_PLANNER = "none"


def make_planner(kind: str) -> BasePlanner | None:
    """'none' (default; reasoning goes through the record_plan tool), 'plan_react', or 'builtin'.

    History, all measured live on gemini-3.5-flash-lite on 2026-11-19/20:
    - builtin: Flash-Lite ignores thinking settings (0 thinking tokens), so nothing is visible.
    - plan_react: visible /*PLANNING*/ text, but a plan-only reply ends the agent early
      (2 of ~12 agent runs). Kept available for comparison.
    - none + record_plan tool: the plan is a tool call, visible in the trace, with no early stops.
    """
    if kind == "plan_react":
        return PlanReActPlanner()
    if kind == "builtin":
        return BuiltInPlanner(thinking_config=types.ThinkingConfig(include_thoughts=True))
    if kind == "none":
        return None
    raise ValueError(f"unknown planner {kind!r}")


# Appended to every specialist's instructions. Added after the first live Supervisor
# run (2026-11-20), where specialists briefed by the Supervisor skipped most of
# their checks, one ended with plain text instead of its structured result, and
# one made four lookups one at a time.
TEAM_RULES = """Working as part of the team:
- Call record_plan with a short numbered plan in the SAME turn as your first tool calls.
- Make independent tool calls together in one turn. Each extra turn costs time and quota, so most
  of your work should take two or three turns.
- The request you receive may focus on one aspect. Still run your standard checks, then look
  deeper where the request points.
- Your final step must be a call to set_model_response with your structured result. Never finish
  with a plain-text answer."""


MAX_GUARD_REFUSALS = 2


def make_checklist_guard(agent_name: str, required_tools: Callable[[AlertBundle], set[str]]):
    """A before_tool_callback that enforces minimum coverage.

    It records every tool the agent calls, and refuses the final
    set_model_response until the core checks for this alert's data have
    run. The refusal returns an error dict instead of running the tool, so
    ADK doesn't accept the answer, and the model reads the error and keeps
    working. After MAX_GUARD_REFUSALS it lets the answer through, so the
    guard can never loop forever.

    Why: in the first live Supervisor run, Flash-Lite's static specialist
    skipped 3 of its 4 core checks even when the brief asked for them. The
    LLM still decides the order and how deep to go; code guarantees the floor.
    """
    called_key = f"temp:called_tools_{agent_name}"
    refusals_key = f"temp:guard_refusals_{agent_name}"

    def checklist_guard(tool, args, tool_context):  # ADK passes these by name
        state = tool_context.state
        if tool.name != "set_model_response":
            called = list(state.get(called_key) or [])
            if tool.name not in called:
                called.append(tool.name)
                state[called_key] = called
            return None
        alert = load_alert(state)
        missing = sorted(required_tools(alert) - set(state.get(called_key) or [])) if alert else []
        refusals = state.get(refusals_key, 0)
        if missing and refusals < MAX_GUARD_REFUSALS:
            state[refusals_key] = refusals + 1
            return {"status": "error",
                    "error_message": "Not submitted yet. Run these standard checks first: "
                                     + ", ".join(missing) + ". Then call set_model_response again."}
        return None

    return checklist_guard


def build_specialist(*, name: str, description: str, instruction: str, tools: list[Callable],
                     output_schema: type[BaseModel], output_key: str,
                     model: str | BaseLlm | None = None, as_subagent: bool = False,
                     planner: str = DEFAULT_PLANNER,
                     required_tools: Callable[[AlertBundle], set[str]] | None = None) -> Agent:
    kwargs = dict(
        name=name,
        model=make_model(model),  # Gemini with timeout + retries (or a test fake)
        description=description,  # the Supervisor reads this to decide when to delegate here
        instruction=instruction + "\n\n" + TEAM_RULES,
        tools=[record_plan, *tools],  # record_plan = the explicit "reason" step
        output_schema=output_schema,  # final answer is validated against this
        output_key=output_key,  # ...and saved in session state under this key
        planner=make_planner(planner),
    )
    if required_tools is not None:
        kwargs["before_tool_callback"] = make_checklist_guard(name, required_tools)
    if as_subagent:
        # single_turn: run once on the Supervisor's request, return a result, no chatting.
        kwargs["mode"] = "single_turn"
    return Agent(**kwargs)
