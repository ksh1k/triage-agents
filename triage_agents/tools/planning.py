"""record_plan: the "Reason" step of ReAct as an explicit tool call.

Why a tool instead of ADK's PlanReActPlanner: with the planner, the model
writes a /*PLANNING*/ section that ADK marks as a thought. In live runs
(2026-11-20) Flash-Lite sometimes sent the plan on its own, with no tool
call, and ADK treats a reply without tool calls as the agent's final answer,
so the agent stopped before doing any work (2 of ~12 agent runs). Native
Gemini thinking isn't available on Flash-Lite. Making the plan a tool call
keeps the reasoning visible in the trace, and an agent can't stop after
planning, because recording the plan is itself an action.
"""

from __future__ import annotations

from google.adk.tools import ToolContext

PLAN_KEY_PREFIX = "plan_"  # one key per agent, so parallel specialists don't overwrite each other
MAX_PLAN_CHARS = 1500


def record_plan(plan: str, tool_context: ToolContext) -> dict:
    """Write down your plan before acting: which checks you will run, in what order, and why,
    as a few short numbered steps. Call this first, then carry out the plan with your other tools.

    Args:
        plan: Your plan as short numbered steps.
    """
    agent = getattr(tool_context, "agent_name", None) or "agent"
    tool_context.state[f"{PLAN_KEY_PREFIX}{agent}"] = plan[:MAX_PLAN_CHARS]
    return {"status": "success", "message": "Plan recorded. Now carry it out: call your first tool."}
