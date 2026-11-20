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


def make_planner(kind: str) -> BasePlanner | None:
    """'plan_react' (explicit text reasoning), 'builtin' (Gemini thinking summaries), or 'none'.

    PlanReAct is the default: on Flash-Lite, BuiltInPlanner produced no
    visible thoughts, so the reasoning step could not be seen in the trace.
    """
    if kind == "plan_react":
        return PlanReActPlanner()
    if kind == "builtin":
        return BuiltInPlanner(thinking_config=types.ThinkingConfig(include_thoughts=True))
    if kind == "none":
        return None
    raise ValueError(f"unknown planner {kind!r}")


def build_specialist(*, name: str, description: str, instruction: str, tools: list[Callable],
                     output_schema: type[BaseModel], output_key: str,
                     model: str | BaseLlm | None = None, as_subagent: bool = False,
                     planner: str = "plan_react") -> Agent:
    kwargs = dict(
        name=name,
        model=make_model(model),  # Gemini with timeout + retries (or a test fake)
        description=description,  # the Supervisor reads this to decide when to delegate here
        instruction=instruction,
        tools=tools,
        output_schema=output_schema,  # final answer is validated against this
        output_key=output_key,  # ...and saved in session state under this key
        planner=make_planner(planner),
    )
    if as_subagent:
        # single_turn: run once on the Supervisor's request, return a result, no chatting.
        kwargs["mode"] = "single_turn"
    return Agent(**kwargs)
