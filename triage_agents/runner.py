"""Run an agent (or, later, the whole workflow) on one alert and collect the results.

Each call builds a fresh App + InMemoryRunner with its own TracePlugin, so
traces from concurrent requests never mix. The alert goes into session state
under "alert", where the tools read it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from google.adk.agents import RunConfig
from google.adk.apps import App
from google.adk.runners import InMemoryRunner
from google.genai import types

from .config import MAX_LLM_CALLS_PER_RUN
from .schemas import AlertBundle
from .tools.common import ALERT_KEY
from .tracing import TracePlugin

APP_NAME = "triage_agents"
USER_ID = "analyst"


@dataclass
class RunResult:
    final_text: str | None
    state: dict[str, Any]
    trace: TracePlugin
    session_id: str
    wall_time_s: float


def default_prompt(alert: AlertBundle) -> str:
    return (f"Triage alert {alert.alert_id} from {alert.source}: {alert.title}\n"
            f"Description: {alert.description or '(none)'}\n"
            "The full alert bundle is in session state. Use your tools to analyze it.")


async def run_agent(root_agent, alert: AlertBundle, prompt: str | None = None, *,
                    live_trace: bool = False, max_llm_calls: int = MAX_LLM_CALLS_PER_RUN,
                    initial_state: dict[str, Any] | None = None) -> RunResult:
    """Run one agent on one alert.

    `initial_state` carries results from earlier runs (e.g. evidence and
    findings from other specialists); "temp:" keys are dropped.
    """
    state = {k: v for k, v in (initial_state or {}).items() if not k.startswith("temp:")}
    state[ALERT_KEY] = alert.model_dump(mode="json")
    trace = TracePlugin(live=live_trace)
    app = App(name=APP_NAME, root_agent=root_agent, plugins=[trace])
    run_config = RunConfig(max_llm_calls=max_llm_calls)
    runner = InMemoryRunner(app=app)
    started = time.perf_counter()
    try:
        session = await runner.session_service.create_session(
            app_name=APP_NAME, user_id=USER_ID, state=state)
        message = types.Content(role="user", parts=[types.Part(text=prompt or default_prompt(alert))])
        final_text = None
        async for event in runner.run_async(user_id=USER_ID, session_id=session.id,
                                            new_message=message, run_config=run_config):
            if event.is_final_response() and event.content and event.content.parts:
                text = "".join(p.text or "" for p in event.content.parts if not p.thought)
                final_text = text or final_text
        session = await runner.session_service.get_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session.id)
        return RunResult(final_text=final_text, state=dict(session.state), trace=trace,
                         session_id=session.id, wall_time_s=round(time.perf_counter() - started, 3))
    finally:
        await runner.close()
