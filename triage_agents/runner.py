"""Run an agent (or, later, the whole workflow) on one alert and collect the results.

Each call builds a fresh App + InMemoryRunner with its own TracePlugin, so
traces from concurrent requests never mix. The alert goes into session state
under "alert", where the tools read it.

A failed run does not raise. RunResult.error holds the error, and the
partial state and trace are still returned, so the eval can record the
failure and move on, and the trace shows exactly where it broke.
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
from .ratelimit import RateLimitPlugin
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
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def default_prompt(alert: AlertBundle) -> str:
    return (f"Triage alert {alert.alert_id} from {alert.source}: {alert.title}\n"
            f"Description: {alert.description or '(none)'}\n"
            "The full alert bundle is in session state. Use your tools to analyze it.")


async def run_agent(root_agent, alert: AlertBundle, prompt: str | None = None, *,
                    live_trace: bool = False, max_llm_calls: int = MAX_LLM_CALLS_PER_RUN,
                    initial_state: dict[str, Any] | None = None, rpm: int | None = None) -> RunResult:
    """Run one agent on one alert.

    `initial_state` carries results from earlier runs (e.g. evidence and
    findings from other specialists); "temp:" keys are dropped. `rpm`
    overrides the requests-per-minute limit (default TRIAGE_RPM or 14; 0 = off).
    """
    state = {k: v for k, v in (initial_state or {}).items() if not k.startswith("temp:")}
    state[ALERT_KEY] = alert.model_dump(mode="json")
    trace = TracePlugin(live=live_trace)
    # Rate limiter first, so the trace's model latency excludes time spent waiting.
    app = App(name=APP_NAME, root_agent=root_agent, plugins=[RateLimitPlugin(trace=trace, rpm=rpm), trace])
    runner = InMemoryRunner(app=app)
    started = time.perf_counter()
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID, state=state)
    final_text, error = None, None
    try:
        message = types.Content(role="user", parts=[types.Part(text=prompt or default_prompt(alert))])
        async for event in runner.run_async(user_id=USER_ID, session_id=session.id, new_message=message,
                                            run_config=RunConfig(max_llm_calls=max_llm_calls)):
            if event.is_final_response() and event.content and event.content.parts:
                text = "".join(p.text or "" for p in event.content.parts if not p.thought)
                final_text = text or final_text
    except Exception as exc:  # noqa: BLE001 - recorded, not swallowed: see RunResult.error
        error = f"{type(exc).__name__}: {str(exc)[:500]}"
        trace.note("run_error", root_agent.name, error=error)
    finally:
        session = await runner.session_service.get_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session.id) or session
        await runner.close()
    return RunResult(final_text=final_text, state=dict(session.state), trace=trace, session_id=session.id,
                     wall_time_s=round(time.perf_counter() - started, 3), error=error)
