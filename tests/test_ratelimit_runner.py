"""Rate limiter (sliding 60 s window) and the runner's failure handling."""

import asyncio
from pathlib import Path

import pytest

from triage_agents import ratelimit
from triage_agents.agents.static_analysis import build_static_analyst
from triage_agents.ratelimit import RateLimitPlugin, SlidingWindowLimiter, get_limiter
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle
from triage_agents.tracing import TracePlugin

from .fakes import ScriptedLlm, call

ROOT = Path(__file__).resolve().parent.parent
ALERT = AlertBundle.model_validate_json((ROOT / "examples" / "alerts" / "loader_demo_sample.json").read_text())


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_window_allows_rpm_then_says_how_long_to_wait():
    clock = FakeClock()
    lim = SlidingWindowLimiter(rpm=3, clock=clock)
    assert [lim._try_reserve() for _ in range(3)] == [0.0, 0.0, 0.0]
    clock.now += 10
    wait = lim._try_reserve()
    assert wait == pytest.approx(50.05)  # oldest request leaves the window 50 s from now
    clock.now += 50.1
    assert lim._try_reserve() == 0.0


def test_acquire_sleeps_until_a_slot_frees(monkeypatch):
    clock = FakeClock()
    lim = SlidingWindowLimiter(rpm=2, clock=clock)

    async def fake_sleep(seconds):
        clock.now += seconds  # time passes instantly in the test

    monkeypatch.setattr(ratelimit.asyncio, "sleep", fake_sleep)

    async def three_calls():
        return [await lim.acquire() for _ in range(3)]

    waits = asyncio.run(three_calls())
    assert waits[:2] == [0.0, 0.0] and waits[2] == pytest.approx(60.05)


def test_zero_rpm_disables_limiting():
    assert asyncio.run(SlidingWindowLimiter(rpm=0).acquire()) == 0.0


def test_limiters_are_shared_per_model(monkeypatch):
    monkeypatch.setenv("TRIAGE_RPM", "7")
    monkeypatch.setattr(ratelimit, "_limiters", {})
    a = get_limiter("model-a")
    assert get_limiter("model-a") is a and a.rpm == 7
    assert get_limiter("model-b") is not a


def test_plugin_reports_waits_to_the_trace(monkeypatch):
    clock = FakeClock()

    async def fake_sleep(seconds):
        clock.now += seconds

    monkeypatch.setattr(ratelimit.asyncio, "sleep", fake_sleep)
    monkeypatch.setitem(ratelimit._limiters, "m", SlidingWindowLimiter(rpm=1, clock=clock))
    trace = TracePlugin()
    plugin = RateLimitPlugin(trace=trace, rpm=1)

    class Req:
        model = "m"

    class Ctx:
        agent_name = "static_analyst"

    async def two_calls():
        for _ in range(2):
            await plugin.before_model_callback(callback_context=Ctx(), llm_request=Req())

    asyncio.run(two_calls())
    waits = [r for r in trace.records if r["kind"] == "rate_limit_wait"]
    assert len(waits) == 1 and waits[0]["wait_s"] == pytest.approx(60.05, abs=0.01)
    assert trace.totals()["rate_limit_wait_s"] == pytest.approx(60.05, abs=0.01)


def test_failed_run_returns_partial_state_and_trace_instead_of_raising():
    llm = ScriptedLlm(script=[call("get_file_overview")])  # then runs out of steps
    result = asyncio.run(run_agent(build_static_analyst(model=llm), ALERT, rpm=0))
    assert not result.ok and "ran out of scripted steps" in result.error
    assert result.state["evidence_SA"][0]["id"] == "SA-1"  # work done before the failure is kept
    assert result.trace.records[-1]["kind"] == "run_error"
