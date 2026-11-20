"""Response cache: a repeated run is served from disk with zero model calls."""

import asyncio
import json
from pathlib import Path

from triage_agents.agents.static_analysis import OUTPUT_KEY, build_static_analyst
from triage_agents.cache import request_key
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle

from .fakes import ScriptedLlm, call, calls

ROOT = Path(__file__).resolve().parent.parent
ALERT = AlertBundle.model_validate_json((ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text())
FINDINGS = {"agent": "static_analyst", "summary": "cached run", "findings": [], "benign_explanations": [], "gaps": []}


def script():
    return [
        calls(("record_plan", {"plan": "1. all checks 2. submit"}), ("get_file_overview", {}),
              ("analyze_imports", {}), ("analyze_sections", {}), ("analyze_strings", {})),
        call("set_model_response", **FINDINGS),
    ]


def test_second_identical_run_makes_no_model_calls(tmp_path):
    first_llm = ScriptedLlm(script=script())
    first = asyncio.run(run_agent(build_static_analyst(model=first_llm), ALERT, cache=True, cache_dir=tmp_path))
    assert len(first_llm.requests) == 2 and len(list(tmp_path.glob("*.json"))) == 2

    empty_llm = ScriptedLlm(script=[])  # would raise if the model were actually called
    second = asyncio.run(run_agent(build_static_analyst(model=empty_llm), ALERT, cache=True, cache_dir=tmp_path))
    assert second.ok and empty_llm.requests == []
    assert second.state[OUTPUT_KEY]["summary"] == "cached run"
    assert second.state["evidence_SA"] == first.state["evidence_SA"]  # tools still ran for real
    totals = second.trace.totals()
    assert totals["model_calls"] == 2 and totals["cached_calls"] == 2 and totals["api_calls"] == 0
    assert "[LLM 1] from cache" in second.trace.format_timeline()


def test_cache_off_by_default_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("TRIAGE_CACHE", raising=False)
    asyncio.run(run_agent(build_static_analyst(model=ScriptedLlm(script=script())), ALERT, cache_dir=tmp_path))
    assert list(tmp_path.glob("*.json")) == []


def test_key_ignores_random_function_call_ids():
    from google.adk.models.llm_request import LlmRequest
    from google.genai import types

    def req(call_id):
        return LlmRequest(model="m", contents=[
            types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(
                id=call_id, name="analyze_imports", args={}))]),
            types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(
                id=call_id, name="analyze_imports", response={"status": "success"}))]),
        ])

    assert request_key(req("adk-111")) == request_key(req("adk-222"))
    different = req("adk-111")
    different.contents[1].parts[0].function_response.response = {"status": "error"}
    assert request_key(different) != request_key(req("adk-111"))
    json.dumps(request_key(req("x")))  # plain string
