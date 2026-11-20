"""Model factory: real Gemini gets timeout + retries; test fakes pass straight through."""

from google.adk.models.google_llm import Gemini

from triage_agents import config
from triage_agents.models import REQUEST_TIMEOUT_MS, make_model

from .fakes import ScriptedLlm


def test_gemini_gets_timeout_and_retries(monkeypatch):
    monkeypatch.delenv("TRIAGE_MODEL", raising=False)
    model = make_model()
    assert isinstance(model, Gemini)
    assert model.model == config.DEFAULT_MODEL
    assert model.retry_options.attempts == 3
    assert {429, 503, 504} <= set(model.retry_options.http_status_codes)
    assert model.client_kwargs["http_options"].timeout == REQUEST_TIMEOUT_MS


def test_named_model_and_fake_passthrough():
    assert make_model("gemini-3.8-flash").model == "gemini-3.8-flash"
    fake = ScriptedLlm()
    assert make_model(fake) is fake


def test_cost_estimate_uses_prefix_match():
    exact = config.estimate_cost_usd("gemini-3.5-flash-lite", 1_000_000, 1_000_000)
    assert exact == 0.30 + 2.50
    assert config.estimate_cost_usd("gemini-3.5-flash-lite-002", 1_000_000, 0) == 0.30
    assert config.estimate_cost_usd("unknown-model", 10, 10) is None
