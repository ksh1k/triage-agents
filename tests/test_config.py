"""Config: model selection works, and the API key never leaks."""

from triage_agents import config

FAKE_KEY = "test-key-" + "x" * 20  # not a real key, and not key-shaped


def test_default_model_when_unset(monkeypatch):
    monkeypatch.delenv("TRIAGE_MODEL", raising=False)
    assert config.get_settings().model == config.DEFAULT_MODEL


def test_model_override(monkeypatch):
    monkeypatch.setenv("TRIAGE_MODEL", "gemini-3.5-flash-lite")
    assert config.get_settings().model == "gemini-3.5-flash-lite"


def test_max_revision_rounds_is_two():
    assert config.get_settings().max_revision_rounds == 2


def test_api_key_detection(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", FAKE_KEY)
    assert config.api_key_configured() is True
    monkeypatch.setenv("GOOGLE_API_KEY", "   ")
    assert config.api_key_configured() is False
    monkeypatch.delenv("GOOGLE_API_KEY")
    assert config.api_key_configured() is False


def test_key_never_appears_in_settings_or_summary(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", FAKE_KEY)
    assert FAKE_KEY not in repr(config.get_settings())
    summary = config.describe()
    assert summary["google_api_key"] == "set"
    assert FAKE_KEY not in str(summary)
