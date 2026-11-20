"""Shared test setup."""

import os

import pytest


@pytest.fixture(autouse=True)
def no_rate_limit_for_fake_models(monkeypatch):
    """Offline tests make many scripted (fake) model calls in seconds; pacing them like
    real Gemini calls would make the suite wait minutes. Live tests (RUN_LIVE=1) keep
    the real limiter. Rate-limiter tests pass explicit limits, so they are unaffected."""
    if os.environ.get("RUN_LIVE") != "1":
        monkeypatch.setenv("TRIAGE_RPM", "0")
