"""Build the Gemini model object every agent uses, with timeouts and retries.

Without a client timeout a request to an overloaded model can hang for
minutes, which is exactly what happened on 2026-11-19 when the Flash models
returned 504/503 under load. With these settings each attempt gives up after
60 s, and transient errors (rate limit 429, server 5xx) are retried with
exponential backoff before the run fails.
"""

from __future__ import annotations

from google.adk.models.base_llm import BaseLlm
from google.adk.models.google_llm import Gemini
from google.genai import types

from .config import get_settings

REQUEST_TIMEOUT_MS = 60_000
RETRY = types.HttpRetryOptions(
    attempts=3,  # first try + 2 retries
    initial_delay=2.0,  # seconds, doubled each retry
    exp_base=2.0,
    max_delay=20.0,
    http_status_codes=[429, 500, 502, 503, 504],
)


def make_model(model: str | BaseLlm | None = None) -> BaseLlm:
    """A Gemini model with timeout + retry. Pass a BaseLlm (e.g. a test fake) to use it as is."""
    if isinstance(model, BaseLlm):
        return model
    return Gemini(
        model=model or get_settings().model,
        retry_options=RETRY,
        client_kwargs={"http_options": types.HttpOptions(timeout=REQUEST_TIMEOUT_MS)},
    )
