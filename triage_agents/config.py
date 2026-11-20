"""Central configuration.

Settings come from environment variables. A local `.env` file is loaded first
if one exists, and variables already set in the environment take precedence.

The API key is never stored on the Settings object, printed, or logged. Code
that needs to know about it asks `api_key_configured()`, which returns only
True or False.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# override=False: a real environment variable (e.g. set by Cloud Run) beats .env.
load_dotenv(PROJECT_ROOT / ".env", override=False)

# Flash-Lite: the cheapest current model, the only Flash-family model answering
# on 2026-11-19 while 3.6/3.7/3.8 Flash returned 503/504, and the one with real
# free-tier headroom: 15 RPM / 500 requests per day, versus 5 RPM / 20 per day
# for 3.8 Flash. A full triage takes ~20-30 calls, so 20/day would not even
# cover one eval. Override with TRIAGE_MODEL.
DEFAULT_MODEL = "gemini-3.5-flash-lite"
MAX_REVISION_ROUNDS = 2  # The Critic may send a draft back at most this many times.
# Circuit breaker: ADK aborts a run after this many model calls, so a looping
# agent can't burn through the free-tier daily quota.
MAX_LLM_CALLS_PER_RUN = 40

# Paid-tier list prices in USD per 1M tokens (input, output), from Google's
# Gemini API pricing page, checked 2026-11-19. The free tier costs $0. These
# give a "what this would cost at scale" figure. Thinking tokens bill as output.
MODEL_PRICES_PER_1M: dict[str, tuple[float, float]] = {
    "gemini-3.8-flash": (0.75, 3.75),  # rises to 1.50 / 7.50 on 2027-01-01
    "gemini-3.6-flash": (0.75, 3.75),
    "gemini-3.5-flash-lite": (0.30, 2.50),
}

# Binaries the static tools may open. Anything outside these folders is
# refused, so an alert (or a prompt-injected model) can't point the parser
# at arbitrary files on the server.
DEFAULT_SAMPLE_DIRS = [PROJECT_ROOT / "data" / "samples"]


def sample_dirs() -> list[Path]:
    """Allowed sample folders: the default plus any listed in TRIAGE_SAMPLE_DIRS."""
    extra = [Path(p) for p in os.environ.get("TRIAGE_SAMPLE_DIRS", "").split(os.pathsep) if p.strip()]
    return [p.resolve() for p in DEFAULT_SAMPLE_DIRS + extra]


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float | None:
    """Paid-tier cost estimate, or None if we don't have a price for this model."""
    # Exact name first, then prefix (the API may report e.g. "gemini-3.8-flash-002").
    prices = MODEL_PRICES_PER_1M.get(model) or next(
        (p for name, p in MODEL_PRICES_PER_1M.items() if model.startswith(name)), None)
    if prices is None:
        return None
    return (input_tokens * prices[0] + output_tokens * prices[1]) / 1_000_000


@dataclass(frozen=True)
class Settings:
    model: str
    max_revision_rounds: int
    data_dir: Path
    traces_dir: Path


def get_settings() -> Settings:
    """Read settings from the environment. Called fresh each time, so tests can
    change environment variables and see the effect."""
    return Settings(
        model=os.environ.get("TRIAGE_MODEL", "").strip() or DEFAULT_MODEL,
        max_revision_rounds=MAX_REVISION_ROUNDS,
        data_dir=PROJECT_ROOT / "data",
        traces_dir=PROJECT_ROOT / "traces",
    )


def api_key_configured() -> bool:
    """True if a Gemini API key is present. Never returns the key itself."""
    return bool(os.environ.get("GOOGLE_API_KEY", "").strip())


def describe() -> dict[str, str]:
    """A safe summary for logs and the CLI: the key shows only as set/missing."""
    s = get_settings()
    return {
        "model": s.model,
        "max_revision_rounds": str(s.max_revision_rounds),
        "google_api_key": "set" if api_key_configured() else "missing",
    }
