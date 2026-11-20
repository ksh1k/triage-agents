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

DEFAULT_MODEL = "gemini-3.8-flash"
MAX_REVISION_ROUNDS = 2  # The Critic may send a draft back at most this many times.


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
