"""Triage Agents: multi-agent security-alert triage with Google ADK and Gemini.

`from . import agent` lets ADK's `adk web` / `adk run` find `root_agent`
(the full triage Workflow). Building it makes no API calls.
"""

__version__ = "0.1.0"

from . import agent  # noqa: E402,F401
