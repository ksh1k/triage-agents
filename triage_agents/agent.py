"""Entry point for ADK's developer tools.

`adk web` (browser UI with the agent graph, events and traces) and `adk run`
look for a module-level `root_agent`. From the repo root:

    uv run adk web .        # then pick "triage_agents" and paste an alert JSON as the message

The intake node accepts the alert as the chat message when it isn't already in
session state.
"""

from .pipeline import build_pipeline

root_agent = build_pipeline()
