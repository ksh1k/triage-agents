"""ADK tool wrappers: thin functions the agents can call.

Each wrapper reads the alert from session state, calls the tested analysis
code in `triage_agents.analysis`, records notable results in the evidence
ledger, and returns a small JSON-friendly dict (with the new evidence IDs)
for the model to read.
"""
