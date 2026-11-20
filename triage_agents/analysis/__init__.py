"""Deterministic security analysis: plain Python, no LLM, no ADK.

Everything in this package is a pure function or a small class that can be
unit-tested on its own. The agents (built in later steps) call these through
thin ADK tool wrappers, so the security logic stays testable and explainable
whatever the LLM does.
"""
