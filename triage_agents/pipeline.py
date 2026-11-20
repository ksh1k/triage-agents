"""The full triage pipeline as an ADK 2.x graph Workflow.

    START -> intake -> supervisor -> check_findings --OK----> report_writer -> check_report -> critic -> route_after_critic
                           ^              |                         ^                                         |      |
                           +----RETRY-----+  (at most 1 retry)      +----------------REVISE (max 2)-----------+      |
                                                                                                          FINAL -> finalize

LLM nodes (agents): supervisor (with its three specialists), report_writer, critic.
Code nodes (plain Python): intake, check_findings, check_report, route_after_critic, finalize.

The loop limits and the "deterministic issues force a revision" rule live in
plain Python, not in prompts: the LLM judges quality, code enforces the budget.

ADK 2.x deprecates LoopAgent and SequentialAgent in favor of this graph API:
routers return Event(route=...), and a routed back-edge forms the loop.
"""

from __future__ import annotations

import json
from typing import Any

from google.adk import Context, Event, Workflow
from google.adk.models.base_llm import BaseLlm
from google.adk.workflow import RetryConfig
from pydantic import ValidationError

from .agents.critic import build_critic
from .agents.report_writer import build_report_writer
from .agents.supervisor import build_supervisor
from .analysis.evidence import EvidenceLedger
from .config import MAX_REVISION_ROUNDS
from .report_check import cited_ids, find_issues
from .schemas import AlertBundle, ReportDraft, TriageReport
from .tools.common import ALERT_KEY, UNTRUSTED_NOTE
from .tools.supervisor_tools import alert_brief

MAX_SUPERVISOR_ATTEMPTS = 2
NODE_RETRY = RetryConfig(max_attempts=2, initial_delay=1.0, jitter=0.0,
                         exceptions=["ValidationError", "JSONDecodeError"])


# ---------------------------------------------------------------- helpers


def _content_text(node_input: Any) -> str:
    parts = getattr(node_input, "parts", None)
    if parts is not None:
        return "".join(p.text or "" for p in parts)
    return node_input if isinstance(node_input, str) else ""


def _ledger_text(state) -> str:
    return "\n".join(f"- {e['id']}: {e['summary']}" for e in EvidenceLedger(state).all()) or "(empty)"


def _alert(state) -> AlertBundle:
    return AlertBundle.model_validate(state[ALERT_KEY])


def _issues_text(issues: list[dict]) -> str:
    return "\n".join(f"- [{i.get('kind', 'other')}] {i.get('detail', '')}" for i in issues) or "(none)"


# ---------------------------------------------------------------- code nodes


def intake(ctx: Context, node_input: Any):
    """Load the alert (from session state, or from the user message as JSON, e.g. in `adk web`),
    record what the alerting tool reported as AL-1 evidence, and brief the Supervisor."""
    updates: dict[str, Any] = {}
    if ctx.state.get(ALERT_KEY):
        alert = _alert(ctx.state)
    else:
        try:
            alert = AlertBundle.model_validate_json(_content_text(node_input))
        except ValidationError as exc:
            raise ValueError(f"Send an alert bundle as JSON (see examples/alerts/). {exc}") from exc
        updates[ALERT_KEY] = alert.model_dump(mode="json")
    reported = f"Reported by {alert.source} on host {alert.host}: {alert.title!r}."
    if alert.description:
        reported += f" Description: {alert.description[:300]!r}"
    updates["evidence_AL"] = [{"id": "AL-1", "source_agent": "alert_intake", "tool": "intake",
                               "summary": reported[:500]}]
    return Event(output=alert_brief(alert), state=updates)


def check_findings(ctx: Context, node_input: Any):
    """Make sure the Supervisor produced merged findings; retry it once if it didn't."""
    attempts = ctx.state.get("supervisor_attempts", 0) + 1
    findings = ctx.state.get("findings")
    if not findings and attempts < MAX_SUPERVISOR_ATTEMPTS:
        retry = (alert_brief(_alert(ctx.state)) + "\n\nThe previous attempt ended without merged findings. "
                 "Delegate to the specialists and submit the merged findings.")
        return Event(route="RETRY", output=retry, state={"supervisor_attempts": attempts})
    request = (
        f"Write the triage report for alert {_alert(ctx.state).alert_id}.\n\n"
        f"Merged findings from the Supervisor:\n{json.dumps(findings, indent=1)}\n\n"
        f"Evidence ledger (cite only these IDs):\n{_ledger_text(ctx.state)}\n\n{UNTRUSTED_NOTE}"
    )
    return Event(route="OK", output=request, state={"supervisor_attempts": attempts})


def check_report(ctx: Context, node_input: Any):
    """Run the deterministic checks on the current draft and brief the Critic."""
    draft = ctx.state.get("draft")
    ledger_ids = EvidenceLedger(ctx.state).ids()
    issues = find_issues(draft, ledger_ids, alert_id=_alert(ctx.state).alert_id,
                         merged=ctx.state.get("findings"))
    updates: dict[str, Any] = {"check_issues": issues}
    if ctx.state.get("revision_round", 0) == 0:
        # Keep the first draft: it is the "without Critic" baseline in the eval.
        updates["draft_v0"] = draft
        updates["check_issues_v0"] = issues
    request = (
        f"Review this draft triage report.\n\nDraft:\n{json.dumps(draft, indent=1)}\n\n"
        f"Automated check results (facts):\n{_issues_text(issues)}\n\n"
        f"Evidence ledger:\n{_ledger_text(ctx.state)}\n\n{UNTRUSTED_NOTE}"
    )
    return Event(output=request, state=updates)


def route_after_critic(ctx: Context, node_input: Any):
    """Send the draft back for revision, or finalize. Max MAX_REVISION_ROUNDS revisions.

    A draft is revised if the Critic says so OR the deterministic checks found problems,
    so an approving Critic can't wave through, say, a wrong tactic.
    """
    critique = ctx.state.get("critique") or {}
    check_issues = ctx.state.get("check_issues") or []
    rounds = ctx.state.get("revision_round", 0)
    critic_issues = critique.get("issues") or []
    log = list(ctx.state.get("review_log") or [])
    log.append({"round": rounds, "critic_verdict": critique.get("verdict", "none"),
                "critic_issues": len(critic_issues), "check_issues": len(check_issues)})

    needs_revision = critique.get("verdict") != "approve" or bool(check_issues)
    if needs_revision and rounds < MAX_REVISION_ROUNDS:
        request = (
            "Revise your triage report. Fix every problem listed below and keep everything else.\n\n"
            f"Your previous draft:\n{json.dumps(ctx.state.get('draft'), indent=1)}\n\n"
            f"Problems found by the automated checks:\n{_issues_text(check_issues)}\n\n"
            f"Problems found by the Critic:\n{_issues_text(critic_issues)}\n\n"
            f"Merged findings from the Supervisor:\n{json.dumps(ctx.state.get('findings'), indent=1)}\n\n"
            f"Evidence ledger (cite only these IDs):\n{_ledger_text(ctx.state)}\n\n{UNTRUSTED_NOTE}"
        )
        return Event(route="REVISE", output=request, state={"revision_round": rounds + 1, "review_log": log})
    return Event(route="FINAL", output="finalize", state={"review_log": log})


def build_report(draft: dict | None, state, revision_rounds: int) -> dict | None:
    """Draft + the evidence records it cites (attached by code, so the LLM can't invent evidence)."""
    if not draft:
        return None
    try:
        d = ReportDraft.model_validate(draft)
    except ValidationError:
        return None
    ledger = EvidenceLedger(state)
    evidence = [ledger.get(i) for i in cited_ids(d) if ledger.exists(i)]
    return TriageReport(**d.model_dump(), evidence=evidence, revision_rounds=revision_rounds).model_dump(mode="json")


def finalize(ctx: Context, node_input: Any):
    """Build the final report and, for the eval, the same report as it was before any revision."""
    state = ctx.state
    rounds = state.get("revision_round", 0)
    report = build_report(state.get("draft"), state, rounds)
    if report is None:
        raise ValueError("The Report Writer did not produce a valid report.")
    ledger_ids = EvidenceLedger(state).ids()
    alert_id = _alert(state).alert_id
    final_issues = find_issues(state.get("draft"), ledger_ids, alert_id=alert_id, merged=state.get("findings"))
    return Event(output=report, state={
        "report": report,
        "final_issues": final_issues,
        "report_without_critic": build_report(state.get("draft_v0"), state, 0),
    })


# ---------------------------------------------------------------- the graph


def build_pipeline(model: str | BaseLlm | None = None, *, supervisor=None, report_writer=None,
                   critic=None) -> Workflow:
    """Assemble the triage graph. Pass agents in to swap in test fakes."""
    supervisor = supervisor or build_supervisor(model)
    report_writer = report_writer or build_report_writer(model)
    critic = critic or build_critic(model)
    for agent in (supervisor, report_writer, critic):
        # Inside a workflow, an agent that ends with plain text has it validated against its
        # output schema; non-JSON text raises. Retry that node once (and only for that error,
        # not e.g. quota errors, which retrying wouldn't fix).
        agent.retry_config = NODE_RETRY
    return Workflow(
        name="triage_pipeline",
        edges=[
            ("START", intake, supervisor, check_findings),
            (check_findings, {"OK": report_writer, "RETRY": supervisor}),
            (report_writer, check_report, critic, route_after_critic),
            (route_after_critic, {"REVISE": report_writer, "FINAL": finalize}),
        ],
    )
