"""Helpers for the Supervisor.

Call-budget design (2026-11-20): the first Supervisor spent 3 of its 6 model
calls fetching data that code can simply hand over. The alert summary used to
be a tool call; now `alert_brief` puts it in the Supervisor's input. Reading
the evidence ledger used to be a tool call; now `attach_evidence_ledger`
appends the current ledger to every specialist's result, so it arrives in the
same turn as their findings.
"""

from __future__ import annotations

import json

from ..analysis.evidence import EvidenceLedger
from ..schemas import AlertBundle
from .common import UNTRUSTED_NOTE

SPECIALIST_TOOL_NAMES = {"static_analyst", "log_network_analyst", "threat_intel_analyst"}


def alert_summary(alert: AlertBundle) -> dict:
    """What the alert contains: enough to decide which specialists to call."""
    f = alert.file
    return {
        "alert_id": alert.alert_id, "title": alert.title, "source": alert.source, "host": alert.host,
        "description": alert.description,
        "file": {"file_name": f.file_name, "has_sample_binary": bool(f.sample_path),
                 "imported_function_count": sum(len(v) for v in f.imports.values()),
                 "section_count": len(f.sections), "string_count": len(f.strings)} if f else None,
        "process_event_count": len(alert.process_events),
        "connection_count": len(alert.network_connections),
        "dns_query_count": len(alert.dns_queries),
    }


def alert_brief(alert: AlertBundle) -> str:
    """The Supervisor's input message: the alert summary plus a reminder that it is data."""
    return (f"Triage this alert. Summary of what it contains:\n"
            f"{json.dumps(alert_summary(alert), indent=1)}\n\n{UNTRUSTED_NOTE}")


def attach_evidence_ledger(tool, args, tool_context, tool_response):
    """after_tool_callback: append the evidence ledger to each specialist's result.

    Returning a dict replaces the tool result the Supervisor sees, so the ledger arrives
    with the findings instead of costing a separate model call.
    """
    if tool.name not in SPECIALIST_TOOL_NAMES or not isinstance(tool_response, dict):
        return None
    ledger = [{"id": e["id"], "summary": e["summary"]} for e in EvidenceLedger(tool_context.state).all()]
    return {**tool_response, "evidence_ledger_so_far": ledger}
