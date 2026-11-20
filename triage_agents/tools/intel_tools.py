"""Tools for the Threat Intel agent: ATT&CK lookups and past-alert history."""

from __future__ import annotations

from functools import lru_cache

from google.adk.tools import ToolContext

from ..analysis.attack import get_index
from ..analysis.evidence import EvidenceLedger
from ..analysis.history import INDICATOR_TYPES, PastAlertsDB
from ..analysis.network import is_internal_ip
from .common import load_alert, record

AGENT = "threat_intel_analyst"
CONFIRMED_KEY = "temp:ti_confirmed"  # technique ID -> evidence ID, so repeats don't duplicate evidence
SPECIALIST_OUTPUT_KEYS = {"static_findings": "static_analyst", "lognet_findings": "log_network_analyst"}


@lru_cache(maxsize=1)
def _history() -> PastAlertsDB:
    return PastAlertsDB()


def _past(rows: list[dict], limit: int = 3) -> str:
    return "; ".join(f"{r['alert_id']} ({r['verdict']}, {r['severity']}): {r['title']}" for r in rows[:limit])


def get_specialist_findings(tool_context: ToolContext) -> dict:
    """Get what the Static Analysis and Log/Network specialists found: their findings, the
    evidence behind them (SA- and LN- IDs), and the ATT&CK technique hints they suggested.
    Call this first.
    """
    state = tool_context.state
    reports = {agent: state.get(key) for key, agent in SPECIALIST_OUTPUT_KEYS.items() if state.get(key)}
    evidence = [{"id": e["id"], "summary": e["summary"]} for e in EvidenceLedger(state).all()
                if not e["id"].startswith("TI-")]
    if not reports and not evidence:
        return {"status": "no_findings", "message": "No specialist findings yet. Work from the alert's indicators."}
    hints = sorted({h for r in reports.values() for f in r.get("findings", []) for h in f.get("technique_hints", [])})
    return {"status": "success", "specialist_reports": reports, "evidence": evidence, "technique_hints": hints}


def get_alert_indicators(tool_context: ToolContext) -> dict:
    """List the indicators in this alert that can be checked against past alerts: file
    hashes and file name, external IP addresses, domains, and the host name.
    """
    alert = load_alert(tool_context.state)
    if alert is None:
        return {"status": "error", "error_message": "no alert in session state"}
    indicators: dict[str, list[str]] = {t: [] for t in INDICATOR_TYPES}
    if alert.file:
        for kind in ("sha256", "md5"):
            if getattr(alert.file, kind):
                indicators[kind].append(getattr(alert.file, kind))
        indicators["filename"].append(alert.file.file_name)
    for c in alert.network_connections:
        if not is_internal_ip(c.dst_ip):
            indicators["ip"].append(c.dst_ip)
        if c.domain:
            indicators["domain"].append(c.domain)
    for q in alert.dns_queries:
        indicators["domain"].append(q.query)
    user_writable = ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\downloads\\")
    for e in alert.process_events:
        cmd = e.command_line
        if any(folder in cmd.lower() for folder in user_writable):
            # Files launched from user-writable folders are worth a history check.
            for token in cmd.replace(",", " ").replace('"', " ").split():
                if token.lower().endswith((".dll", ".exe")) and "\\" in token:
                    indicators["filename"].append(token.rsplit("\\", 1)[-1])
    deduped = {k: sorted(set(v)) for k, v in indicators.items() if v}
    return {"status": "success", "host": alert.host, "indicators": deduped}


def get_technique(technique_id: str, tool_context: ToolContext) -> dict:
    """Look up an ATT&CK technique by ID in the local ATT&CK v20.1 dataset and confirm it
    exists. If MITRE revoked the ID, the replacement ID is returned instead. A confirmed
    ID is recorded as evidence (TI-n) that you cite next to the behavior evidence.

    Args:
        technique_id: The technique ID, e.g. "T1059.001".
    """
    index = get_index()
    record_ = index.get(technique_id)
    if record_ is None:
        replacement = index.replacement_for(technique_id)
        if replacement:
            return {"status": "revoked", "technique_id": technique_id.upper(), "replacement": replacement,
                    "message": f"{technique_id.upper()} was revoked in ATT&CK v{index.version}; "
                               f"call get_technique with {replacement} instead."}
        return {"status": "not_found", "technique_id": technique_id,
                "message": f"No such technique in ATT&CK v{index.version}. Do not use this ID."}
    confirmed = dict(tool_context.state.get(CONFIRMED_KEY) or {})
    eid = confirmed.get(record_["id"])
    if eid is None:
        eid = record(tool_context.state, AGENT, "get_technique",
                     f"ATT&CK v{index.version} confirms {record_['id']} '{record_['name']}' "
                     f"(tactics: {', '.join(record_['tactics'])})")
        confirmed[record_["id"]] = eid
        tool_context.state[CONFIRMED_KEY] = confirmed
    return {"status": "success", "evidence_id": eid, "id": record_["id"], "name": record_["name"],
            "tactics": record_["tactics"], "parent": record_["parent"], "platforms": record_["platforms"],
            "description": record_["description"]}


def search_attack(query: str, tactic: str = "") -> dict:
    """Search ATT&CK v20.1 techniques by keywords when a behavior has no technique hint, e.g.
    "rundll32 proxy execution" or "web protocol command and control". Optionally filter by a
    tactic short name such as "persistence", "command-and-control", "stealth" or "execution".
    Confirm any result with get_technique before using it.

    Args:
        query: Keywords describing the behavior.
        tactic: Optional tactic short name to filter by. Leave empty for all tactics.
    """
    index = get_index()
    tactic = tactic.strip() or None
    if tactic and tactic not in index.tactics:
        return {"status": "error", "error_message": f"unknown tactic; use one of {sorted(index.tactics)}"}
    return {"status": "success", "attack_version": index.version, "results": index.search(query, limit=6, tactic=tactic)}


def check_indicator_history(indicator_type: str, value: str, tool_context: ToolContext) -> dict:
    """Check whether an indicator appeared in past alerts and how those alerts were resolved:
    true_positive (confirmed malicious), false_positive (the alert was wrong), or
    benign_true_positive (real activity, but authorized, e.g. IT admin work or a red team).

    Args:
        indicator_type: One of sha256, md5, ip, domain, filename.
        value: The indicator value.
    """
    result = _history().lookup_indicator(indicator_type, value)
    if result.get("match_count"):
        result["evidence_id"] = record(tool_context.state, AGENT, "check_indicator_history",
                                       f"{indicator_type} {value!r} seen in {result['match_count']} past "
                                       f"alert(s): {_past(result['matches'])}")
    return result


def check_technique_history(technique_id: str, tool_context: ToolContext) -> dict:
    """How past alerts involving this ATT&CK technique were resolved (counts per verdict and
    recent examples). Useful for knowing whether this behavior is usually benign here.

    Args:
        technique_id: The technique ID, e.g. "T1071.001".
    """
    result = _history().technique_history(technique_id)
    if result["verdict_counts"]:
        counts = ", ".join(f"{v} {k}" for k, v in sorted(result["verdict_counts"].items()))
        result["evidence_id"] = record(tool_context.state, AGENT, "check_technique_history",
                                       f"Past alerts with {result['technique_id']}: {counts}")
    return result


def check_host_history(host: str, tool_context: ToolContext) -> dict:
    """Recent past alerts on the same host.

    Args:
        host: The host name, e.g. "WS-FIN-07".
    """
    result = _history().host_history(host)
    if result["alert_count"]:
        result["evidence_id"] = record(tool_context.state, AGENT, "check_host_history",
                                       f"Host {host} had {result['alert_count']} past alert(s): {_past(result['alerts'])}")
    return result


INTEL_TOOLS = [get_specialist_findings, get_alert_indicators, get_technique, search_attack,
               check_indicator_history, check_technique_history, check_host_history]
