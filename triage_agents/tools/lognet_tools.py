"""Tools for the Log/Network agent: process trees, connections, beaconing, DNS."""

from __future__ import annotations

from google.adk.tools import ToolContext

from ..analysis.logs import analyze_process_events, build_process_tree
from ..analysis.network import detect_beaconing, dns_anomalies, is_internal_ip, summarize_connections
from .common import UNTRUSTED_NOTE, load_alert, record

AGENT = "log_network_analyst"
MAX_TREE_CHARS = 3000
MAX_DESTINATIONS = 10


def _clip(text: str, limit: int = 160) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _events(alert) -> list[dict]:
    return [e.model_dump(mode="json") for e in alert.process_events]


def _conns(alert) -> list[dict]:
    return [c.model_dump(mode="json") for c in alert.network_connections]


def get_activity_overview(tool_context: ToolContext) -> dict:
    """Get an overview of the alert's activity logs: the host, how many process events,
    network connections and DNS queries there are, and the time span they cover.
    Call this first.
    """
    alert = load_alert(tool_context.state)
    if alert is None:
        return {"status": "error", "error_message": "no alert in session state"}
    times = ([e.timestamp for e in alert.process_events] + [c.timestamp for c in alert.network_connections]
             + [q.timestamp for q in alert.dns_queries])
    if not times:
        return {"status": "no_logs", "message": "This alert has no process, network or DNS logs."}
    first, last = min(times).isoformat(), max(times).isoformat()
    eid = record(tool_context.state, AGENT, "get_activity_overview",
                 f"Alert {alert.alert_id} on host {alert.host}: {len(alert.process_events)} process events, "
                 f"{len(alert.network_connections)} network connections, {len(alert.dns_queries)} DNS "
                 f"queries between {first} and {last}")
    return {"status": "success", "evidence_id": eid, "host": alert.host,
            "process_event_count": len(alert.process_events),
            "connection_count": len(alert.network_connections),
            "dns_query_count": len(alert.dns_queries), "first_seen": first, "last_seen": last}


def analyze_process_tree(tool_context: ToolContext) -> dict:
    """Rebuild the process tree (which process started which) and check it for suspicious
    parent-child pairs (e.g. Word starting PowerShell), command-line patterns (encoded
    PowerShell, download cradles, LOLBins such as rundll32, mshta or certutil, LSASS
    dumping, persistence, Defender tampering, log clearing), system binaries running from
    the wrong folder, and bursts of discovery commands. Encoded PowerShell is decoded
    (never run) and checked again.
    """
    alert = load_alert(tool_context.state)
    if alert is None or not alert.process_events:
        return {"status": "no_process_events", "message": "No process events in this alert."}
    result = analyze_process_events(_events(alert))
    state = tool_context.state
    for f in result["findings"]:
        detail = f"decoded text {f['decoded']!r}" if "decoded" in f else f"command line {_clip(f['command_line'])!r}"
        where = f" (in the {f['matched_in']})" if "matched_in" in f else ""
        parent = f", parent {f['parent']} (pid {f['parent_pid']})" if "parent" in f else ""
        f["evidence_id"] = record(state, AGENT, "analyze_process_tree",
                                  f"pid {f['pid']} {f['image']}{parent}: {f['description']}{where}; {detail}")
    response = {"status": "success", "process_count": result["process_count"],
                "process_tree": result["tree_text"][:MAX_TREE_CHARS], "findings": result["findings"],
                "score": result["score"], "note": UNTRUSTED_NOTE}
    if not result["findings"]:
        response["evidence_id"] = record(state, AGENT, "analyze_process_tree",
                                         f"Process tree of {result['process_count']} processes shows no "
                                         "suspicious parent-child pairs or command lines")
    return response


def summarize_network(tool_context: ToolContext) -> dict:
    """Summarize network connections by destination (count, bytes sent and received,
    internal or external, which process IDs) and flag external connections on uncommon
    ports and large uploads.
    """
    alert = load_alert(tool_context.state)
    if alert is None or not alert.network_connections:
        return {"status": "no_connections", "message": "No network connections in this alert."}
    summary = summarize_connections(_conns(alert))
    state = tool_context.state
    for flag in summary["flags"]:
        flag["evidence_id"] = record(state, AGENT, "summarize_network",
                                     f"{flag['detail']}: {flag['dst_ip']}:{flag['dst_port']} ({flag['domain']})")
    external = [d for d in summary["destinations"] if d["external"]]
    listing = "; ".join(f"{d['dst_ip']}:{d['dst_port']} ({d['domain'] or 'no domain'}) x{d['count']} "
                        f"from pid {d['pids']}" for d in external[:5])
    summary["evidence_id"] = record(state, AGENT, "summarize_network",
                                    f"{summary['connection_count']} connections to {len(external)} external "
                                    f"destination(s): {listing or 'none'}")
    summary["destinations"] = summary["destinations"][:MAX_DESTINATIONS]
    return {"status": "success", **summary}


def check_beaconing(tool_context: ToolContext) -> dict:
    """Test each external destination for beaconing: connections on a regular timer, typical
    of malware checking in with a command-and-control server. Uses the coefficient of
    variation (CV) of the gaps between connections: near 0 means a machine-like timer,
    around 1 means irregular, human-like traffic. Needs at least 6 connections.
    """
    alert = load_alert(tool_context.state)
    if alert is None or not alert.network_connections:
        return {"status": "no_connections", "message": "No network connections in this alert."}
    results = detect_beaconing(_conns(alert))
    state = tool_context.state
    for r in results:
        if r["verdict"] != "irregular":
            r["evidence_id"] = record(
                state, AGENT, "check_beaconing",
                f"{r['verdict']}: {r['connections']} connections to {r['dst_ip']}:{r['dst_port']} "
                f"({r['domain']}) every {r['mean_interval_s']} s on average, interval CV {r['interval_cv']}, "
                f"bytes-sent CV {r['bytes_out_cv']}")
    response = {"status": "success", "destinations_tested": len(results), "results": results}
    if not any(r["verdict"] != "irregular" for r in results):
        response["evidence_id"] = record(
            state, AGENT, "check_beaconing",
            f"No beaconing: {len(results)} external destination(s) had enough connections to test, "
            "none on a regular timer")
    return response


def analyze_dns(tool_context: ToolContext) -> dict:
    """Check DNS queries for random-looking (DGA) domain names, unusually long names that
    could carry hidden data (DNS tunneling), and bursts of failed lookups.
    """
    alert = load_alert(tool_context.state)
    if alert is None or not alert.dns_queries:
        return {"status": "no_dns", "message": "No DNS queries in this alert."}
    findings = dns_anomalies([q.model_dump(mode="json") for q in alert.dns_queries])
    for f in findings:
        f["evidence_id"] = record(tool_context.state, AGENT, "analyze_dns", f"{f['detail']}: {f['query']}")
    response = {"status": "success", "queries": len(alert.dns_queries), "findings": findings,
                "note": UNTRUSTED_NOTE}
    if not findings:
        response["evidence_id"] = record(tool_context.state, AGENT, "analyze_dns",
                                         f"No DNS anomalies in {len(alert.dns_queries)} queries")
    return response


def lookup_process(pid: int, tool_context: ToolContext) -> dict:
    """Show one process from the logs in detail: executable, full command line, user, parent
    process, child processes, and its network connections. Use it to look closer at a PID.

    Args:
        pid: The process ID to look up.
    """
    alert = load_alert(tool_context.state)
    if alert is None or not alert.process_events:
        return {"status": "no_process_events", "message": "No process events in this alert."}
    nodes = build_process_tree(_events(alert))["nodes"]
    node = nodes.get(pid)
    if node is None:
        return {"status": "not_found", "message": f"pid {pid} is not in the process log"}
    parent = nodes.get(node["ppid"])
    conns = [c for c in _conns(alert) if c.get("pid") == pid]
    external = sorted({f"{c['dst_ip']}:{c['dst_port']}" for c in conns if not is_internal_ip(c["dst_ip"])})
    eid = record(tool_context.state, AGENT, "lookup_process",
                 f"pid {pid} {node['image']} started by "
                 f"{parent['image'] + ' (pid ' + str(parent['pid']) + ')' if parent else 'pid ' + str(node['ppid']) + ' (not in log)'}"
                 f" as user {node.get('user')}; command line {_clip(node.get('command_line', ''), 200)!r}; "
                 f"{len(conns)} connections" + (f" to {', '.join(external[:3])}" if external else ""))
    return {
        "status": "success", "evidence_id": eid, "pid": pid, "image": node["image"],
        "command_line": node.get("command_line", ""), "user": node.get("user"),
        "parent": {"pid": parent["pid"], "image": parent["image"]} if parent else {"pid": node["ppid"], "image": None},
        "children": [{"pid": c, "image": nodes[c]["image"], "command_line": _clip(nodes[c].get("command_line", ""))}
                     for c in node["children"]],
        "connection_count": len(conns), "external_destinations": external, "note": UNTRUSTED_NOTE,
    }


LOGNET_TOOLS = [get_activity_overview, analyze_process_tree, summarize_network, check_beaconing,
                analyze_dns, lookup_process]
