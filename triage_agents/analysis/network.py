"""Network analysis: connection summary, beaconing detection, suspicious DNS.

Beaconing is malware "checking in" with its command-and-control server on a
timer. Humans browse in irregular bursts, while an implant connects every N
seconds (often with a little random jitter). We measure regularity with the
coefficient of variation (CV) of the gaps between connections:

    CV = standard deviation of gaps / mean gap

CV is unit-free, so a 60-second beacon and a 1-hour beacon are judged the
same way. A perfect timer has CV = 0. Random human-ish traffic (gaps from an
exponential distribution) has CV around 1.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict
from datetime import datetime

from .static import shannon_entropy

# Python's ipaddress.is_private also treats the documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as private. Our synthetic
# data uses those ranges to stand in for *internet* hosts, so we list the
# genuinely internal ranges explicitly instead.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
)]
COMMON_PORTS = {53, 80, 123, 443, 853}
LARGE_UPLOAD_BYTES = 10 * 1024 * 1024

BEACON_MIN_CONNECTIONS = 6
BEACON_MAX_CV = 0.25  # "likely beacon" at or below this
POSSIBLE_BEACON_MAX_CV = 0.5
BEACON_MIN_MEAN_GAP_S = 1.0  # sub-second gaps are bursts, not timers

DGA_MIN_LABEL_LEN = 12
DGA_MIN_CHAR_ENTROPY = 3.5
TUNNEL_LABEL_LEN = 40
TUNNEL_TOTAL_LEN = 100
NXDOMAIN_BURST = 5
CDN_SUFFIXES = ("cloudfront.net", "akamaiedge.net", "azureedge.net", "googleusercontent.com",
                "fastly.net", "edgekey.net")


def _ts(value) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value))


def is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version)


def _web_or_dns_technique(port: int) -> list[str]:
    if port in (80, 443, 8080, 8443):
        return ["T1071.001"]
    if port == 53:
        return ["T1071.004"]
    return ["T1071"]


# ------------------------------------------------------------------ connections


def summarize_connections(connections: list[dict]) -> dict:
    """Group connections by destination and flag unusual ports and big uploads."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for c in connections:
        groups[(c["dst_ip"], c["dst_port"], c.get("domain"))].append(c)

    destinations, flags = [], []
    for (ip, port, domain), conns in groups.items():
        times = sorted(_ts(c["timestamp"]) for c in conns)
        out = sum(c.get("bytes_out") or 0 for c in conns)
        dest = {
            "dst_ip": ip, "dst_port": port, "domain": domain, "count": len(conns),
            "external": not is_internal_ip(ip),
            "first_seen": times[0].isoformat(), "last_seen": times[-1].isoformat(),
            "bytes_out": out, "bytes_in": sum(c.get("bytes_in") or 0 for c in conns),
            "pids": sorted({c["pid"] for c in conns if c.get("pid") is not None}),
        }
        destinations.append(dest)
        if dest["external"] and port not in COMMON_PORTS:
            flags.append({"flag": "uncommon_port", "dst_ip": ip, "dst_port": port, "domain": domain,
                          "detail": f"external connection on uncommon port {port}",
                          "technique_hints": ["T1571"]})
        if dest["external"] and out >= LARGE_UPLOAD_BYTES:
            flags.append({"flag": "large_upload", "dst_ip": ip, "dst_port": port, "domain": domain,
                          "detail": f"{out / 1048576:.1f} MB sent to an external host",
                          "technique_hints": ["T1041"]})

    destinations.sort(key=lambda d: -d["count"])
    return {"connection_count": len(connections), "destination_count": len(destinations),
            "external_destination_count": sum(d["external"] for d in destinations),
            "destinations": destinations, "flags": flags}


def detect_beaconing(connections: list[dict], min_connections: int = BEACON_MIN_CONNECTIONS,
                     max_cv: float = BEACON_MAX_CV) -> list[dict]:
    """Find external destinations contacted on a regular timer.

    For each (dst_ip, dst_port) with enough connections, compute the gaps
    between consecutive connections and their CV. Also report the CV of
    bytes sent, since implants tend to send same-sized check-ins.
    """
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for c in connections:
        if not is_internal_ip(c["dst_ip"]):
            groups[(c["dst_ip"], c["dst_port"])].append(c)

    results = []
    for (ip, port), conns in groups.items():
        if len(conns) < min_connections:
            continue
        conns = sorted(conns, key=lambda c: _ts(c["timestamp"]))
        times = [_ts(c["timestamp"]) for c in conns]
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        mean_gap = statistics.fmean(gaps)
        if mean_gap < BEACON_MIN_MEAN_GAP_S:
            continue
        cv = statistics.stdev(gaps) / mean_gap if len(gaps) > 1 else 0.0
        sizes = [c["bytes_out"] for c in conns if c.get("bytes_out") is not None]
        size_cv = (statistics.stdev(sizes) / statistics.fmean(sizes)
                   if len(sizes) > 1 and statistics.fmean(sizes) > 0 else None)
        if cv <= max_cv:
            verdict = "likely_beacon"
        elif cv <= POSSIBLE_BEACON_MAX_CV:
            verdict = "possible_beacon"
        else:
            verdict = "irregular"
        results.append({
            "dst_ip": ip, "dst_port": port, "domain": conns[0].get("domain"),
            "connections": len(conns), "mean_interval_s": round(mean_gap, 2),
            "median_interval_s": round(statistics.median(gaps), 2),
            "interval_cv": round(cv, 3), "bytes_out_cv": None if size_cv is None else round(size_cv, 3),
            "verdict": verdict,
            "technique_hints": _web_or_dns_technique(port) if verdict != "irregular" else [],
        })
    return sorted(results, key=lambda r: r["interval_cv"])


# ------------------------------------------------------------------ DNS


def dns_anomalies(queries: list[dict]) -> list[dict]:
    """Flag DGA-looking names, tunneling-sized names, and bursts of failed lookups."""
    findings = []
    nx = []
    for q in queries:
        name = q["query"].rstrip(".").lower()
        labels = name.split(".")
        longest = max(labels, key=len)
        char_entropy = shannon_entropy(longest.encode())
        if not q.get("response_ips"):
            nx.append(name)
        if (len(longest) >= DGA_MIN_LABEL_LEN and char_entropy >= DGA_MIN_CHAR_ENTROPY
                and not name.endswith(CDN_SUFFIXES)):
            findings.append({"flag": "dga_like_name", "query": name,
                             "detail": f"label {longest!r} is long and random-looking "
                                       f"(character entropy {char_entropy:.2f})",
                             "technique_hints": ["T1568.002"]})
        if len(longest) >= TUNNEL_LABEL_LEN or len(name) >= TUNNEL_TOTAL_LEN:
            findings.append({"flag": "possible_dns_tunneling", "query": name[:120],
                             "detail": f"unusually long DNS name ({len(name)} chars), can carry data",
                             "technique_hints": ["T1071.004", "T1048"]})
    if len(nx) >= NXDOMAIN_BURST:
        findings.append({"flag": "nxdomain_burst", "query": ", ".join(nx[:5]),
                         "detail": f"{len(nx)} lookups returned no address (DGA malware tries many names)",
                         "technique_hints": ["T1568.002"]})
    return findings


def all_technique_hints() -> set[str]:
    return {"T1071", "T1071.001", "T1071.004", "T1571", "T1041", "T1568.002", "T1048"}
