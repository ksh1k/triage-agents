"""Network analysis: internal-IP logic, beaconing statistics, DNS heuristics."""

import random
from datetime import datetime, timedelta, timezone

import pytest

from triage_agents.analysis.network import (
    detect_beaconing,
    dns_anomalies,
    is_internal_ip,
    summarize_connections,
)

START = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def conns(gaps, dst="203.0.113.50", port=443, bytes_out=512):
    t, out = START, []
    for gap in [0, *gaps]:
        t += timedelta(seconds=gap)
        out.append({"timestamp": t.isoformat(), "pid": 99, "src_ip": "10.0.0.5", "dst_ip": dst,
                    "dst_port": port, "bytes_out": bytes_out, "bytes_in": 128})
    return out


@pytest.mark.parametrize("ip,internal", [
    ("10.1.2.3", True), ("192.168.1.10", True), ("172.20.0.1", True), ("127.0.0.1", True),
    ("8.8.8.8", False),
    # Documentation ranges stand in for internet hosts in our synthetic data,
    # even though Python's ipaddress.is_private calls them private.
    ("203.0.113.50", False), ("198.51.100.7", False), ("192.0.2.1", False),
    ("not-an-ip", False),
])
def test_is_internal_ip(ip, internal):
    assert is_internal_ip(ip) is internal


def test_regular_timer_with_small_jitter_is_a_likely_beacon():
    rng = random.Random(7)
    gaps = [60 + rng.uniform(-3, 3) for _ in range(30)]  # every 60 s, +/- 5% jitter
    [result] = detect_beaconing(conns(gaps))
    assert result["verdict"] == "likely_beacon"
    assert result["interval_cv"] < 0.05
    assert result["mean_interval_s"] == pytest.approx(60, abs=2)
    assert result["technique_hints"] == ["T1071.001"]


def test_random_human_like_gaps_are_irregular():
    rng = random.Random(8)
    gaps = [rng.expovariate(1 / 90) + 1 for _ in range(40)]  # exponential gaps: CV ~ 1
    [result] = detect_beaconing(conns(gaps))
    assert result["verdict"] == "irregular"
    assert result["interval_cv"] > 0.5


def test_too_few_connections_are_not_judged():
    assert detect_beaconing(conns([60, 60, 60])) == []


def test_internal_destinations_are_ignored():
    assert detect_beaconing(conns([60] * 20, dst="10.0.0.1")) == []


def test_sub_second_bursts_are_not_beacons():
    assert detect_beaconing(conns([0.1] * 20)) == []


def test_summary_flags_uncommon_port_and_large_upload():
    data = conns([5], port=4444) + conns([5], dst="198.51.100.20", bytes_out=8 * 1024 * 1024)
    summary = summarize_connections(data)
    flags = {f["flag"] for f in summary["flags"]}
    assert flags == {"uncommon_port", "large_upload"}
    assert summary["external_destination_count"] == 2


def q(name, ips=("203.0.113.1",)):
    return {"timestamp": START.isoformat(), "query": name, "response_ips": list(ips)}


def test_dns_dga_like_and_normal_names():
    hits = dns_anomalies([q("xkqj2v9fz7wq1p3m.example"), q("www.example.com"), q("mail.google.com")])
    assert [h["query"] for h in hits if h["flag"] == "dga_like_name"] == ["xkqj2v9fz7wq1p3m.example"]


def test_dns_cdn_hashes_are_not_called_dga():
    assert dns_anomalies([q("d3k81ch9hvuctc.cloudfront.net")]) == []


def test_dns_tunneling_sized_name():
    name = "a" * 20 + "4f6e652074776f2074687265652066" * 3 + ".t.example"
    assert any(h["flag"] == "possible_dns_tunneling" for h in dns_anomalies([q(name)]))


def test_dns_nxdomain_burst():
    queries = [q(f"host{i}.example", ips=()) for i in range(6)]
    assert any(h["flag"] == "nxdomain_burst" for h in dns_anomalies(queries))
