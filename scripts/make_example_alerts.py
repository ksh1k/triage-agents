"""Generate synthetic example alerts with realistic-looking logs (seeded, so reproducible).

All indicators are fake: IPs come from the RFC 5737 documentation ranges,
domains end in .example, and hashes are derived from fixed labels. Nothing
here describes a real host or real malware.

Usage:  uv run python scripts/make_example_alerts.py
"""

from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from triage_agents.schemas import AlertBundle

OUT = Path(__file__).resolve().parent.parent / "examples" / "alerts"
T0 = datetime(2026, 11, 18, 13, 0, 0, tzinfo=timezone.utc)


def fake_hash(label: str) -> str:
    return hashlib.sha256(f"synthetic:{label}".encode()).hexdigest()


def ts(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def beacon_rundll32() -> dict:
    """A DLL run by rundll32 from AppData beacons every ~60 s and runs recon commands.
    The C2 IP, domain and DLL name match past alert PA-2026-0901 (a true positive)."""
    rng = random.Random(4101)
    user = "FIN\\jdoe"
    dll = r"C:\Users\jdoe\AppData\Roaming\Microsoft\Crypto\upd.dll"
    procs = [
        {"timestamp": ts(0), "pid": 2400, "ppid": 612, "image": r"C:\Windows\explorer.exe",
         "command_line": r"C:\Windows\Explorer.EXE", "user": user},
        {"timestamp": ts(35), "pid": 6120, "ppid": 2400, "image": r"C:\Windows\System32\rundll32.exe",
         "command_line": f"rundll32.exe {dll},Start", "user": user},
        {"timestamp": ts(410), "pid": 6400, "ppid": 6120, "image": r"C:\Windows\System32\cmd.exe",
         "command_line": "cmd.exe /c whoami /all", "user": user},
        {"timestamp": ts(470), "pid": 6410, "ppid": 6120, "image": r"C:\Windows\System32\cmd.exe",
         "command_line": 'cmd.exe /c net group "domain admins" /domain', "user": user},
        {"timestamp": ts(540), "pid": 6420, "ppid": 6120, "image": r"C:\Windows\System32\cmd.exe",
         "command_line": "cmd.exe /c nltest /domain_trusts", "user": user},
        {"timestamp": ts(900), "pid": 5000, "ppid": 2400,
         "image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
         "command_line": '"chrome.exe" --profile-directory=Default', "user": user},
    ]
    conns, t = [], 60.0
    for _ in range(24):  # beacon: ~60 s with +/- 4 s jitter, similar small requests
        conns.append({"timestamp": ts(t), "pid": 6120, "src_ip": "10.20.4.37", "dst_ip": "198.51.100.23",
                      "dst_port": 443, "protocol": "tcp", "bytes_out": 400 + rng.randint(0, 40),
                      "bytes_in": 180 + rng.randint(0, 60), "domain": "cdn-sync.badupdate.example"})
        t += 60 + rng.uniform(-4, 4)
    t = 905.0
    for _ in range(12):  # normal browsing: irregular gaps, varied sizes
        conns.append({"timestamp": ts(t), "pid": 5000, "src_ip": "10.20.4.37", "dst_ip": "203.0.113.10",
                      "dst_port": 443, "protocol": "tcp", "bytes_out": rng.randint(600, 4000),
                      "bytes_in": rng.randint(5_000, 400_000), "domain": "news.example"})
        t += rng.expovariate(1 / 40) + 1
    conns.sort(key=lambda c: c["timestamp"])
    dns = [
        {"timestamp": ts(58), "query": "cdn-sync.badupdate.example", "response_ips": ["198.51.100.23"]},
        {"timestamp": ts(903), "query": "news.example", "response_ips": ["203.0.113.10"]},
    ]
    return {
        "alert_id": "DEMO-LOGNET-01",
        "title": "Periodic outbound HTTPS from rundll32.exe to an uncategorized host",
        "source": "NDR+EDR",
        "host": "WS-FIN-11",
        "description": "Network sensor flagged repeated HTTPS sessions from WS-FIN-11 to an uncategorized "
                       "domain. EDR attached the process tree, connections and DNS for the window, plus "
                       "static metadata of the DLL loaded by rundll32.",
        "file": {
            "file_name": "upd.dll",
            "sha256": fake_hash("upd.dll"),
            "size_bytes": 118784,
            "file_type": "PE32+ executable (DLL)",
            "signed": False,
            "imports": {
                "KERNEL32.dll": ["VirtualAlloc", "VirtualProtect", "GetProcAddress", "LoadLibraryA", "Sleep",
                                 "CreateThread"],
                "WINHTTP.dll": ["WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
                                "WinHttpReceiveResponse"],
            },
            "sections": [
                {"name": ".text", "virtual_size": 61440, "raw_size": 61440, "entropy": 6.31},
                {"name": ".rdata", "virtual_size": 24576, "raw_size": 24576, "entropy": 5.02},
                {"name": ".data", "virtual_size": 28672, "raw_size": 28672, "entropy": 7.71},
            ],
            "strings": ["cdn-sync.badupdate.example", "/api/v2/poll?id=%s",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Start", "Global\\upd_mtx_01"],
        },
        "process_events": procs,
        "network_connections": conns,
        "dns_queries": dns,
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for build in (beacon_rundll32,):
        alert = build()
        AlertBundle.model_validate(alert)  # fail loudly if the generator drifts from the schema
        path = OUT / f"{build.__name__}.json"
        path.write_text(json.dumps(alert, indent=1) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(OUT.parent.parent)}")


if __name__ == "__main__":
    main()
