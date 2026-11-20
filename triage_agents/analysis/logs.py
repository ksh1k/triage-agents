"""Process-log analysis: rebuild the process tree and flag suspicious behavior.

Input events look like Sysmon / EDR process-creation records:
{"timestamp", "pid", "ppid", "image", "command_line", "user"}.

Three kinds of checks:
1. Parent -> child pairs that rarely happen legitimately (Word starting PowerShell).
2. Command-line patterns (encoded PowerShell, download cradles, LOLBins, dumping LSASS).
3. Context: system binaries running from the wrong folder, bursts of recon commands.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import PureWindowsPath

from .static import decode_powershell_encoded

# ------------------------------------------------------------------ helpers


def _ts(value) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value))


def _name(image: str) -> str:
    return PureWindowsPath(image).name.lower()


def _clip(text: str, limit: int = 300) -> str:
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


# ------------------------------------------------------------------ process tree


def build_process_tree(events: list[dict]) -> dict:
    """Link process events into parent/child trees.

    Returns {"roots": [pid, ...], "nodes": {pid: {...event, "children": [...]}},
    "text": an indented, human-readable tree}. A process whose parent is
    missing from the log becomes a root.
    """
    nodes: dict[int, dict] = {}
    for e in sorted(events, key=lambda e: _ts(e["timestamp"])):
        nodes[e["pid"]] = {**e, "children": []}
    roots = []
    for pid, node in nodes.items():
        parent = nodes.get(node["ppid"])
        if parent is not None and parent is not node:
            parent["children"].append(pid)
        else:
            roots.append(pid)

    lines: list[str] = []
    seen: set[int] = set()  # guards against loops if a log reuses PIDs

    def render(pid: int, depth: int) -> None:
        if pid in seen:
            return
        seen.add(pid)
        n = nodes[pid]
        prefix = "" if depth == 0 else "   " * (depth - 1) + "└─ "
        lines.append(f'{prefix}{_name(n["image"])} (pid {pid}) "{_clip(n.get("command_line", ""), 160)}"')
        for child in n["children"]:
            render(child, depth + 1)

    for root in roots:
        render(root, 0)
    return {"roots": roots, "nodes": nodes, "text": "\n".join(lines)}


# ------------------------------------------------------------------ rules

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe"}
SHELLS_AND_LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                      "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}


@dataclass(frozen=True)
class ParentChildRule:
    rule_id: str
    parents: frozenset[str]
    children: frozenset[str]
    description: str
    techniques: tuple[str, ...]
    weight: int


PARENT_CHILD_RULES = [
    ParentChildRule("office_spawns_shell", frozenset(OFFICE), frozenset(SHELLS_AND_LOLBINS),
                    "an Office application started a shell or script host (typical of malicious macros)",
                    ("T1204.002", "T1059"), 3),
    ParentChildRule("browser_spawns_shell", frozenset(BROWSERS), frozenset(SHELLS_AND_LOLBINS),
                    "a web browser started a shell or script host", ("T1189", "T1059"), 2),
    ParentChildRule("wmi_spawns_shell", frozenset({"wmiprvse.exe"}),
                    frozenset({"powershell.exe", "pwsh.exe", "cmd.exe"}),
                    "WMI provider host started a shell (remote WMI execution)", ("T1047",), 2),
    ParentChildRule("script_host_spawns_powershell", frozenset({"wscript.exe", "cscript.exe", "mshta.exe"}),
                    frozenset({"powershell.exe", "pwsh.exe"}),
                    "a script host started PowerShell (multi-stage script)", ("T1059.001",), 2),
]


@dataclass(frozen=True)
class CommandRule:
    rule_id: str
    pattern: re.Pattern[str]
    description: str
    techniques: tuple[str, ...]
    weight: int


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


USER_WRITABLE = r"(?:\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|\\downloads\\)"

COMMAND_RULES = [
    CommandRule("ps_encoded_command", _rx(r"\s-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}"),
                "PowerShell with a base64-encoded command (hides what it runs)", ("T1059.001", "T1027.010"), 2),
    CommandRule("ps_hidden_window", _rx(r"\s-w(?:indowstyle)?\s+hidden\b"),
                "PowerShell started with a hidden window", ("T1564.003",), 2),
    CommandRule("ps_bypass_policy", _rx(r"-(?:ep|executionpolicy)\s+bypass\b"),
                "PowerShell execution policy bypass", ("T1059.001",), 1),
    CommandRule("download_cradle",
                _rx(r"(?:DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|Net\.WebClient|Start-BitsTransfer)"),
                "command downloads content from the network", ("T1105",), 3),
    CommandRule("certutil_download", _rx(r"certutil(?:\.exe)?\b.*-urlcache\b"),
                "certutil used to download a file", ("T1105",), 3),
    CommandRule("certutil_decode", _rx(r"certutil(?:\.exe)?\b.*-decode\b"),
                "certutil used to decode a file", ("T1140",), 2),
    CommandRule("bitsadmin_transfer", _rx(r"bitsadmin(?:\.exe)?\b.*/transfer\b"),
                "BITS job used to transfer a file", ("T1197",), 2),
    CommandRule("mshta_remote", _rx(r"mshta(?:\.exe)?\b.*(?:https?:|javascript:|vbscript:)"),
                "mshta running remote or inline script", ("T1218.005",), 3),
    CommandRule("rundll32_user_path", _rx(r"rundll32(?:\.exe)?\b.*" + USER_WRITABLE + r"[^,\s]*\.(?:dll|dat|tmp|bin)"),
                "rundll32 loading a DLL from a user-writable folder", ("T1218.011",), 3),
    CommandRule("rundll32_script", _rx(r"rundll32(?:\.exe)?\b.*javascript:"),
                "rundll32 executing inline script", ("T1218.011",), 3),
    CommandRule("regsvr32_remote_scriptlet", _rx(r"regsvr32(?:\.exe)?\b.*/i:\s*https?:.*scrobj"),
                "regsvr32 loading a remote scriptlet (Squiblydoo)", ("T1218.010",), 3),
    CommandRule("lsass_dump", _rx(r"(?:procdump(?:64)?(?:\.exe)?\b.*-ma\b.*lsass|comsvcs(?:\.dll)?\W+minidump|lsass\.dmp)"),
                "attempt to dump LSASS memory (credential theft)", ("T1003.001",), 3),
    CommandRule("schtasks_create", _rx(r"schtasks(?:\.exe)?\b.*/create\b"),
                "scheduled task created", ("T1053.005",), 2),
    CommandRule("registry_run_key", _rx(r"\breg(?:\.exe)?\s+add\b.*\\CurrentVersion\\Run"),
                "registry Run key added (starts a program at logon)", ("T1547.001",), 2),
    CommandRule("defender_tamper",
                _rx(r"(?:Set-MpPreference\b.*-Disable|Add-MpPreference\b.*-Exclusion|sc(?:\.exe)?\s+(?:stop|config)\s+WinDefend)"),
                "attempt to disable or weaken Microsoft Defender", ("T1562.001",), 3),
    CommandRule("event_log_clearing", _rx(r"(?:wevtutil(?:\.exe)?\s+cl\b|Clear-EventLog)"),
                "Windows event logs cleared", ("T1070.001",), 3),
    CommandRule("shadow_copy_deletion",
                _rx(r"(?:vssadmin(?:\.exe)?\b.*delete\s+shadows|wmic(?:\.exe)?\b.*shadowcopy\s+delete|wbadmin(?:\.exe)?\b.*delete\s+catalog)"),
                "volume shadow copies deleted (blocks recovery; common before ransomware)", ("T1490",), 3),
]

RECON_RULES = {
    "whoami": (_rx(r"\bwhoami(?:\.exe)?\b"), "T1033"),
    "net_user_group": (_rx(r"\bnet1?(?:\.exe)?\s+(?:user|group|localgroup)\b"), "T1087"),
    "nltest_trusts": (_rx(r"\bnltest(?:\.exe)?\b.*(?:/domain_trusts|/dclist)"), "T1482"),
    "systeminfo": (_rx(r"\bsysteminfo(?:\.exe)?\b"), "T1082"),
    "ipconfig_all": (_rx(r"\bipconfig(?:\.exe)?\s+/all\b"), "T1016"),
}
RECON_BURST_WINDOW = timedelta(minutes=5)
RECON_BURST_MIN = 3

# Where Windows keeps these binaries. Anything else with the same name is masquerading.
SYSTEM_BINARY_DIRS = {
    "svchost.exe": {r"c:\windows\system32", r"c:\windows\syswow64"},
    "lsass.exe": {r"c:\windows\system32"},
    "csrss.exe": {r"c:\windows\system32"},
    "services.exe": {r"c:\windows\system32"},
    "winlogon.exe": {r"c:\windows\system32"},
    "smss.exe": {r"c:\windows\system32"},
    "explorer.exe": {r"c:\windows"},
}


def _finding(rule_id, event, description, techniques, weight, **extra) -> dict:
    return {
        "rule_id": rule_id,
        "pid": event["pid"],
        "image": _name(event["image"]),
        "command_line": _clip(event.get("command_line", "")),
        "description": description,
        "technique_hints": list(techniques),
        "weight": weight,
        **extra,
    }


def _scan_command_line(event: dict, text: str, decoded_from: str | None = None) -> list[dict]:
    found = []
    for rule in COMMAND_RULES:
        if rule.pattern.search(text):
            extra = {"matched_in": "decoded -EncodedCommand payload"} if decoded_from else {}
            found.append(_finding(rule.rule_id, event, rule.description, rule.techniques, rule.weight, **extra))
    return found


def analyze_process_events(events: list[dict]) -> dict:
    """Run every process-log check. Returns the tree text plus a list of findings."""
    tree = build_process_tree(events)
    nodes = tree["nodes"]
    findings: list[dict] = []

    for pid, node in nodes.items():
        parent = nodes.get(node["ppid"])
        child_name = _name(node["image"])

        # 1. Parent -> child
        if parent is not None:
            parent_name = _name(parent["image"])
            for rule in PARENT_CHILD_RULES:
                if parent_name in rule.parents and child_name in rule.children:
                    findings.append(_finding(rule.rule_id, node, rule.description, rule.techniques,
                                             rule.weight, parent=parent_name, parent_pid=parent["pid"]))

        # 2. Command line, plus one level of decoding for -EncodedCommand
        cmd = node.get("command_line", "")
        findings += _scan_command_line(node, cmd)
        enc = re.search(r"\s-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", cmd, re.IGNORECASE)
        if enc:
            decoded = decode_powershell_encoded(enc.group(1))
            if decoded:
                findings.append(_finding("ps_encoded_payload_decoded", node,
                                         "decoded the -EncodedCommand payload (decoded only, never run)",
                                         (), 0, decoded=_clip(decoded)))
                findings += _scan_command_line(node, decoded, decoded_from=enc.group(1))

        # 3a. System binary name outside its real folder
        expected = SYSTEM_BINARY_DIRS.get(child_name)
        folder = str(PureWindowsPath(node["image"]).parent).lower()
        if expected and folder not in expected:
            findings.append(_finding("masquerading_system_binary", node,
                                     f"{child_name} running from {folder} instead of a Windows system folder",
                                     ("T1036.005",), 3))

    # 3b. Several distinct recon commands in a short window
    recon_hits = []
    for node in nodes.values():
        for label, (pattern, technique) in RECON_RULES.items():
            if pattern.search(node.get("command_line", "")):
                recon_hits.append((_ts(node["timestamp"]), label, technique, node))
    recon_hits.sort(key=lambda h: h[0])
    for i, (start, *_rest) in enumerate(recon_hits):
        window = [h for h in recon_hits[i:] if h[0] - start <= RECON_BURST_WINDOW]
        labels = {h[1] for h in window}
        if len(labels) >= RECON_BURST_MIN:
            findings.append(_finding(
                "recon_burst", window[0][3],
                f"{len(labels)} different discovery commands within {RECON_BURST_WINDOW}: {', '.join(sorted(labels))}",
                tuple(sorted({h[2] for h in window})), 2, commands=sorted(labels)))
            break

    return {"tree_text": tree["text"], "process_count": len(nodes), "findings": findings,
            "score": sum(f["weight"] for f in findings)}


def all_technique_hints() -> set[str]:
    ids = {t for r in PARENT_CHILD_RULES for t in r.techniques}
    ids |= {t for r in COMMAND_RULES for t in r.techniques}
    ids |= {t for _p, t in RECON_RULES.values()}
    ids.add("T1036.005")
    return ids
