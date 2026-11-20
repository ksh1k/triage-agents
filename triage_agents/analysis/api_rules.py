"""Map imported Windows API functions to capabilities and ATT&CK technique hints.

One import proves nothing on its own: benign programs call GetProcAddress all
the time. So each API gets a weight (1 = common in benign software, 3 = rarely
benign), and certain *combinations* (e.g. the classic remote-injection trio)
raise their own, stronger finding.

The technique IDs are hints for the Threat Intel agent, not verdicts. A test
checks that every ID here exists in the pinned ATT&CK dataset.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ApiRule:
    capability: str
    weight: int  # 1 = weak signal, 2 = moderate, 3 = strong
    techniques: tuple[str, ...]


# Keys are base names: the A/W (ANSI/Unicode) suffix is stripped before lookup.
API_RULES: dict[str, ApiRule] = {
    # Process injection
    "VirtualAllocEx": ApiRule("process_injection", 3, ("T1055",)),
    "WriteProcessMemory": ApiRule("process_injection", 3, ("T1055",)),
    "CreateRemoteThread": ApiRule("process_injection", 3, ("T1055",)),
    "NtUnmapViewOfSection": ApiRule("process_injection", 3, ("T1055.012",)),
    "SetThreadContext": ApiRule("process_injection", 2, ("T1055.012",)),
    "QueueUserAPC": ApiRule("process_injection", 2, ("T1055.004",)),
    # Hiding imports / calling the OS directly
    "GetProcAddress": ApiRule("dynamic_api_resolution", 1, ("T1027.007",)),
    "LoadLibrary": ApiRule("dynamic_api_resolution", 1, ("T1027.007",)),
    "LoadLibraryEx": ApiRule("dynamic_api_resolution", 1, ("T1027.007",)),
    # Anti-analysis
    "IsDebuggerPresent": ApiRule("anti_debugging", 1, ("T1622",)),
    "CheckRemoteDebuggerPresent": ApiRule("anti_debugging", 2, ("T1622",)),
    "NtQueryInformationProcess": ApiRule("anti_debugging", 2, ("T1622",)),
    # Keylogging / input capture
    "SetWindowsHookEx": ApiRule("keylogging", 2, ("T1056.001",)),
    "GetAsyncKeyState": ApiRule("keylogging", 2, ("T1056.001",)),
    # Persistence
    "RegSetValueEx": ApiRule("registry_modification", 1, ("T1547.001",)),
    "CreateService": ApiRule("service_persistence", 2, ("T1543.003",)),
    # Network / download
    "URLDownloadToFile": ApiRule("download", 3, ("T1105",)),
    "InternetOpen": ApiRule("http_client", 1, ("T1071.001",)),
    "InternetOpenUrl": ApiRule("http_client", 2, ("T1071.001", "T1105")),
    "InternetReadFile": ApiRule("http_client", 1, ("T1105",)),
    "HttpSendRequest": ApiRule("http_client", 1, ("T1071.001",)),
    "WinHttpOpen": ApiRule("http_client", 1, ("T1071.001",)),
    # Credential access
    "MiniDumpWriteDump": ApiRule("credential_dumping", 3, ("T1003.001",)),
    # Privilege
    "AdjustTokenPrivileges": ApiRule("token_manipulation", 2, ("T1134",)),
    "ImpersonateLoggedOnUser": ApiRule("token_manipulation", 2, ("T1134.001",)),
    # Encryption (ransomware-adjacent, but also normal crypto)
    "CryptEncrypt": ApiRule("encryption", 1, ("T1486",)),
    "BCryptEncrypt": ApiRule("encryption", 1, ("T1486",)),
    # Execution / discovery (very common, weak on their own)
    "CreateProcess": ApiRule("process_creation", 1, ("T1106",)),
    "WinExec": ApiRule("process_creation", 2, ("T1106",)),
    "ShellExecute": ApiRule("process_creation", 1, ("T1106",)),
    "CreateToolhelp32Snapshot": ApiRule("process_discovery", 1, ("T1057",)),
    "GetClipboardData": ApiRule("clipboard_access", 1, ("T1115",)),
}

COMBINATIONS: list[dict] = [
    {
        "name": "remote_process_injection",
        "requires": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
        "techniques": ("T1055",),
        "detail": "allocate + write + start a thread in another process: classic remote injection",
    },
    {
        "name": "process_hollowing",
        "requires": {"NtUnmapViewOfSection", "WriteProcessMemory", "SetThreadContext"},
        "techniques": ("T1055.012",),
        "detail": "unmap + write + redirect a thread: process hollowing",
    },
    {
        "name": "download_and_execute",
        "requires": {"URLDownloadToFile", "WinExec"},
        "techniques": ("T1105",),
        "detail": "download a file then run it",
    },
]


def normalize_api_name(name: str) -> str:
    """'RegSetValueExW' -> 'RegSetValueEx', 'LoadLibraryA' -> 'LoadLibrary'."""
    if name in API_RULES:
        return name
    if len(name) > 1 and name[-1] in "AW" and name[:-1] in API_RULES:
        return name[:-1]
    return name


def flag_suspicious_apis(imports: dict[str, list[str]]) -> dict:
    """Score a file's imports.

    Args:
        imports: DLL name -> list of imported function names (as in parse_pe output).

    Returns a dict with the matched APIs (capability, weight, technique hints),
    any matched combinations, and a total score: the sum of weights, plus 5 per
    combination.
    """
    imported: dict[str, str] = {}  # base name -> DLL it came from
    for dll, functions in imports.items():
        for fn in functions:
            imported.setdefault(normalize_api_name(fn), dll)

    matches = [
        {"api": api, "dll": imported[api], "capability": rule.capability,
         "weight": rule.weight, "technique_hints": list(rule.techniques)}
        for api, rule in API_RULES.items() if api in imported
    ]
    combos = [
        {"name": c["name"], "apis": sorted(c["requires"]), "technique_hints": list(c["techniques"]),
         "detail": c["detail"]}
        for c in COMBINATIONS if c["requires"] <= imported.keys()
    ]
    score = sum(m["weight"] for m in matches) + 5 * len(combos)
    return {
        "suspicious_apis": sorted(matches, key=lambda m: -m["weight"]),
        "combinations": combos,
        "score": score,
        "capabilities": sorted({m["capability"] for m in matches}),
    }


def all_technique_hints() -> set[str]:
    """Every technique ID referenced above (used by tests to validate against ATT&CK)."""
    ids = {t for rule in API_RULES.values() for t in rule.techniques}
    ids |= {t for c in COMBINATIONS for t in c["techniques"]}
    return ids
