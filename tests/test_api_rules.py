"""API rules: normalization, scoring, and combination detection."""

from triage_agents.analysis.api_rules import flag_suspicious_apis, normalize_api_name


def test_normalize_strips_ansi_and_unicode_suffixes():
    assert normalize_api_name("RegSetValueExW") == "RegSetValueEx"
    assert normalize_api_name("LoadLibraryA") == "LoadLibrary"
    assert normalize_api_name("GetProcAddress") == "GetProcAddress"
    assert normalize_api_name("ReadFileW") == "ReadFileW"  # unknown API: left alone


def test_benign_imports_score_zero():
    result = flag_suspicious_apis({"KERNEL32.dll": ["ExitProcess", "GetLastError", "ReadFile"]})
    assert result["score"] == 0 and result["suspicious_apis"] == [] and result["combinations"] == []


def test_injection_trio_triggers_combination():
    result = flag_suspicious_apis({
        "KERNEL32.dll": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    })
    assert [c["name"] for c in result["combinations"]] == ["remote_process_injection"]
    assert "process_injection" in result["capabilities"]
    assert result["score"] == 3 + 3 + 3 + 5


def test_weak_signals_stay_weak():
    result = flag_suspicious_apis({"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress"]})
    assert result["score"] == 2
    assert result["combinations"] == []


def test_strongest_matches_listed_first():
    result = flag_suspicious_apis({"KERNEL32.dll": ["GetProcAddress"], "urlmon.dll": ["URLDownloadToFileW"]})
    assert result["suspicious_apis"][0]["api"] == "URLDownloadToFile"
    assert result["suspicious_apis"][0]["dll"] == "urlmon.dll"
