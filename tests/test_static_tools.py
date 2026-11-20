"""Static tool wrappers: they read the alert from state, record evidence, and refuse unsafe paths."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.tools import static_tools as st
from triage_agents.tools.common import ALERT_KEY

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = json.loads((ROOT / "tests" / "fixtures" / "minimal_alert.json").read_text(encoding="utf-8"))
LOADER = json.loads((ROOT / "examples" / "alerts" / "loader_demo_sample.json").read_text(encoding="utf-8"))


def ctx(alert: dict | None) -> SimpleNamespace:
    """Stand-in for ADK's ToolContext: the tools only use .state."""
    return SimpleNamespace(state={ALERT_KEY: alert} if alert else {})


def test_overview_records_evidence():
    c = ctx(FIXTURE)
    result = st.get_file_overview(c)
    assert result["status"] == "success" and result["evidence_id"] == "SA-1"
    assert result["imported_function_count"] == 5 and result["sample_available"] is False
    assert "invoice_viewer.exe" in EvidenceLedger(c.state).get("SA-1")["summary"]


def test_tools_handle_alerts_without_a_file():
    c = ctx({"alert_id": "X", "title": "network only", "source": "NDR"})
    for tool in (st.get_file_overview, st.parse_sample_binary, st.analyze_imports,
                 st.analyze_sections, st.analyze_strings):
        assert tool(c)["status"] == "no_file"
    assert EvidenceLedger(c.state).all() == []


def test_metadata_only_imports_sections_strings():
    c = ctx(FIXTURE)
    imports = st.analyze_imports(c)
    assert imports["source"] == "alert metadata"
    assert {"GetProcAddress", "LoadLibrary", "InternetOpen", "InternetReadFile"} <= {
        a["api"] for a in imports["suspicious_apis"]}
    assert imports["combinations"] == []  # VirtualAlloc (no "Ex") is not the injection API
    sections = st.analyze_sections(c)
    assert any(a["anomaly"] == "high_entropy" and a["section"] == ".rsrc" for a in sections["anomalies"])
    strings = st.analyze_strings(c)
    assert {"url", "registry_run_key"} <= set(strings["categories"])
    assert "UNTRUSTED" in strings["note"]
    ids = EvidenceLedger(c.state).ids()
    assert all(i.startswith("SA-") for i in ids) and len(ids) >= 4


def test_parse_sample_then_tools_use_the_real_binary():
    c = ctx(LOADER)
    parsed = st.parse_sample_binary(c)
    assert parsed["status"] == "success" and "hash_mismatch_evidence_id" not in parsed
    assert st.analyze_imports(c)["source"] == "parsed binary"
    strings = st.analyze_strings(c)
    assert "llm_prompt_injection" in strings["categories"]
    injection_eid = strings["categories"]["llm_prompt_injection"]["evidence_id"]
    assert "prompt-injection" in EvidenceLedger(c.state).get(injection_eid)["summary"]


def test_hash_mismatch_is_recorded():
    alert = {**LOADER, "file": {**LOADER["file"], "sha256": "0" * 64}}
    result = st.parse_sample_binary(ctx(alert))
    assert "hash_mismatch_evidence_id" in result


@pytest.mark.parametrize("bad_path", ["../.env", "data/samples/../../.env", "C:/Windows/System32/kernel32.dll",
                                      "/etc/passwd", "README.md"])
def test_sample_paths_outside_allowed_folders_are_refused(bad_path):
    alert = {**LOADER, "file": {**LOADER["file"], "sample_path": bad_path}}
    result = st.parse_sample_binary(ctx(alert))
    assert result["status"] == "error" and "outside the allowed" in result["error_message"]


def test_extra_sample_dir_via_env(monkeypatch, tmp_path):
    exe = tmp_path / "copy.exe"
    exe.write_bytes((ROOT / "data" / "samples" / "bin" / "hello.exe").read_bytes())
    alert = {**LOADER, "file": {**LOADER["file"], "sample_path": str(exe), "sha256": None}}
    assert st.parse_sample_binary(ctx(alert))["status"] == "error"
    monkeypatch.setenv("TRIAGE_SAMPLE_DIRS", str(tmp_path))
    assert st.parse_sample_binary(ctx(alert))["status"] == "success"


def test_decode_powershell_and_lookup_api():
    c = ctx(FIXTURE)
    decoded = st.decode_powershell("SQBFAFgA", c)
    assert decoded["decoded"] == "IEX" and decoded["evidence_id"] == "SA-1"
    assert st.decode_powershell("%%%not base64", c)["status"] == "error"
    assert st.lookup_api("WriteProcessMemory")["part_of_combinations"] == ["remote_process_injection", "process_hollowing"]
    assert st.lookup_api("RegSetValueExW")["api"] == "RegSetValueEx"
    assert st.lookup_api("ReadFile")["status"] == "not_in_rule_table"
