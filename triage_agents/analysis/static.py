"""Static file analysis: entropy, PE parsing, strings, section anomalies.

"Static" means we only read bytes. Nothing here ever runs the file.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pefile

MAX_FILE_BYTES = 50 * 1024 * 1024  # refuse anything bigger than 50 MB
HIGH_ENTROPY = 7.2  # bits/byte; compressed or encrypted data sits around 7.5-8.0
HIGH_WINDOW_ENTROPY = 7.5  # threshold for the hottest 2 KB slice of a section
ENTROPY_WINDOW = 2048
STANDARD_SECTION_NAMES = {
    ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc", ".idata", ".edata",
    ".tls", ".bss", ".CRT", ".xdata", ".didat", ".gfids", ".00cfg", ".buildid",
    # Sections Microsoft's own toolchain emits in Windows system files:
    "fothk", ".mrdata", ".retplne",
}
KNOWN_PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".themida",
                         ".vmp0", ".vmp1", ".petite", ".nsp0", ".nsp1", "MPRESS1"}

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


# ------------------------------------------------------------------ entropy


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: 0.0 (all the same byte) to 8.0 (uniform random).

    H = -sum(p_i * log2(p_i)) over the 256 possible byte values, where p_i is
    how often byte value i appears.
    """
    if not data:
        return 0.0
    n = len(data)
    h = -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
    return h if h > 0 else 0.0  # avoid printing -0.0 when every byte is the same


def max_window_entropy(data: bytes, window: int = ENTROPY_WINDOW, step: int | None = None) -> float:
    """Highest entropy of any `window`-byte slice of `data`.

    A section's overall entropy can look normal while a small encrypted blob
    hides inside it. Scanning in windows finds that blob. Random data
    measured in 2 KB windows comes out around 7.9; x86 code is about 6-6.7.
    """
    if len(data) <= window:
        return shannon_entropy(data)
    step = step or window // 2
    return max(shannon_entropy(data[i:i + window]) for i in range(0, len(data) - window + 1, step))


# ------------------------------------------------------------------ PE parsing


def _section_name(section: pefile.SectionStructure) -> str:
    return section.Name.rstrip(b"\x00").decode("ascii", errors="replace")


def parse_pe(path: str | Path) -> dict:
    """Parse a PE file (EXE/DLL) without executing it.

    Returns a dict with hashes, header fields, sections (with entropy), imports,
    export count, and whether an embedded Authenticode signature is present.
    On failure returns {"status": "error", "error_message": ...}.
    """
    path = Path(path)
    if not path.is_file():
        return {"status": "error", "error_message": f"not a file: {path.name}"}
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        return {"status": "error", "error_message": f"file too large ({size} bytes)"}

    raw = path.read_bytes()
    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except pefile.PEFormatError as exc:
        return {"status": "error", "error_message": f"not a valid PE file: {exc}"}

    try:
        sections = [
            {
                "name": _section_name(s),
                "virtual_size": int(s.Misc_VirtualSize),
                "raw_size": int(s.SizeOfRawData),
                "entropy": round(shannon_entropy(s.get_data()), 3),
                "max_window_entropy": round(max_window_entropy(s.get_data()), 3),
                "executable": bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE),
                "writable": bool(s.Characteristics & IMAGE_SCN_MEM_WRITE),
            }
            for s in pe.sections
        ]

        imports: dict[str, list[str]] = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("ascii", errors="replace")
            names = [
                imp.name.decode("ascii", errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
                for imp in entry.imports
            ]
            imports.setdefault(dll, []).extend(names)

        export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        timestamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc)

        return {
            "status": "success",
            "file_name": path.name,
            "size_bytes": size,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "md5": hashlib.md5(raw).hexdigest(),
            "imphash": pe.get_imphash() or None,
            "is_dll": pe.is_dll(),
            "is_64bit": pe.OPTIONAL_HEADER.Magic == 0x20B,
            "machine": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
            "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "unknown"),
            # Reproducible builds set this to a hash, not a time, so treat it as a hint only.
            "compile_timestamp": timestamp.isoformat(),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "sections": sections,
            "imports": imports,
            "export_count": len(export_dir.symbols) if export_dir else 0,
            # Many Windows system files are catalog-signed, so False here does
            # NOT prove a file is unsigned.
            "embedded_signature_present": security_dir.Size > 0,
            "overall_entropy": round(shannon_entropy(raw), 3),
        }
    finally:
        pe.close()


# ------------------------------------------------------------------ strings

_ASCII_RE_CACHE: dict[int, re.Pattern[bytes]] = {}
_UTF16_RE_CACHE: dict[int, re.Pattern[bytes]] = {}


def extract_strings(data: bytes, min_len: int = 5, max_strings: int = 2000) -> list[str]:
    """Pull printable ASCII and UTF-16LE strings out of raw bytes (like the `strings` tool)."""
    if min_len not in _ASCII_RE_CACHE:
        _ASCII_RE_CACHE[min_len] = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        _UTF16_RE_CACHE[min_len] = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    found = [m.group().decode("ascii") for m in _ASCII_RE_CACHE[min_len].finditer(data)]
    found += [m.group().decode("utf-16le") for m in _UTF16_RE_CACHE[min_len].finditer(data)]
    unique = list(dict.fromkeys(found))  # de-duplicate, keep first-seen order
    return unique[:max_strings]


STRING_RULES: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"\bhttps?://[^\s\"'<>]{4,}", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "registry_run_key": re.compile(r"\\CurrentVersion\\(?:Run|RunOnce|RunServices)\b", re.I),
    "registry_path": re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|Software\\Microsoft)\\", re.I),
    "windows_path": re.compile(r"\b[A-Za-z]:\\[^\s\"']+\.(?:exe|dll|ps1|bat|vbs|js|tmp)\b", re.I),
    "powershell_download": re.compile(
        r"(?:DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|Net\.WebClient|IEX\s*\()", re.I),
    "encoded_command_flag": re.compile(r"\s-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}", re.I),
    "base64_blob": re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}"),
    "llm_prompt_injection": re.compile(
        r"(?:ignore (?:all |any )?(?:previous|prior|above) instructions|"
        r"(?:note|message) to (?:the )?(?:ai|llm|assistant|analyst)|"
        r"(?:classify|mark|report) (?:this|the) (?:file|sample|alert) as (?:benign|clean|safe))",
        re.I),
}


def classify_strings(strings: list[str]) -> dict[str, list[str]]:
    """Group strings into indicator categories. A string can land in several.

    `llm_prompt_injection` flags text that tries to talk to an AI analyst. In
    a binary that is suspicious by itself, and the agents must treat it as
    data, never as an instruction.
    """
    hits: dict[str, list[str]] = {}
    for s in strings:
        for label, pattern in STRING_RULES.items():
            if pattern.search(s):
                hits.setdefault(label, []).append(s[:300])
    return hits


def decode_powershell_encoded(b64: str) -> str | None:
    """Decode a PowerShell -EncodedCommand argument (base64 of UTF-16LE text).

    Decoding is safe: it turns bytes into text and never runs anything.
    Returns None if it isn't valid base64 / UTF-16LE.
    """
    try:
        raw = base64.b64decode(b64, validate=True)
        return raw.decode("utf-16le")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


# ------------------------------------------------------------------ sections


def section_anomalies(sections: list[dict]) -> list[dict]:
    """Flag section-level red flags. Works on parse_pe() output or alert metadata.

    Checks: high entropy (whole section, or one 2 KB region), writable+executable, packer
    section names, non-standard names, and empty-on-disk-but-big-in-memory
    sections (space reserved for unpacked code).
    """
    findings: list[dict] = []
    for s in sections:
        name = s.get("name", "")
        entropy = s.get("entropy")
        window = s.get("max_window_entropy")
        if entropy is not None and entropy >= HIGH_ENTROPY:
            findings.append({"section": name, "anomaly": "high_entropy",
                             "detail": f"entropy {entropy:.2f} >= {HIGH_ENTROPY} suggests packed or encrypted data"})
        elif window is not None and window >= HIGH_WINDOW_ENTROPY:
            findings.append({"section": name, "anomaly": "high_entropy_region",
                             "detail": f"a {ENTROPY_WINDOW}-byte region has entropy {window:.2f} "
                                       f"(section overall {entropy:.2f}): possible embedded encrypted or "
                                       "compressed blob"})
        if s.get("executable") and s.get("writable"):
            findings.append({"section": name, "anomaly": "writable_and_executable",
                             "detail": "section is both writable and executable (self-modifying or unpacking code)"})
        if name in KNOWN_PACKER_SECTIONS:
            findings.append({"section": name, "anomaly": "packer_section_name",
                             "detail": f"section name {name!r} is used by a known packer"})
        elif name and name not in STANDARD_SECTION_NAMES and not name.startswith("/"):
            findings.append({"section": name, "anomaly": "nonstandard_name",
                             "detail": f"section name {name!r} is not a standard compiler section"})
        if s.get("raw_size", 1) == 0 and s.get("virtual_size", 0) > 4096:
            findings.append({"section": name, "anomaly": "empty_on_disk",
                             "detail": "0 bytes on disk but reserves memory (typical of unpacking stubs)"})
    return findings
