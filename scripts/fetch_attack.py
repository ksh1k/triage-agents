"""Download the pinned MITRE ATT&CK Enterprise bundle and build a compact index.

The raw STIX bundle (~55 MB) goes to data/raw/ (gitignored). The script checks
it against a pinned SHA-256, so a changed or tampered file is refused, then
writes data/attack/enterprise-attack-v20.1.json: one small record per active
technique (no revoked or deprecated ones). The compact index is committed so
the app and tests work offline.

Usage:  uv run python scripts/fetch_attack.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "20.1"
URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       f"enterprise-attack/enterprise-attack-{VERSION}.json")
EXPECTED_SHA256 = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"
RAW = ROOT / "data" / "raw" / f"enterprise-attack-{VERSION}.json"
OUT = ROOT / "data" / "attack" / f"enterprise-attack-v{VERSION}.json"
DESCRIPTION_CHARS = 600


def download() -> None:
    if RAW.exists():
        print(f"using existing {RAW.relative_to(ROOT)}")
        return
    RAW.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {URL}")
    with urllib.request.urlopen(URL, timeout=120) as resp, open(RAW, "wb") as f:
        while chunk := resp.read(1 << 20):
            f.write(chunk)


def verify() -> str:
    digest = hashlib.sha256(RAW.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"SHA-256 mismatch for {RAW.name}: got {digest}, expected {EXPECTED_SHA256}")
    return digest


def clean_description(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text)  # drop "(Citation: Foo 2020)"
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)  # [link text](url) -> link text
    text = re.sub(r"<[^>]+>", "", text)  # stray HTML tags
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= DESCRIPTION_CHARS:
        return text
    cut = text[:DESCRIPTION_CHARS]
    return cut[: cut.rfind(". ") + 1] or cut  # end on a sentence when possible


def build(digest: str) -> dict:
    bundle = json.loads(RAW.read_text(encoding="utf-8"))
    objects = bundle["objects"]

    def mitre_ref(obj):
        return next((r for r in obj.get("external_references", [])
                     if r.get("source_name") == "mitre-attack"), None)

    tactics = {o["x_mitre_shortname"]: o["name"] for o in objects
               if o["type"] == "x-mitre-tactic" and not o.get("x_mitre_deprecated")}
    statements = sorted({o["definition"]["statement"] for o in objects
                         if o["type"] == "marking-definition"
                         and isinstance(o.get("definition"), dict) and "statement" in o["definition"]})

    techniques = []
    for o in objects:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = mitre_ref(o)
        if not ref or not ref.get("external_id", "").startswith("T"):
            continue
        tid = ref["external_id"]
        techniques.append({
            "id": tid,
            "name": o["name"],
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"],
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
            "parent": tid.split(".")[0] if "." in tid else None,
            "platforms": o.get("x_mitre_platforms", []),
            "description": clean_description(o.get("description", "")),
            "url": ref.get("url"),
        })
    techniques.sort(key=lambda t: [int(x) for x in t["id"][1:].split(".")])

    # Old ID -> replacement ID, from STIX "revoked-by" relationships. LLMs
    # trained on older ATT&CK versions still cite the old IDs.
    by_stix_id = {o["id"]: o for o in objects}
    revoked = {}
    for r in objects:
        if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by":
            src, dst = by_stix_id.get(r["source_ref"]), by_stix_id.get(r["target_ref"])
            if src and dst and src["type"] == dst["type"] == "attack-pattern":
                old, new = mitre_ref(src), mitre_ref(dst)
                if old and new:
                    revoked[old["external_id"]] = new["external_id"]
    revoked = dict(sorted(revoked.items()))

    return {
        "attack_version": VERSION,
        "source_url": URL,
        "source_sha256": digest,
        "copyright_statements": statements,
        "terms_of_use": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
        "tactics": tactics,
        "techniques": techniques,
        "revoked": revoked,
    }


def main() -> int:
    download()
    digest = verify()
    index = build(digest)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(index, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    subs = sum(t["is_subtechnique"] for t in index["techniques"])
    print(f"wrote {OUT.relative_to(ROOT)}: {len(index['techniques'])} techniques "
          f"({subs} sub-techniques), {len(index['tactics'])} tactics, "
          f"{len(index['revoked'])} revoked-ID redirects, {OUT.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
