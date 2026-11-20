"""ATT&CK index: lookups, validation, search, and that every hint our rules emit is real."""

import pytest

from triage_agents.analysis import api_rules, logs, network
from triage_agents.analysis.attack import get_index


@pytest.fixture(scope="module")
def idx():
    return get_index()


def test_index_is_the_pinned_version(idx):
    assert idx.version == "20.1"
    assert len(idx) > 600
    assert any("MITRE" in s for s in idx.copyright)


def test_get_known_technique(idx):
    t = idx.get("T1055")
    assert t["name"] == "Process Injection"
    assert idx.get(" t1059.001 ")["name"] == "PowerShell"  # case and spaces don't matter
    assert idx.get("T1059.001")["parent"] == "T1059"


def test_unknown_or_malformed_ids_are_invalid(idx):
    assert idx.get("T9999") is None
    assert not idx.is_valid("T1055.999")
    assert idx.validate_ids(["T1055", "T9999", "banana"]) == {
        "valid": ["T1055"], "revoked": {}, "invalid": ["T9999", "BANANA"]}


def test_revoked_ids_point_to_their_replacement(idx):
    """v20 revoked these. Older-trained LLMs still cite them, so we redirect instead of just rejecting."""
    assert idx.get("T1562.001") is None
    assert idx.replacement_for("T1562.001") == "T1685"
    assert idx.validate_ids(["T1070.001"])["revoked"] == {"T1070.001": "T1685.005"}
    assert idx.get("T1685.005")["name"] == "Clear Windows Event Logs"


def test_revoked_and_deprecated_are_excluded(idx):
    # The index only keeps active techniques, so every entry has a tactic.
    assert all(t["tactics"] for t in idx._by_id.values())


def test_search_by_keyword(idx):
    top = [r["id"] for r in idx.search("powershell", limit=3)]
    assert "T1059.001" in top
    assert idx.search("process injection")[0]["id"] == "T1055"


def test_search_exact_id_and_tactic_filter(idx):
    assert idx.search("T1218.011")[0]["name"] == "Rundll32"
    results = idx.search("scheduled task", tactic="persistence")
    assert results and all("persistence" in r["tactics"] for r in results)


def test_search_with_no_useful_words(idx):
    assert idx.search("the and of") == []


@pytest.mark.parametrize("module", [api_rules, logs, network], ids=lambda m: m.__name__.split(".")[-1])
def test_every_rule_technique_hint_exists_in_attack(idx, module):
    """If ATT&CK renames or revokes something, this fails instead of the agents citing a dead ID."""
    hints = module.all_technique_hints()
    invalid = idx.validate_ids(sorted(hints))["invalid"]
    assert invalid == [], f"technique hints not in ATT&CK v{idx.version}: {invalid}"
