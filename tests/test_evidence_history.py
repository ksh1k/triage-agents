"""Evidence ledger IDs and the read-only, parameterized past-alerts database."""

import json
import sqlite3

import pytest

from triage_agents.analysis.attack import get_index
from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.analysis.history import SEED_PATH, PastAlertsDB, build_db

# ---------------------------------------------------------------- evidence ledger


def test_ledger_assigns_per_agent_ids():
    state = {}
    ledger = EvidenceLedger(state)
    assert ledger.add("static_analyst", "parse_pe", ".rsrc entropy 7.9") == "SA-1"
    assert ledger.add("static_analyst", "flag_suspicious_apis", "imports VirtualAllocEx") == "SA-2"
    assert ledger.add("log_network_analyst", "detect_beaconing", "60 s beacon, CV 0.03") == "LN-1"
    assert [e["id"] for e in ledger.all()] == ["SA-1", "SA-2", "LN-1"]
    assert ledger.get("LN-1")["tool"] == "detect_beaconing"
    assert ledger.exists("SA-2") and not ledger.exists("SA-3") and not ledger.exists("E1")


def test_ledger_reassigns_state_keys_instead_of_mutating():
    """ADK only records a state change when the key is assigned. Prove we assign."""

    class RecordingState(dict):
        def __init__(self):
            super().__init__()
            self.assigned = []

        def __setitem__(self, key, value):
            self.assigned.append(key)
            super().__setitem__(key, value)

    state = RecordingState()
    EvidenceLedger(state).add("threat_intel_analyst", "search_attack", "T1055 matches")
    assert state.assigned == ["evidence_TI"]


def test_ledger_rejects_unknown_agent_and_truncates_long_summaries():
    ledger = EvidenceLedger({})
    with pytest.raises(ValueError):
        ledger.add("report_writer", "x", "writers don't produce evidence")
    eid = ledger.add("static_analyst", "extract_strings", "x" * 5000)
    assert len(ledger.get(eid)["summary"]) == 500


# ---------------------------------------------------------------- past-alerts DB


@pytest.fixture()
def db(tmp_path):
    database = PastAlertsDB(db_path=tmp_path / "past.db")
    yield database
    database.close()


def test_lookup_known_domain_case_insensitive(db):
    result = db.lookup_indicator("domain", "UPDATE.Invalid-CDN.example.")
    assert result["match_count"] == 1
    assert result["matches"][0]["alert_id"] == "PA-2026-1003"
    assert result["matches"][0]["verdict"] == "true_positive"


def test_lookup_unknown_and_bad_type(db):
    assert db.lookup_indicator("ip", "203.0.113.254")["match_count"] == 0
    assert db.lookup_indicator("hostname; DROP TABLE alerts", "x")["status"] == "error"


def test_sql_injection_string_is_just_a_value(db):
    assert db.lookup_indicator("domain", "x' OR '1'='1")["match_count"] == 0
    assert db.host_history("' OR 1=1 --")["alert_count"] == 0


def test_connection_is_read_only(db):
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        db._conn.execute("DELETE FROM alerts")


def test_technique_history_counts_verdicts(db):
    h = db.technique_history("t1003.001")
    assert h["verdict_counts"] == {"true_positive": 1, "benign_true_positive": 1}
    fp = db.technique_history("T1071.001")["verdict_counts"]
    assert fp["false_positive"] == 2 and fp["true_positive"] == 1


def test_host_history(db):
    assert db.host_history("ws-hr-03")["alerts"][0]["alert_id"] == "PA-2026-1003"


def test_rebuild_when_seed_is_newer(tmp_path):
    seed = tmp_path / "seed.json"
    data = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    data["alerts"] = data["alerts"][:1]
    seed.write_text(json.dumps(data), encoding="utf-8")
    build_db(seed, tmp_path / "x.db")
    with sqlite3.connect(tmp_path / "x.db") as conn:
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    conn.close()


def test_seed_techniques_are_valid_attack_ids():
    seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    ids = sorted({t for a in seed["alerts"] for t in a["techniques"]})
    result = get_index().validate_ids(ids)
    assert result["invalid"] == [] and result["revoked"] == {}
