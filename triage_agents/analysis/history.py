"""Past-alert history in SQLite: "have we seen this indicator / technique / host before?"

The agents never get a raw SQL tool. The LLM can only call fixed lookups
whose values are bound as SQL parameters, and the connection is opened
read-only. A prompt-injected value like "x' OR '1'='1" is just a string that
matches nothing. The only code that writes to the database is the seed
builder below.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
SEED_PATH = DATA_DIR / "past_alerts_seed.json"
DB_PATH = DATA_DIR / "past_alerts.db"

INDICATOR_TYPES = ("sha256", "md5", "ip", "domain", "filename")
VERDICTS = ("true_positive", "false_positive", "benign_true_positive")
MAX_ROWS = 20

SCHEMA = f"""
CREATE TABLE alerts (
    alert_id     TEXT PRIMARY KEY,
    closed_at    TEXT NOT NULL,
    host         TEXT NOT NULL,
    title        TEXT NOT NULL,
    verdict      TEXT NOT NULL CHECK (verdict IN {VERDICTS}),
    severity     TEXT NOT NULL,
    analyst_note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE indicators (
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
    type     TEXT NOT NULL CHECK (type IN {INDICATOR_TYPES}),
    value    TEXT NOT NULL,
    PRIMARY KEY (alert_id, type, value)
);
CREATE TABLE alert_techniques (
    alert_id     TEXT NOT NULL REFERENCES alerts(alert_id),
    technique_id TEXT NOT NULL,
    PRIMARY KEY (alert_id, technique_id)
);
CREATE INDEX idx_indicator_lookup ON indicators(type, value);
CREATE INDEX idx_technique_lookup ON alert_techniques(technique_id);
CREATE INDEX idx_host_lookup ON alerts(host);
"""


def normalize_indicator(kind: str, value: str) -> str:
    """Hashes, domains and file names compare case-insensitively; IPs as given."""
    value = value.strip()
    return value if kind == "ip" else value.lower().rstrip(".")


def build_db(seed_path: Path = SEED_PATH, db_path: Path = DB_PATH) -> Path:
    """(Re)create the SQLite file from the JSON seed."""
    seed = json.loads(Path(seed_path).read_text(encoding="utf-8"))
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = db_path.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    with sqlite3.connect(tmp) as conn:
        conn.executescript(SCHEMA)
        for a in seed["alerts"]:
            conn.execute("INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (a["alert_id"], a["closed_at"], a["host"].upper(), a["title"],
                          a["verdict"], a["severity"], a.get("analyst_note", "")))
            conn.executemany("INSERT INTO indicators VALUES (?, ?, ?)",
                             [(a["alert_id"], i["type"], normalize_indicator(i["type"], i["value"]))
                              for i in a["indicators"]])
            conn.executemany("INSERT INTO alert_techniques VALUES (?, ?)",
                             [(a["alert_id"], t.upper()) for t in a["techniques"]])
    conn.close()
    tmp.replace(db_path)  # swap in atomically so readers never see a half-built file
    return db_path


class PastAlertsDB:
    def __init__(self, db_path: Path = DB_PATH, seed_path: Path = SEED_PATH):
        db_path = Path(db_path)
        if not db_path.exists() or (Path(seed_path).exists()
                                    and Path(seed_path).stat().st_mtime > db_path.stat().st_mtime):
            build_db(seed_path, db_path)
        # mode=ro: SQLite itself refuses any write on this connection.
        self._conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True,
                                     check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def close(self) -> None:
        self._conn.close()

    def _rows(self, sql: str, params: tuple) -> list[dict]:
        return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def lookup_indicator(self, kind: str, value: str) -> dict:
        """Past alerts that contained this exact indicator (hash, IP, domain, or file name)."""
        if kind not in INDICATOR_TYPES:
            return {"status": "error", "error_message": f"type must be one of {list(INDICATOR_TYPES)}"}
        rows = self._rows(
            """SELECT a.alert_id, a.closed_at, a.host, a.title, a.verdict, a.severity, a.analyst_note
               FROM indicators i JOIN alerts a USING (alert_id)
               WHERE i.type = ? AND i.value = ?
               ORDER BY a.closed_at DESC LIMIT ?""",
            (kind, normalize_indicator(kind, value), MAX_ROWS))
        return {"status": "success", "type": kind, "value": value, "match_count": len(rows), "matches": rows}

    def technique_history(self, technique_id: str) -> dict:
        """How past alerts with this technique were resolved (counts per verdict + recent examples)."""
        tid = technique_id.strip().upper()
        counts = {r["verdict"]: r["n"] for r in self._rows(
            """SELECT a.verdict, COUNT(*) AS n FROM alert_techniques t JOIN alerts a USING (alert_id)
               WHERE t.technique_id = ? GROUP BY a.verdict""", (tid,))}
        recent = self._rows(
            """SELECT a.alert_id, a.closed_at, a.host, a.title, a.verdict, a.severity
               FROM alert_techniques t JOIN alerts a USING (alert_id)
               WHERE t.technique_id = ? ORDER BY a.closed_at DESC LIMIT 5""", (tid,))
        return {"status": "success", "technique_id": tid, "verdict_counts": counts, "recent": recent}

    def host_history(self, host: str) -> dict:
        """Recent past alerts on the same host."""
        rows = self._rows(
            """SELECT alert_id, closed_at, title, verdict, severity FROM alerts
               WHERE host = ? ORDER BY closed_at DESC LIMIT ?""", (host.strip().upper(), MAX_ROWS))
        return {"status": "success", "host": host, "alert_count": len(rows), "alerts": rows}
