"""Rebuild data/past_alerts.db from data/past_alerts_seed.json.

The app also rebuilds it automatically when the DB is missing or the seed
is newer, so running this by hand is optional.

Usage:  uv run python scripts/seed_past_alerts.py
"""

import sqlite3
import sys

from triage_agents.analysis.history import DB_PATH, build_db


def main() -> int:
    path = build_db()
    with sqlite3.connect(path) as conn:
        alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        indicators = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    conn.close()
    print(f"built {DB_PATH.name}: {alerts} past alerts, {indicators} indicators")
    return 0


if __name__ == "__main__":
    sys.exit(main())
