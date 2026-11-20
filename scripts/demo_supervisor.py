"""Run the Supervisor (hierarchical delegation) on one or more alerts with real Gemini.

The Supervisor decides which specialists to call, briefs them, and merges
their results. The timeline is indented by delegation depth, so you can follow
who did what, in order. Several alerts run in one process so they share one
rate-limit budget, just like the real quota.

Usage:
    uv run python scripts/demo_supervisor.py examples/alerts/beacon_rundll32.json
    uv run python scripts/demo_supervisor.py examples/alerts/*.json

Writes traces/<alert_id>-supervisor.jsonl (gitignored).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from triage_agents.agents.supervisor import OUTPUT_KEY, build_supervisor
from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.config import api_key_configured, get_settings
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle


async def run_one(path: Path, planner: str) -> bool:
    settings = get_settings()
    alert = AlertBundle.model_validate_json(path.read_text(encoding="utf-8"))
    result = await run_agent(build_supervisor(planner=planner), alert, live_trace=True)
    trace_path = result.trace.write_jsonl(settings.traces_dir / f"{alert.alert_id}-supervisor.jsonl")

    print(f"\n######## {alert.alert_id}: {alert.title}")
    if not result.ok:
        print(f"RUN FAILED: {result.error}\n(partial trace saved to {trace_path})")
    print(f"===== Trace ({settings.model})")
    print(result.trace.format_timeline())
    print("\n===== Merged findings (state['findings'])")
    print(json.dumps(result.state.get(OUTPUT_KEY), indent=2))
    print("\n===== Evidence ledger")
    for e in EvidenceLedger(result.state).all():
        print(f"  {e['id']:6} [{e['tool']}] {e['summary'][:150]}")
    print("\n===== Totals")
    print(json.dumps(result.trace.totals(model=settings.model), indent=2))
    return result.ok


async def run_all(paths: list[Path], planner: str) -> bool:
    results = [await run_one(p, planner) for p in paths]
    return all(results)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("alerts", type=Path, nargs="+")
    parser.add_argument("--planner", choices=["none", "plan_react", "builtin"], default="none")
    args = parser.parse_args()
    if not api_key_configured():
        print("GOOGLE_API_KEY is not set (put it in .env).", file=sys.stderr)
        return 1
    return 0 if asyncio.run(run_all(args.alerts, args.planner)) else 1


if __name__ == "__main__":
    sys.exit(main())
