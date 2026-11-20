"""Run the Static Analysis agent on one alert with real Gemini and print the trace.

Usage:
    uv run python scripts/demo_static_agent.py examples/alerts/loader_demo_sample.json
    uv run python scripts/demo_static_agent.py <alert.json> --planner builtin

Writes the full trace to traces/<alert_id>-<planner>.jsonl (gitignored).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from triage_agents.agents.static_analysis import OUTPUT_KEY, build_static_analyst
from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.config import api_key_configured, get_settings
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("alert", type=Path)
    parser.add_argument("--planner", choices=["plan_react", "builtin", "none"], default="plan_react")
    args = parser.parse_args()
    if not api_key_configured():
        print("GOOGLE_API_KEY is not set (put it in .env).", file=sys.stderr)
        return 1

    alert = AlertBundle.model_validate_json(args.alert.read_text(encoding="utf-8"))
    settings = get_settings()
    agent = build_static_analyst(planner=args.planner)
    result = asyncio.run(run_agent(agent, alert, live_trace=True))

    print(f"=== Trace ({settings.model}, planner={args.planner})")
    print(result.trace.format_timeline())
    print("\n=== Evidence ledger")
    for e in EvidenceLedger(result.state).all():
        print(f"  {e['id']:6} [{e['tool']}] {e['summary'][:150]}")
    print("\n=== Findings (state['static_findings'])")
    print(json.dumps(result.state.get(OUTPUT_KEY), indent=2))
    print("\n=== Totals")
    print(json.dumps(result.trace.totals(model=settings.model), indent=2))
    out = result.trace.write_jsonl(settings.traces_dir / f"{alert.alert_id}-{args.planner}.jsonl")
    print(f"\ntrace written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
