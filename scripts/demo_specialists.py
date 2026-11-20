"""Run the specialist agents on one alert with real Gemini and print what each did.

Specialists run one after another and share session state, so the Threat
Intel agent sees the evidence and findings of the ones before it. (In step 5
the Supervisor decides this delegation itself.)

Usage:
    uv run python scripts/demo_specialists.py examples/alerts/beacon_rundll32.json
    uv run python scripts/demo_specialists.py examples/alerts/loader_demo_sample.json --agents static
    uv run python scripts/demo_specialists.py <alert.json> --planner builtin

Traces go to traces/<alert_id>-<agent>.jsonl (gitignored).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from triage_agents.agents.log_network import build_log_network_analyst
from triage_agents.agents.static_analysis import build_static_analyst
from triage_agents.agents.threat_intel import build_threat_intel_analyst
from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.config import api_key_configured, estimate_cost_usd, get_settings
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle

SPECIALISTS = {
    "static": (build_static_analyst, "static_findings"),
    "lognet": (build_log_network_analyst, "lognet_findings"),
    "intel": (build_threat_intel_analyst, "intel_findings"),
}


async def run_all(alert: AlertBundle, names: list[str], planner: str) -> None:
    settings = get_settings()
    state: dict = {}
    grand = {"model_calls": 0, "input_tokens": 0, "output_tokens": 0, "thinking_tokens": 0, "wall_time_s": 0.0}
    for name in names:
        build, key = SPECIALISTS[name]
        result = await run_agent(build(planner=planner), alert, live_trace=True, initial_state=state)
        state = result.state
        totals = result.trace.totals(model=settings.model)
        for k in grand:
            grand[k] += totals[k]
        print(f"\n===== {name}: trace", file=sys.stderr)
        print(result.trace.format_timeline())
        print(f"\n===== {name}: output (state['{key}'])")
        print(json.dumps(state.get(key), indent=2))
        result.trace.write_jsonl(settings.traces_dir / f"{alert.alert_id}-{name}.jsonl")

    print("\n===== Evidence ledger")
    for e in EvidenceLedger(state).all():
        print(f"  {e['id']:6} [{e['tool']}] {e['summary'][:160]}")
    cost = estimate_cost_usd(settings.model, grand["input_tokens"], grand["output_tokens"] + grand["thinking_tokens"])
    print(f"\n===== Totals ({settings.model}, planner={planner}): {json.dumps(grand)}  "
          f"est. paid-tier cost ${cost:.4f}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("alert", type=Path)
    parser.add_argument("--agents", default="static,lognet,intel",
                        help="comma-separated, in order: static, lognet, intel")
    parser.add_argument("--planner", choices=["none", "plan_react", "builtin"], default="none")
    args = parser.parse_args()
    if not api_key_configured():
        print("GOOGLE_API_KEY is not set (put it in .env).", file=sys.stderr)
        return 1
    names = [n.strip() for n in args.agents.split(",") if n.strip()]
    unknown = set(names) - set(SPECIALISTS)
    if unknown:
        parser.error(f"unknown agents: {sorted(unknown)}")
    alert = AlertBundle.model_validate_json(args.alert.read_text(encoding="utf-8"))
    asyncio.run(run_all(alert, names, args.planner))
    return 0


if __name__ == "__main__":
    sys.exit(main())
