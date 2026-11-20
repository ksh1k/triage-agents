"""Command-line interface.

    triage run examples/alerts/beacon_rundll32.json --trace     # triage one or more alerts
    triage eval                                                 # run + score the labeled evaluation set
    triage serve --port 8080                                    # start the HTTP API
    triage config                                               # show settings (the API key only as set/missing)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .config import api_key_configured, describe, get_settings


def _cmd_run(args) -> int:
    from .pipeline import build_pipeline
    from .render import render_report
    from .runner import run_agent
    from .schemas import AlertBundle

    if not api_key_configured() and not args.cache:
        print("GOOGLE_API_KEY is not set (put it in .env).", file=sys.stderr)
        return 1
    settings = get_settings()
    out_dir = Path(args.out or settings.traces_dir)
    ok = True

    async def run_all():
        nonlocal ok
        for path in args.alerts:
            alert = AlertBundle.model_validate_json(Path(path).read_text(encoding="utf-8"))
            result = await run_agent(build_pipeline(), alert, live_trace=args.live, cache=args.cache or None)
            trace_path = result.trace.write_jsonl(out_dir / f"{alert.alert_id}.trace.jsonl")
            report = result.state.get("report")
            if report:
                (out_dir / f"{alert.alert_id}.report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            if args.json:
                print(json.dumps({"report": report, "error": result.error,
                                  "totals": result.trace.totals(model=settings.model)}, indent=2))
                continue
            print("=" * 100)
            if args.trace:
                print(result.trace.format_timeline())
                print("-" * 100)
            if report:
                print(render_report(report, result.state.get("review_log")))
            if not result.ok:
                ok = False
                print(f"RUN FAILED: {result.error}")
            t = result.trace.totals(model=settings.model)
            cost = t["estimated_cost_usd"] or 0.0
            print(f"\n{t['model_calls']} model calls ({t['api_calls']} API, {t['cached_calls']} cached), "
                  f"{t['total_tokens']:,} tokens, {t['wall_time_s']:.0f}s ({t['rate_limit_wait_s']:.0f}s rate-limit wait), "
                  f"~${cost:.4f} at paid-tier prices. Trace: {trace_path}")

    asyncio.run(run_all())
    return 0 if ok else 1


def _cmd_eval(args) -> int:
    from .evaluation import run_cli  # imported lazily: only needed for this command
    return run_cli(args)


def _cmd_serve(args) -> int:
    import uvicorn
    uvicorn.run("triage_agents.api:app", host=args.host, port=args.port)
    return 0


def _cmd_config(args) -> int:
    print(json.dumps(describe(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="triage", description="Multi-agent security-alert triage (Google ADK + Gemini)")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="triage one or more alert JSON files")
    run.add_argument("alerts", nargs="+", type=Path)
    run.add_argument("--trace", action="store_true", help="print the full agent timeline")
    run.add_argument("--live", action="store_true", help="stream each step to stderr as it happens")
    run.add_argument("--cache", action="store_true", help="record/replay model responses (cache/llm/)")
    run.add_argument("--json", action="store_true", help="print machine-readable JSON")
    run.add_argument("--out", help="where to write report and trace files (default: traces/)")
    run.set_defaults(func=_cmd_run)

    ev = sub.add_parser("eval", help="run the labeled evaluation set")
    ev.add_argument("--alerts", type=Path, default=Path("eval/alerts"))
    ev.add_argument("--only", nargs="*", help="alert IDs to run (default: all)")
    ev.add_argument("--no-cache", action="store_true", help="don't record/replay model responses")
    ev.add_argument("--rescore", action="store_true", help="re-score saved runs without calling any model")
    ev.add_argument("--force", action="store_true", help="re-run alerts that already have a saved run")
    ev.add_argument("--out", type=Path, default=Path("results"))
    ev.set_defaults(func=_cmd_eval)

    serve = sub.add_parser("serve", help="start the HTTP API (POST /triage)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.set_defaults(func=_cmd_serve)

    cfg = sub.add_parser("config", help="show settings")
    cfg.set_defaults(func=_cmd_config)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
