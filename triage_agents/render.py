"""Plain-text rendering of a triage report, for the CLI."""

from __future__ import annotations

import textwrap

SEVERITY_BADGE = {"informational": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}


def _wrap(text: str, indent: str = "    ") -> str:
    return textwrap.fill(text, width=100, initial_indent=indent, subsequent_indent=indent)


def render_report(report: dict, review_log: list[dict] | None = None) -> str:
    lines = [
        f"Alert {report['alert_id']}   severity: {SEVERITY_BADGE.get(report['severity'], report['severity'])}"
        f"   confidence: {report['confidence']}   revisions: {report.get('revision_rounds', 0)}",
        "",
        _wrap(report["summary"], ""),
        "",
        "Claims (with evidence):",
    ]
    for n, claim in enumerate(report.get("claims", []), 1):
        lines.append(_wrap(f"{n}. {claim['text']}  [{', '.join(claim.get('evidence_ids', [])) or 'no citation'}]", "  "))
    if report.get("techniques"):
        lines += ["", "MITRE ATT&CK (v20.1):"]
        for t in report["techniques"]:
            lines.append(f"  {t['technique_id']:10} {t['name']} ({t['tactic']}), confidence {t['confidence']}"
                         f"  [{', '.join(t.get('evidence_ids', []))}]")
    lines += ["", "Recommended next steps:"]
    lines += [_wrap(f"{n}. {step}", "  ") for n, step in enumerate(report.get("recommended_next_steps", []), 1)]
    if report.get("evidence"):
        lines += ["", "Evidence cited:"]
        lines += [_wrap(f"{e['id']}  ({e['tool']}) {e['summary']}", "  ") for e in report["evidence"]]
    if review_log:
        lines += ["", "Self-reflection log:"]
        lines += [f"  round {r['round']}: critic {r['critic_verdict']} ({r['critic_issues']} issue(s)), "
                  f"automated checks {r['check_issues']} issue(s)" for r in review_log]
    return "\n".join(lines)
