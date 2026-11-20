"""Evaluation scoring: matching rules, statistics, and the paired with/without-Critic comparison."""

import pytest

from triage_agents.evaluation import (
    render_summary,
    score_report,
    score_runs,
    sign_test_p,
    technique_counts,
    technique_match,
    wilson,
)


def test_technique_matching_rules():
    assert technique_match("T1071.001", "T1071.001")
    assert technique_match("T1071", "T1071.001") and technique_match("T1071.001", "T1071")  # parent/sub
    assert not technique_match("T1027.002", "T1027.007")  # siblings never match
    assert not technique_match("T1071", "T1071.001", lenient=False)


def test_technique_counts_precision_and_recall_parts():
    tp, n_pred, matched = technique_counts(["T1218.011", "T1071", "T1105"], ["T1218.011", "T1071.001", "T1033"])
    assert (tp, n_pred, matched) == (2, 3, 2)
    assert technique_counts([], ["T1003.001"]) == (0, 0, 0)


def test_wilson_interval_is_honest_for_small_n():
    lo, hi = wilson(12, 15)
    assert lo == pytest.approx(0.548, abs=0.01) and hi == pytest.approx(0.930, abs=0.01)
    assert wilson(0, 0) == (0.0, 0.0)


def test_sign_test():
    assert sign_test_p(0, 0) == 1.0
    assert sign_test_p(5, 0) == pytest.approx(0.0625)
    assert sign_test_p(3, 3) == 1.0


def report(severity, techniques=(), claims=(("x", ["LN-1"]),)):
    return {"severity": severity, "techniques": [{"technique_id": t} for t in techniques],
            "claims": [{"text": t, "evidence_ids": e} for t, e in claims]}


def test_score_report_fields():
    label = {"severity": "high", "techniques": ["T1055"]}
    s = score_report(report("critical", ["T1055", "T1105"], (("a", ["LN-1"]), ("b", ["LN-9"]))), label, {"LN-1"}, [])
    assert s["severity_within_one"] and not s["severity_exact"] and s["escalate"] and s["label_escalate"]
    assert (s["tech_tp"], s["tech_pred"], s["tech_matched"]) == (1, 2, 1)
    assert (s["claims"], s["valid_claims"]) == (2, 1)
    assert score_report(None, label, set(), []) == {"has_report": False}


def run(alert_id, final_sev, draft_sev, revisions=1, issues_v0=(), final_issues=()):
    return {"alert_id": alert_id, "model": "m", "error": None,
            "report": {**report(final_sev), "revision_rounds": revisions},
            "report_without_critic": report(draft_sev), "check_issues_v0": [{"kind": k} for k in issues_v0],
            "final_issues": [{"kind": k} for k in final_issues], "ledger_ids": ["LN-1"],
            "totals": {"model_calls": 12, "api_calls": 12, "total_tokens": 50_000, "wall_time_s": 40.0,
                       "rate_limit_wait_s": 10.0, "estimated_cost_usd": 0.02},
            "cost": {"reflection_calls": 3, "reflection_tokens": 9_000}}


def test_score_runs_paired_critic_effect_and_summary():
    labels = {"A": {"severity": "high", "techniques": []}, "B": {"severity": "low", "techniques": []},
              "C": {"severity": "critical", "techniques": []}}
    runs = [run("A", "high", "medium", issues_v0=["wrong_tactic"]),  # critic fixed severity
            run("B", "low", "low", revisions=0),
            run("C", "high", "critical")]  # critic made it worse
    rows, summary = score_runs(runs, labels)
    assert summary["with_critic"]["severity_exact"] == 2 and summary["without_critic"]["severity_exact"] == 2
    ce = summary["critic_effect"]
    assert (ce["severity_improved"], ce["severity_worsened"], ce["alerts_revised"]) == (1, 1, 2)
    assert (ce["checker_issues_before"], ce["checker_issues_after"]) == (1, 0)
    assert summary["cost"]["mean_model_calls"] == 12 and summary["cost"]["mean_active_s"] == 30
    md = render_summary(rows, summary, labels, "m")
    assert "| Severity exact match |" in md and "| A | high | high |" in md and "| C | critical | high ~ |" in md
