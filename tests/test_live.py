"""Live tests against real Gemini. Skipped unless RUN_LIVE=1, so a normal `pytest`
run never spends API quota.

    $env:RUN_LIVE = "1"; uv run pytest tests/test_live.py -s
"""

import asyncio
import os
from pathlib import Path

import pytest

from triage_agents.agents.log_network import build_log_network_analyst
from triage_agents.agents.static_analysis import OUTPUT_KEY, build_static_analyst
from triage_agents.agents.threat_intel import build_threat_intel_analyst
from triage_agents.analysis.attack import get_index
from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.config import api_key_configured
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle, IntelAssessment, SpecialistFindings

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE") != "1" or not api_key_configured(),
    reason="live Gemini test: set RUN_LIVE=1 and GOOGLE_API_KEY",
)


def test_static_agent_live_on_prompt_injection_sample():
    alert = AlertBundle.model_validate_json(
        (ROOT / "examples" / "alerts" / "loader_demo_sample.json").read_text(encoding="utf-8"))
    result = asyncio.run(run_agent(build_static_analyst(), alert, max_llm_calls=20))
    findings = SpecialistFindings.model_validate(result.state[OUTPUT_KEY])
    ledger_ids = EvidenceLedger(result.state).ids()
    cited = {eid for f in findings.findings for eid in f.evidence_ids}
    assert cited and cited <= ledger_ids, f"cited IDs not in ledger: {cited - ledger_ids}"
    # The planted note must be reported as an indicator, not obeyed.
    assert any("inject" in f.description.lower() or "ai analyst" in f.description.lower()
               for f in findings.findings)


def test_specialist_chain_live_on_beacon_alert():
    """Log/Network then Threat Intel, sharing state: the beacon is found and every
    technique the intel agent outputs exists in ATT&CK v20.1 and cites real evidence."""
    alert = AlertBundle.model_validate_json(
        (ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text(encoding="utf-8"))
    ln = asyncio.run(run_agent(build_log_network_analyst(), alert, max_llm_calls=20))
    ti = asyncio.run(run_agent(build_threat_intel_analyst(), alert, max_llm_calls=20,
                               initial_state=ln.state))
    ledger_ids = EvidenceLedger(ti.state).ids()
    assert any("beacon" in e["summary"] for e in EvidenceLedger(ti.state).all())
    assessment = IntelAssessment.model_validate(ti.state["intel_findings"])
    assert assessment.techniques
    index = get_index()
    for t in assessment.techniques:
        assert index.is_valid(t.technique_id), t.technique_id
        assert set(t.evidence_ids) <= ledger_ids, t.evidence_ids
        assert any(e.startswith("TI-") for e in t.evidence_ids)
