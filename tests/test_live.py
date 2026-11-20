"""Live tests against real Gemini. Skipped unless RUN_LIVE=1, so a normal `pytest`
run never spends API quota.

    $env:RUN_LIVE = "1"; uv run pytest tests/test_live.py -s
"""

import asyncio
import os
from pathlib import Path

import pytest

from triage_agents.agents.static_analysis import OUTPUT_KEY, build_static_analyst
from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.config import api_key_configured
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle, SpecialistFindings

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
