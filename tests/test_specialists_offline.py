"""Log/Network and Threat Intel agents end to end with a scripted fake model (no API calls).
The Threat Intel run starts from the state the Log/Network run left behind, the way
the Supervisor will chain them in step 5."""

import asyncio
from pathlib import Path

from triage_agents.agents.log_network import OUTPUT_KEY as LN_KEY
from triage_agents.agents.log_network import build_log_network_analyst
from triage_agents.agents.threat_intel import OUTPUT_KEY as TI_KEY
from triage_agents.agents.threat_intel import build_threat_intel_analyst
from triage_agents.analysis.evidence import EvidenceLedger
from triage_agents.runner import run_agent
from triage_agents.schemas import AlertBundle, IntelAssessment, SpecialistFindings

from .fakes import ScriptedLlm, call, calls, function_responses

ROOT = Path(__file__).resolve().parent.parent
ALERT = AlertBundle.model_validate_json((ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text())

LN_OUTPUT = {
    "agent": "log_network_analyst",
    "summary": "rundll32 runs a DLL from AppData that beacons every ~60 s and ran recon commands.",
    "findings": [
        {"description": "rundll32 loads DLL from AppData", "evidence_ids": ["LN-2"],
         "technique_hints": ["T1218.011"], "signal": "strong"},
        {"description": "60 s beacon to 198.51.100.23:443", "evidence_ids": ["LN-4"],
         "technique_hints": ["T1071.001"], "signal": "strong"},
    ],
    "benign_explanations": [], "gaps": [],
}

TI_OUTPUT = {
    "agent": "threat_intel_analyst",
    "summary": "Rundll32 proxy execution with web-protocol C2; IP matches a past true positive.",
    "techniques": [
        {"technique_id": "T1218.011", "name": "Rundll32", "tactic": "stealth",
         "evidence_ids": ["LN-2", "TI-1"], "confidence": "high"},
    ],
    "rejected_hints": [],
    "history": [{"description": "IP seen in PA-2026-0901 (true positive)", "evidence_ids": ["TI-2"],
                 "technique_hints": [], "signal": "strong"}],
    "gaps": [],
}


def run_lognet():
    llm = ScriptedLlm(script=[
        call("get_activity_overview"), call("analyze_process_tree"),
        calls(("summarize_network", {}), ("check_beaconing", {}), ("analyze_dns", {})),
        call("lookup_process", pid=6120), call("set_model_response", **LN_OUTPUT)])
    return llm, asyncio.run(run_agent(build_log_network_analyst(model=llm), ALERT))


def test_lognet_agent_runs_tools_and_returns_findings():
    llm, result = run_lognet()
    assert SpecialistFindings.model_validate(result.state[LN_KEY]).agent == "log_network_analyst"
    # The lookup_process call carried an argument chosen by the model.
    drill = function_responses(llm.requests[4])[-1]
    assert drill.name == "lookup_process" and drill.response["pid"] == 6120
    assert {"LN-1", "LN-2", "LN-3", "LN-4"} <= EvidenceLedger(result.state).ids()


def test_intel_agent_builds_on_lognet_state():
    _, ln_result = run_lognet()
    llm = ScriptedLlm(script=[
        calls(("get_specialist_findings", {}), ("get_alert_indicators", {})),
        call("get_technique", technique_id="T1218.011"),
        call("check_indicator_history", indicator_type="ip", value="198.51.100.23"),
        call("set_model_response", **TI_OUTPUT)])
    result = asyncio.run(run_agent(build_threat_intel_analyst(model=llm), ALERT,
                                   initial_state=ln_result.state))
    seen = function_responses(llm.requests[1])[0].response
    assert seen["technique_hints"] == ["T1071.001", "T1218.011"]  # read the Log/Network output
    assessment = IntelAssessment.model_validate(result.state[TI_KEY])
    assert assessment.techniques[0].technique_id == "T1218.011"
    ledger = EvidenceLedger(result.state)
    assert ledger.get("TI-1")["tool"] == "get_technique"
    assert ledger.get("TI-2")["tool"] == "check_indicator_history"
    assert ledger.exists("LN-2")  # earlier evidence carried over
