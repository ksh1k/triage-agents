"""HTTP API: request validation, hardening, and a full triage through a scripted pipeline."""

import json
from pathlib import Path

from fastapi.testclient import TestClient
from google.adk import Agent

from triage_agents.agents.critic import build_critic
from triage_agents.agents.report_writer import build_report_writer
from triage_agents.api import create_app
from triage_agents.pipeline import build_pipeline
from triage_agents.schemas import MergedFindings
from triage_agents.tools.planning import record_plan

from .fakes import ScriptedLlm, call, say
from .test_pipeline_offline import APPROVE, MERGED

ROOT = Path(__file__).resolve().parent.parent
ALERT = json.loads((ROOT / "examples" / "alerts" / "beacon_rundll32.json").read_text(encoding="utf-8"))

DRAFT = {
    "alert_id": "DEMO-LOGNET-01", "severity": "high", "confidence": "medium",
    "summary": "Reported beaconing from rundll32.",
    "claims": [{"text": "The EDR reported periodic HTTPS from rundll32.", "evidence_ids": ["AL-1"]}],
    "techniques": [], "recommended_next_steps": ["Isolate the host"],
}


def scripted_pipeline():
    supervisor = Agent(name="supervisor", model=ScriptedLlm(script=[call("set_model_response", **MERGED)]),
                       instruction="merge", tools=[record_plan], output_schema=MergedFindings, output_key="findings")
    return build_pipeline(supervisor=supervisor,
                          report_writer=build_report_writer(ScriptedLlm(script=[say(json.dumps(DRAFT))])),
                          critic=build_critic(ScriptedLlm(script=[say(json.dumps(APPROVE))])))


client = TestClient(create_app(pipeline_factory=scripted_pipeline))


def test_healthz_never_reveals_the_key():
    body = client.get("/healthz").json()
    assert body["status"] == "ok" and body["google_api_key"] in {"set", "missing"}
    assert "AIza" not in json.dumps(body)


def test_triage_returns_report_and_metrics():
    resp = client.post("/triage", json=ALERT, params={"include_trace": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["alert_id"] == "DEMO-LOGNET-01" and body["report"]["severity"] == "high"
    assert body["report"]["evidence"][0]["id"] == "AL-1"
    assert body["review_log"][0]["critic_verdict"] == "approve"
    assert body["metrics"]["model_calls"] == 3 and body["trace"]


def test_invalid_alert_is_rejected_by_schema():
    resp = client.post("/triage", json={**ALERT, "unexpected_field": 1})
    assert resp.status_code == 422


def test_sample_path_is_refused_over_http():
    alert = {**ALERT, "file": {**ALERT["file"], "sample_path": "data/samples/bin/hello.exe"}}
    resp = client.post("/triage", json=alert)
    assert resp.status_code == 400 and "sample_path" in resp.json()["detail"]


def test_oversized_alert_is_refused():
    alert = {**ALERT, "dns_queries": ALERT["dns_queries"] * 2600}
    assert client.post("/triage", json=alert).status_code == 413
