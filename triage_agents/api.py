"""HTTP API: POST /triage runs the full multi-agent pipeline on one alert.

    uvicorn triage_agents.api:app --port 8080      (or: triage serve)

Hardening for a service that ingests attacker-influenced data:
- Input is validated against the AlertBundle schema (unknown fields rejected).
- `file.sample_path` is refused over HTTP: the static tools only read allow-listed
  local folders, and a remote client shouldn't be able to point the server at files.
  Send static metadata (imports, sections, strings) instead.
- Size limits on every list, so one request can't make the agents read megabytes.
- Each request gets its own App, Runner and trace; the rate limiter is shared
  process-wide, so concurrent requests queue for the same Gemini quota.
- The API key comes from the environment (Cloud Run: Secret Manager) and is never
  returned; /healthz reports only whether it is set.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import __version__
from .config import api_key_configured, get_settings
from .schemas import AlertBundle, TriageReport

LIMITS = {"process_events": 2_000, "network_connections": 10_000, "dns_queries": 5_000}
FILE_LIMITS = {"strings": 5_000, "sections": 200}


class TriageResponse(BaseModel):
    run_id: str
    alert_id: str
    report: TriageReport | None
    error: str | None = None
    review_log: list[dict] = []
    residual_issues: list[dict] = []
    delegations: list[dict] = []
    metrics: dict[str, Any]
    trace: list[dict] | None = None


def _validate_limits(alert: AlertBundle) -> None:
    for field, limit in LIMITS.items():
        if len(getattr(alert, field)) > limit:
            raise HTTPException(413, f"{field} has more than {limit} entries")
    if alert.file is not None:
        if alert.file.sample_path:
            raise HTTPException(400, "file.sample_path is not accepted over the API; send static metadata "
                                     "(imports, sections, strings) instead")
        for field, limit in FILE_LIMITS.items():
            if len(getattr(alert.file, field)) > limit:
                raise HTTPException(413, f"file.{field} has more than {limit} entries")


def create_app(pipeline_factory: Callable | None = None) -> FastAPI:
    """Build the API. Tests pass a pipeline factory that uses scripted fake models."""
    if pipeline_factory is None:
        from .pipeline import build_pipeline as pipeline_factory  # noqa: N813

    app = FastAPI(title="Triage Agents", version=__version__,
                  description="Multi-agent security-alert triage with Google ADK and Gemini.")

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__, "model": get_settings().model,
                "google_api_key": "set" if api_key_configured() else "missing"}

    @app.post("/triage", response_model=TriageResponse)
    async def triage(alert: AlertBundle, include_trace: bool = False) -> TriageResponse:
        from .runner import run_agent

        _validate_limits(alert)
        result = await run_agent(pipeline_factory(), alert, cache=False)
        report = result.state.get("report")
        if report is None:
            raise HTTPException(502, f"triage failed: {result.error or 'no report produced'}")
        findings = result.state.get("findings") or {}
        return TriageResponse(
            run_id=uuid.uuid4().hex, alert_id=alert.alert_id, report=report, error=result.error,
            review_log=result.state.get("review_log") or [],
            residual_issues=result.state.get("final_issues") or [],
            delegations=findings.get("delegations") or [],
            metrics=result.trace.totals(model=get_settings().model),
            trace=result.trace.records if include_trace else None,
        )

    return app


app = create_app()
