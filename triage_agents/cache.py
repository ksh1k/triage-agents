"""Record-and-replay cache for model calls.

With the cache on (TRIAGE_CACHE=on, or run_agent(cache=True)), every model
response is saved to cache/llm/<hash>.json, keyed by a hash of the request:
model, system instruction, tool declarations, output schema and conversation.
An identical request is then answered from disk: no API call, no quota, no
rate-limit wait.

Why it matters on the free tier (500 requests/day): re-running the eval after
changing only scoring, checking or report-formatting code costs nothing, and a
cached eval run is exactly reproducible. Change a prompt, and only the agents
whose requests changed call the model again.

Determinism detail: ADK gives every function call a random ID ("adk-..."),
and tool results echo it. Those IDs are left out of the hash, or nothing would
ever match twice.

Trade-off, stated in the README: a replay returns the same answer every time,
so measuring run-to-run variance needs the cache off.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin

from .config import PROJECT_ROOT

CACHE_DIR = PROJECT_ROOT / "cache" / "llm"


def cache_enabled() -> bool:
    return os.environ.get("TRIAGE_CACHE", "").strip().lower() in {"1", "on", "true", "yes"}


def _text_of(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    parts = getattr(value, "parts", None)
    if parts is not None:
        return "\n".join(p.text or "" for p in parts)
    return str(value)


def _part(p) -> dict:
    if p.function_call:
        return {"call": p.function_call.name, "args": p.function_call.args or {}}
    if p.function_response:
        return {"result": p.function_response.name, "response": p.function_response.response}
    return {"text": p.text or "", "thought": bool(p.thought)}


def request_key(llm_request) -> str:
    """Stable hash of everything that determines the model's answer (minus random call IDs)."""
    cfg = llm_request.config
    tools = []
    for tool in (getattr(cfg, "tools", None) or []):
        for fd in (getattr(tool, "function_declarations", None) or []):
            tools.append(fd.model_dump(mode="json", exclude_none=True, exclude={"id"}))
    schema = getattr(cfg, "response_schema", None) or getattr(cfg, "response_json_schema", None)
    payload = {
        "model": llm_request.model,
        "system": _text_of(getattr(cfg, "system_instruction", None)),
        "tools": sorted(tools, key=lambda t: t.get("name", "")),
        "schema": schema if isinstance(schema, (dict, str)) else (str(schema) if schema else None),
        "contents": [{"role": c.role, "parts": [_part(p) for p in (c.parts or [])]}
                     for c in (llm_request.contents or [])],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


class ResponseCachePlugin(BasePlugin):
    """Serves repeated model requests from disk; records new responses after real calls."""

    def __init__(self, trace=None, directory: Path = CACHE_DIR) -> None:
        super().__init__(name="response_cache")
        self.trace = trace
        self.directory = Path(directory)
        self.hits = 0
        self.misses = 0
        self._pending: dict[str, list[str]] = defaultdict(list)

    def _path(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    async def before_model_callback(self, *, callback_context, llm_request):
        key = request_key(llm_request)
        path = self._path(key)
        if path.exists():
            response = LlmResponse.model_validate(json.loads(path.read_text(encoding="utf-8"))["response"])
            self.hits += 1
            if self.trace is not None:
                # ADK skips after_model callbacks when a plugin answers, so record it here.
                self.trace.record_model_response(callback_context.agent_name, response, latency=0.0, cached=True)
            return response  # returning a response skips the real model call
        self.misses += 1
        self._pending[callback_context.agent_name].append(key)
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        if llm_response.partial:
            return None
        keys = self._pending[callback_context.agent_name]
        if not keys:
            return None
        key = keys.pop()
        if llm_response.content is None or llm_response.error_code:
            return None
        data = llm_response.model_dump(mode="json", exclude_none=True)
        for part in (data.get("content") or {}).get("parts", []):
            if "function_call" in part:
                part["function_call"].pop("id", None)  # ADK assigns fresh IDs on replay
        self.directory.mkdir(parents=True, exist_ok=True)
        tmp = self._path(key).with_suffix(".tmp")
        tmp.write_text(json.dumps({"model": getattr(llm_response, "model_version", None), "response": data}),
                       encoding="utf-8")
        tmp.replace(self._path(key))
        return None
