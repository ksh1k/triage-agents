"""Tracing: record which agent did what, in order, with timing and token usage.

`TracePlugin` is an ADK plugin. Registered once on the App, it gets a
callback for every agent start/end, model call and tool call in the run,
including inside sub-agents. It never changes behavior: every hook returns
None. The result is a list of records that can be written as JSONL or
printed as a readable timeline.

ADK also emits OpenTelemetry spans (shown in `adk web` and Cloud Trace).
This plugin is our own lightweight view, aimed at following the delegation
step by step and at measuring tokens and latency for the eval.
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from google.adk.plugins.base_plugin import BasePlugin

from .config import estimate_cost_usd

TEXT_LIMIT = 400


def _clip(text: str, limit: int = TEXT_LIMIT) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "..."


def _jsonable(value: Any, limit: int = 300) -> Any:
    try:
        dumped = json.dumps(value, default=str)
    except (TypeError, ValueError):
        dumped = str(value)
    return value if len(dumped) <= limit else dumped[:limit] + "..."


class TracePlugin(BasePlugin):
    def __init__(self, name: str = "trace", live: bool = False) -> None:
        super().__init__(name=name)
        self.live = live  # print each step to stderr as it happens
        self.records: list[dict] = []
        self._t0 = time.perf_counter()
        self._model_started: dict[str, list[float]] = defaultdict(list)
        self._tool_started: dict[str, float] = {}

    # ------------------------------------------------------------ helpers

    def _now(self) -> float:
        return round(time.perf_counter() - self._t0, 3)

    def note(self, kind: str, agent: str, **data: Any) -> None:
        """Let other plugins (e.g. the rate limiter) add a record to this trace."""
        self._add(kind, agent, **data)

    def _add(self, kind: str, agent: str, **data: Any) -> None:
        record = {"seq": len(self.records) + 1, "t": self._now(), "kind": kind, "agent": agent, **data}
        self.records.append(record)
        if self.live:
            detail = data.get("tool") or ", ".join(c["name"] for c in data.get("tool_calls", [])) or ""
            if kind == "model_response" and not detail and data.get("text"):
                detail = "text: " + _clip(" ".join(data["text"]), 120)
            extra = (f" in={data['input_tokens']} out={data['output_tokens']} think={data['thinking_tokens']}"
                     f" {data['latency_s']}s" if kind == "model_response" else "")
            extra += f" waited {data['wait_s']}s" if "wait_s" in data else ""
            err = f" {data['error']}" if "error" in data else ""
            print(f"[{record['t']:8.3f}s] {agent:22} {kind:15} {detail}{extra}{err}", file=sys.stderr, flush=True)

    # ------------------------------------------------------------ ADK hooks

    async def before_agent_callback(self, *, agent, callback_context):
        self._add("agent_start", agent.name)
        return None

    async def after_agent_callback(self, *, agent, callback_context):
        self._add("agent_end", agent.name)
        return None

    async def before_model_callback(self, *, callback_context, llm_request):
        self._model_started[callback_context.agent_name].append(time.perf_counter())
        self._add("model_call", callback_context.agent_name, model=llm_request.model,
                  messages=len(llm_request.contents or []))
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        if llm_response.partial:
            return None
        agent = callback_context.agent_name
        starts = self._model_started[agent]
        latency = round(time.perf_counter() - starts.pop(), 3) if starts else None
        usage = llm_response.usage_metadata
        thoughts, texts, calls = [], [], []
        for part in (llm_response.content.parts if llm_response.content else None) or []:
            if part.function_call:
                calls.append({"name": part.function_call.name, "args": _jsonable(part.function_call.args or {})})
            elif part.text and part.thought:
                thoughts.append(_clip(part.text))
            elif part.text:
                texts.append(_clip(part.text))
        self._add(
            "model_response", agent, latency_s=latency,
            input_tokens=(usage.prompt_token_count or 0) if usage else 0,
            output_tokens=(usage.candidates_token_count or 0) if usage else 0,
            thinking_tokens=(usage.thoughts_token_count or 0) if usage else 0,
            thoughts=thoughts, text=texts, tool_calls=calls,
            model_version=llm_response.model_version,
        )
        return None

    async def on_model_error_callback(self, *, callback_context, llm_request, error):
        self._add("model_error", callback_context.agent_name, error=_clip(repr(error), 300))
        return None

    async def before_tool_callback(self, *, tool, tool_args, tool_context):
        self._tool_started[tool_context.function_call_id or tool.name] = time.perf_counter()
        self._add("tool_call", tool_context.agent_name, tool=tool.name, args=_jsonable(tool_args))
        return None

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        start = self._tool_started.pop(tool_context.function_call_id or tool.name, None)
        if isinstance(result, str) and result.startswith("Error"):
            result = {"status": "error", "error_message": result}  # e.g. a failed sub-agent
        result = result if isinstance(result, dict) else {"result": result}
        evidence = sorted({v for k, v in _walk(result) if k.endswith("evidence_id") and isinstance(v, str)})
        # Delegation tools return the specialist's findings, which have no "status" key.
        status = result.get("status") or ("returned findings" if "agent" in result else None)
        self._add("tool_result", tool_context.agent_name, tool=tool.name,
                  latency_s=round(time.perf_counter() - start, 3) if start else None,
                  status=status, evidence_ids=evidence)
        return None

    async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error):
        self._add("tool_error", tool_context.agent_name, tool=tool.name, error=_clip(repr(error), 300))
        return None

    # ------------------------------------------------------------ outputs

    def totals(self, model: str | None = None) -> dict:
        responses = [r for r in self.records if r["kind"] == "model_response"]
        inp = sum(r["input_tokens"] for r in responses)
        out = sum(r["output_tokens"] for r in responses)
        think = sum(r["thinking_tokens"] for r in responses)
        model = model or next((r["model_version"] for r in responses if r.get("model_version")), None)
        return {
            "model_calls": len(responses),
            "tool_calls": sum(r["kind"] == "tool_call" for r in self.records),
            "input_tokens": inp, "output_tokens": out, "thinking_tokens": think,
            "total_tokens": inp + out + think,
            "estimated_cost_usd": estimate_cost_usd(model, inp, out + think) if model else None,
            "wall_time_s": self.records[-1]["t"] if self.records else 0.0,
            "rate_limit_wait_s": round(sum(r.get("wait_s", 0) for r in self.records), 2),
            "errors": sum(r["kind"] in ("model_error", "tool_error") for r in self.records),
            "agents": list(dict.fromkeys(r["agent"] for r in self.records)),
        }

    def write_jsonl(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for record in self.records:
                f.write(json.dumps(record, default=str) + "\n")
        return path

    def format_timeline(self) -> str:
        """Human-readable, indented by agent depth, e.g.

           0.000s  > static_analyst started
           0.002s      model call #1 ...
        """
        lines, depth, calls = [], 0, 0
        for r in self.records:
            pad = "    " * depth
            k, t = r["kind"], f"{r['t']:8.3f}s"
            if k == "agent_start":
                lines.append(f"{t}  {pad}> {r['agent']} started")
                depth += 1
            elif k == "agent_end":
                depth = max(depth - 1, 0)
                lines.append(f"{t}  {'    ' * depth}< {r['agent']} finished")
            elif k == "model_response":
                calls += 1
                tokens = f"in {r['input_tokens']:,} / out {r['output_tokens']:,}"
                if r["thinking_tokens"]:
                    tokens += f" / thinking {r['thinking_tokens']:,}"
                lines.append(f"{t}  {pad}[LLM {calls}] {r['latency_s']}s, {tokens} tokens")
                for th in r["thoughts"]:
                    lines.append(f"{'':10}{pad}    thought: {_clip(th, 220)}")
                for tx in r["text"]:
                    lines.append(f"{'':10}{pad}    text:    {_clip(tx, 220)}")
                for c in r["tool_calls"]:
                    if c["name"] == "record_plan" and isinstance(c["args"], dict):
                        lines.append(f"{'':10}{pad}    plan:    {_clip(str(c['args'].get('plan', '')), 300)}")
                    else:
                        lines.append(f"{'':10}{pad}    action:  {c['name']}({_clip(json.dumps(c['args'], default=str), 160)})")
            elif k == "tool_result":
                ev = f" -> evidence {', '.join(r['evidence_ids'])}" if r["evidence_ids"] else ""
                lines.append(f"{t}  {pad}[TOOL] {r['tool']}: {r['status']}{ev} ({r['latency_s']}s)")
            elif k in ("tool_error", "model_error"):
                lines.append(f"{t}  {pad}[ERROR] {r.get('tool', 'model')}: {_clip(r['error'], 200)}")
            elif k == "rate_limit_wait":
                lines.append(f"{t}  {pad}[WAIT] {r['wait_s']}s to stay under the requests-per-minute limit")
        return "\n".join(lines)


def _walk(obj: Any, key: str = ""):
    """Yield (key, value) pairs from nested dicts/lists, used to find evidence IDs."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, key)
    else:
        yield key, obj
