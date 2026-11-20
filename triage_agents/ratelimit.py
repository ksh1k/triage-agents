"""Client-side rate limiting, so a multi-agent run stays under the free-tier quota.

Free-tier limits per project and per model, from the AI Studio rate-limit page
(2026-11-20):

    model                  RPM   TPM    RPD
    gemini-3.5-flash-lite   15   250K   500   <- our default
    gemini-3.1-flash-lite   15   250K   500   (a separate bucket)
    gemini-3.8-flash         5   250K    20   (too few for multi-agent runs)
    gemini-3.6-flash         5   250K    20

Measured 2026-11-20: a Supervisor run with two
specialists working in parallel made 15+ calls in ~34 s and got
`429 RESOURCE_EXHAUSTED` with "retry in 32-41 s". Retrying after the fact is
slow and can still fail, so we pace requests *before* sending them.

`RateLimitPlugin` is an ADK plugin: its before_model_callback runs before
every model call in the run (Supervisor and sub-agents alike) and waits until
a slot is free in a sliding 60-second window. Limiters are shared per model
across the whole process, so concurrent runs (e.g. API requests) share one
budget, the same way the quota does.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from collections import deque

from google.adk.plugins.base_plugin import BasePlugin

DEFAULT_RPM = 14  # one under the free-tier limit of 15, as a margin
WINDOW_S = 60.0


def configured_rpm() -> int:
    """Requests per minute from TRIAGE_RPM (0 disables limiting)."""
    raw = os.environ.get("TRIAGE_RPM", "").strip()
    return int(raw) if raw else DEFAULT_RPM


class SlidingWindowLimiter:
    """At most `rpm` acquisitions in any 60-second window.

    A threading.Lock (not asyncio.Lock) guards the bookkeeping, so one
    limiter can be shared across event loops, e.g. one asyncio.run() per
    alert in the eval. The lock is never held while sleeping.
    """

    def __init__(self, rpm: int, clock=time.monotonic):
        self.rpm = rpm
        self._clock = clock
        self._times: deque[float] = deque()
        self._lock = threading.Lock()

    def _try_reserve(self) -> float:
        """Reserve a slot now and return 0, or return how long to wait before trying again."""
        with self._lock:
            now = self._clock()
            while self._times and now - self._times[0] >= WINDOW_S:
                self._times.popleft()
            if len(self._times) < self.rpm:
                self._times.append(now)
                return 0.0
            return WINDOW_S - (now - self._times[0]) + 0.05

    async def acquire(self) -> float:
        """Wait until a request may be sent. Returns the seconds spent waiting."""
        if self.rpm <= 0:
            return 0.0
        waited = 0.0
        while (delay := self._try_reserve()) > 0:
            await asyncio.sleep(delay)
            waited += delay
        return waited


_limiters: dict[str, SlidingWindowLimiter] = {}
_limiters_lock = threading.Lock()


def get_limiter(model: str, rpm: int | None = None) -> SlidingWindowLimiter:
    """One shared limiter per model name (the quota is per model)."""
    rpm = configured_rpm() if rpm is None else rpm
    with _limiters_lock:
        limiter = _limiters.get(model)
        if limiter is None or limiter.rpm != rpm:
            limiter = _limiters[model] = SlidingWindowLimiter(rpm)
        return limiter


class RateLimitPlugin(BasePlugin):
    """Waits for a free slot before each model call; reports waits to the trace."""

    def __init__(self, trace=None, rpm: int | None = None) -> None:
        super().__init__(name="rate_limit")
        self.trace = trace
        self.rpm = rpm
        self.total_wait_s = 0.0

    async def before_model_callback(self, *, callback_context, llm_request):
        waited = await get_limiter(llm_request.model or "default", self.rpm).acquire()
        if waited and self.trace is not None:
            self.total_wait_s += waited
            self.trace.note("rate_limit_wait", callback_context.agent_name, wait_s=round(waited, 2))
        return None
