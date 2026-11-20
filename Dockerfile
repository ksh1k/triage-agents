# Triage Agents API image (FastAPI + Google ADK). Cloud Run compatible: listens on $PORT.
#   docker build -t triage-agents .
#   docker run --rm -p 8080:8080 -e GOOGLE_API_KEY=... triage-agents
# The API key is supplied at run time (on Cloud Run: from Secret Manager), never baked in.

FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:0.11.6 /uv /bin/uv

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PORT=8080

WORKDIR /app

# Dependencies first, so code changes don't invalidate this layer.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY triage_agents ./triage_agents
COPY data ./data
COPY scripts/seed_past_alerts.py ./scripts/seed_past_alerts.py
RUN uv sync --frozen --no-dev \
    && .venv/bin/python scripts/seed_past_alerts.py

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

EXPOSE 8080
CMD ["sh", "-c", "exec /app/.venv/bin/uvicorn triage_agents.api:app --host 0.0.0.0 --port ${PORT}"]
