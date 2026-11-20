# Triage Agents

A multi-agent security-alert triage system built with Google's
[Agent Development Kit (ADK)](https://adk.dev) and Gemini.

Give it a security alert bundle (a file's static metadata, process logs, network
connections) and it returns a structured triage report: severity, likely MITRE
ATT&CK techniques, the evidence behind each claim, a confidence level, and
recommended next steps.

> **Status:** under construction. The full README (architecture diagram, how each
> agent pattern is implemented, eval results, limitations) arrives in step 9.

## Build progress

| Step | What | Status |
|---|---|---|
| 1 | Skeleton: project config, secret scanning, shared schemas | done |
| 2 | Analysis tools (pefile, entropy, logs, beaconing, ATT&CK, SQLite) + tests | done |
| 3 | Static Analysis agent (ReAct) + tracing | done |
| 4 | Log/Network and Threat Intel agents | planned |
| 5 | Supervisor (hierarchical delegation) | planned |
| 6 | Report Writer + Critic loop (self-reflection) | planned |
| 7 | CLI, FastAPI `POST /triage`, Dockerfile | planned |
| 8 | 15-alert evaluation harness + results | planned |
| 9 | Full README, Cloud Run notes | planned |

## Safety and scope

- No live malware anywhere in this repo. Inputs are synthetic logs, synthetic
  metadata, and benign binaries (system DLLs, small test programs we compile ourselves).
- Nothing is ever executed. Binaries are only parsed statically.
- API keys live in `.env`, which is gitignored. A pre-commit hook blocks commits
  that contain `.env` files or strings that look like API keys or private keys.

## Data sources

- **MITRE ATT&CK® Enterprise v20.1**: pinned by SHA-256 and reduced to a compact
  index in `data/attack/` (see `data/attack/NOTICE.md`). Rebuild with
  `uv run python scripts/fetch_attack.py`.
- **Past alerts**: a synthetic SQLite history built from `data/past_alerts_seed.json`.
- **Benign test binaries**: `data/samples/bin/`, compiled from `data/samples/src/` with
  `uv run python scripts/build_test_bins.py` (Zig's C compiler, a dev dependency).

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                   # create .venv and install dependencies
cp .env.example .env                      # then paste your Gemini API key into .env
git config core.hooksPath .githooks       # turn on the secret-scanning pre-commit hook
uv run pytest                             # offline tests (no API calls)
RUN_LIVE=1 uv run pytest tests/test_live.py   # opt-in: one real Gemini run
```

Try the Static Analysis agent on a sample and watch its reason, act, observe loop:

```bash
uv run python scripts/demo_static_agent.py examples/alerts/loader_demo_sample.json
```

The default model is `gemini-3.5-flash-lite` (set `TRIAGE_MODEL` to change it).
Every request has a 60 s timeout and retries on 429/5xx, and each run is capped
at 40 model calls so a looping agent can't drain the free-tier quota.
