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
| 2 | Analysis tools (pefile, entropy, logs, beaconing, ATT&CK, SQLite) + tests | planned |
| 3 | Static Analysis agent (ReAct) + tracing | planned |
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

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                   # create .venv and install dependencies
cp .env.example .env                      # then paste your Gemini API key into .env
git config core.hooksPath .githooks       # turn on the secret-scanning pre-commit hook
uv run pytest                             # run the tests
```
