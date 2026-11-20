# Design decisions

Each entry gives the context, the decision, and the evidence behind it. Most
decisions came from something that broke in a live run and was measured, then
fixed, then covered by a test.

## 1. ADK 2.x graph `Workflow`, not `LoopAgent` / `SequentialAgent`

- **Context:** ADK 2.15 (current when this was built) emits a `DeprecationWarning`
  for `LoopAgent`, `SequentialAgent` and `ParallelAgent`. The replacement is a graph
  API: nodes connected by edges, with routers returning `Event(route=...)`.
- **Decision:** The pipeline is one `Workflow` ([pipeline.py](../triage_agents/pipeline.py)).
  The self-reflection loop is a routed back-edge (`REVISE -> report_writer`) whose cap
  lives in a plain Python router.
- **Why it matters:** The loop's budget (max 2 revisions) is enforced by code, not by
  asking an LLM to stop. The offline test `test_revision_loop_stops_after_two_rounds`
  pins it.

## 2. Hierarchical delegation with `single_turn` sub-agents

- **Context:** ADK offers three ways for one agent to use another: LLM transfer
  (`sub_agents` in chat mode, where control is handed off), `AgentTool`, and, new in
  2.x, sub-agents with `mode="single_turn"`, which ADK exposes as tools.
- **Decision:** `single_turn` specialists. The Supervisor keeps control, briefs each
  specialist through a `request` argument, and gets structured findings back.
- **Verified offline before relying on it** ([test_supervisor_offline.py](../tests/test_supervisor_offline.py)):
  - the brief arrives as the specialist's user message
  - results come back as the tool result
  - session state (alert, evidence) is shared
  - the trace nests the specialists under the Supervisor
  - a crashing specialist returns an error string instead of killing the run

## 3. Evidence IDs assigned by code, and evidence attached by code

- **Decision:** Every tool records what it observed in a ledger with IDs like `SA-3`,
  `LN-5`, `TI-2` and `AL-1` ([evidence.py](../triage_agents/analysis/evidence.py)). The LLM
  can only cite IDs. The final report's evidence list is attached by `finalize` from the
  ledger, so a report can't contain invented evidence.
- **Detail:** Each agent writes its own state key, so specialists running in parallel
  can't overwrite each other. Lists are reassigned rather than mutated, because ADK
  records a state change only on assignment.

## 4. A pinned local ATT&CK dataset with revoked-ID redirects

- **Context:** Models cite ATT&CK IDs from memory.
- **Decision:** The pipeline uses the v20.1 STIX bundle, verified by SHA-256 and reduced
  to a compact index, plus a map of 149 revoked IDs to their replacements. Threat Intel
  must confirm every ID with `get_technique`.
- **Evidence:** The first test that validated our own rule table against v20.1 failed.
  `T1562.001` and `T1070.001`, which nearly every tutorial cites, were revoked in favor of
  `T1685` and `T1685.005`, under a new Defense Impairment tactic.

## 5. A deterministic checker in front of the LLM Critic

- **Decision:** [report_check.py](../triage_agents/report_check.py) verifies what can be
  checked exactly:
  - citations exist in the ledger
  - technique IDs are valid (or revoked, with the replacement named)
  - each tactic belongs to its technique in v20.1
  - each technique cites behavior evidence, not just its confirmation
  - severity is in line with the strongest signal

  The Critic LLM judges what needs reading comprehension. Checker issues force a revision
  even when the Critic approves.
- **Evidence:** Live, both the Threat Intel agent (step 4) and the Report Writer (step 6)
  used the stale tactic name "Defense Evasion" for v20 "stealth" techniques. In the first
  full pipeline run, the checker caught 2 wrong tactics, and revision 1 fixed them.

## 6. Default model: `gemini-3.5-flash-lite`

- **Evidence:** On 2026-11-19, `gemini-3.6/3.7/3.8-flash` returned `504 DEADLINE_EXCEEDED`
  or `503 high demand` even for a one-word prompt; Flash-Lite answered in 0.5 s.
- **Free-tier limits:** 3.8 Flash allows 5 requests/min and 20/day. Flash-Lite allows 15/min
  and 500/day. A full triage takes 10–17 calls, so 20/day can't support even one eval run.
- **Fallout:** The first live run hung for minutes because no client timeout was set. Every
  request now has a 60 s timeout and retries 429/5xx with backoff ([models.py](../triage_agents/models.py)).

## 7. A `record_plan` tool instead of `PlanReActPlanner`

- **Context:** ADK's `PlanReActPlanner` makes the model write `/*PLANNING*/` text, which ADK
  marks as a thought. Flash-Lite sometimes sent only the plan. A reply without tool calls is
  a final answer, so the agent stopped before doing any work: 2 of about 12 agent runs, once
  for the Supervisor itself. `BuiltInPlanner` wasn't an option, because Flash-Lite ignores
  thinking settings (0 thinking tokens).
- **Decision:** The "reason" step is an explicit tool call, `record_plan(plan)`, made in the
  same turn as the first actions. The plan shows in the trace, and an agent can't stop after
  planning, because planning *is* an action.

## 8. A checklist guard for minimum coverage

- **Evidence:** As a sub-agent, the Static specialist ran 1 of its 4 core checks, even when
  the Supervisor's brief asked for imports.
- **Decision:** A `before_tool_callback` refuses the final `set_model_response` until the core
  checks for this alert's data have run. It returns an error instead of running the tool, so
  ADK doesn't accept the answer. It gives up after 2 refusals, so it can't loop. The LLM still
  decides order and depth; code guarantees the floor.

## 9. Working inside the free tier: rate limiter, call budget, response cache

- **Rate limiter.** The first Supervisor run hit `429 RESOURCE_EXHAUSTED`: 15+ calls in 34 s
  against a 15/min quota, with a server-requested wait of 30–40 s. A sliding-window limiter
  plugin now paces calls before they're sent (14/min, shared per model across the process),
  and waits show in the trace ([ratelimit.py](../triage_agents/ratelimit.py)).
- **Call budget.** Half of the Supervisor's turns were bookkeeping. The alert summary now
  arrives as its input, and the evidence ledger rides along with each specialist's result
  (an `after_tool_callback`). Every agent plans and runs its independent checks in one
  parallel turn. The beacon alert dropped from **22 to 12 calls** (74 s to 20 s).
- **Response cache.** Requests are hashed (model, system prompt, tool declarations, schema,
  conversation, excluding ADK's random call IDs) and replayed from disk
  ([cache.py](../triage_agents/cache.py)). In a replay of two alerts, 18 of 20 calls were
  served from cache, taking ~4.5 s per alert. Re-scoring or re-running unchanged alerts
  costs no quota, and cached eval runs are reproducible.

## 10. Lenient schemas for model output, strict schema for input

- **Evidence:** Threat Intel's first structured answer failed validation (it returned an
  object where a string list was expected), costing a retry call.
- **Decision:** Model-facing schemas ignore extra keys, default lists to empty, and flatten
  objects inside string lists. The JSON schema sent to Gemini is unchanged. Alert input stays
  strict (unknown fields are rejected), which catches typos in eval data. Missing citations
  are still caught, by the checker, where they become feedback for revision instead of a crash.

## 11. Robustness inside the graph

- An agent that ends with plain text has it validated against its output schema inside a
  workflow. Non-JSON text raises, so LLM nodes get a `RetryConfig` (2 attempts, only for
  validation errors, never for quota errors).
- An agent that ends with *no* output at all raises nothing. The `check_findings` node
  detects missing findings and routes back to the Supervisor once.
- A failed run returns its partial state and trace instead of raising, so the eval records
  it and moves on.

## 12. A paired ablation for the Critic

- **Decision:** `finalize` keeps the Report Writer's first draft (before any review) next to
  the final report. The eval scores both on the same specialist evidence. That isolates the
  self-reflection loop's effect without paying for, or being confounded by, a second run.

## 13. No tuning on the eval set

- **Evidence:** The 15-alert eval
  ([results/summary.md](../results/summary.md)) found a consistent bias: 8 of the 9
  severity misses were one level too severe, and the Critic corrected only one.
- **Decision:** Report the bias instead of adjusting prompts until these 15 alerts pass,
  which would only fit the test set. The labels were committed before the first run. The
  fix to try next is a deterministic severity ceiling in the checker, measured on a new
  held-out set.

## 14. Security posture for a tool that ingests attacker-controlled data

- **Untrusted data is labeled.** File strings, command lines and decoded payloads are marked
  UNTRUSTED DATA in tool results and in every prompt that carries them. Text addressed to "the
  AI analyst" is detected and reported as an indicator. The eval includes two
  prompt-injection cases.
- **No raw SQL.** The model never gets a raw SQL tool. Past-alert lookups are fixed queries
  with bound parameters on a read-only (`mode=ro`) SQLite connection.
- **File access is allow-listed.** The static tools only open files under `data/samples/`,
  traversal-safe via `resolve()`. The HTTP API refuses `sample_path` entirely and caps every
  list's size.
- **Secrets stay out.** A pre-commit hook blocks `.env` files and key-shaped strings. The
  Docker image contains no secrets and runs as a non-root user. `/healthz` reports the key
  only as set or missing.
- **Nothing is executed.** Analysis is static parsing only. Test binaries are harmless
  programs compiled from source in the repo.
