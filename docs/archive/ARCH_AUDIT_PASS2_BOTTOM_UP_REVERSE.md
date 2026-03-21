# Architecture Audit — Pass 2 (Bottom-Up: Reverse From Outputs to Code)

## Purpose of this pass

This pass starts from the user-visible outputs and walks backward to the code that produced them.
Goal: identify hidden duplication, fallback masking, and logic that diverges from project goals.

## Starting points used for reverse trace

Primary artifacts (user-facing / diagnostic):

- `reports/L1_ops/<run_id>/AGENT_REASONING_TRACE.md`
- `reports/L1_ops/AGENT_INTERACTION_FRICTION_REPORT.md`
- `data/agent_reports/<run_id>_commander_priority.json`
- `data/agent_reports/<run_id>_doctor_variance.json`
- `data/ab_preflight/*.json`
- `data/ab_reports/*_ab*.json`

## Reverse findings (high-value issues)

### 1) One user-visible field often has multiple upstream owners

Examples:
- methodology facts appear in Doctor, AB report, Commander methodology checks
- status/error semantics appear in AB outputs, evaluator outputs, commander checks, reports
- some path-based evidence references are re-derived downstream

Impact:
- same concept can drift across scripts
- reports can show different "truths" depending on which source they prefer
- difficult to explain authoritative source during project defense

### 2) Fallbacks are visible now, but fallback semantics are still scattered

The project improved transparency (good), but reverse pass shows multiple fallback layers:

- backend fallback (Groq -> local/Ollama/local_mock)
- schema/JSON fallback (LLM path reached but output rejected)
- deterministic methodology fallback (Doctor)
- deterministic decision authority (Commander merge)

Impact:
- system is safer, but logic is hard to explain quickly
- "LLM worked" vs "LLM accepted" requires deep artifact knowledge unless docs and naming are very clear

### 3) `Commander` can run twice in one pipeline

Observed in `run_all.py`:
- first run before narrative/validation
- optional refresh pass after narrative/validation

Impact:
- output ownership becomes time-dependent
- reverse tracing a `commander_priority.json` field may depend on which run overwrote it
- easy to create confusion during debugging/demo

This is not necessarily wrong, but it needs explicit naming or separate artifact outputs.

### 4) Diagnostic/report scripts duplicate path and artifact-loading patterns

`build_agent_reasoning_trace.py` and `build_agent_interaction_friction_report.py` load many of the same artifacts with nearly identical path templates and heuristics.

Impact:
- more maintenance cost
- higher risk of divergence in future fixes
- harder to make global path/layout changes

### 5) Model routing policy historically leaked across agents

Reverse pass exposed real cross-agent contamination (already fixed):
- `Doctor` wrote global `GROQ_MODEL`
- downstream agent could inherit the wrong model unintentionally

This is a good example of why reverse tracing catches bugs top-down review can miss.

### 6) Legacy/history artifacts clutter runtime understanding

Top-level and historical logs/reports contain older model choices (`Mixtral`, old routing behavior), which is useful for history but noisy for present architecture understanding.

Impact:
- makes it harder to distinguish active runtime behavior from historical runs
- increases "visual entropy" when explaining the project

## Reverse pass findings specifically tied to project goals

Project goal: prove agents can reason causally, improve metrics, and stay within guardrails.

Reverse trace shows current blockers:

1. Core agent acceptance still limited by LLM contract/schema compatibility (not only model quality)
2. Doctor methodology path can degrade due provider/model deprecation
3. AB/preflight failures still dominate many runs, reducing valid learning throughput
4. Architecture readability debt weakens credibility of the proof, even when safety/logic improved

## What must become single-source-of-truth (SSOT)

To reduce reverse-trace complexity, these should be centralized:

1. Model policy (started)
2. Artifact paths (started)
3. Status/error taxonomy (pending)
4. Goal/metric mapping (pending)
5. AB methodology compatibility policy (partially duplicated today)

## Reverse-pass cleanup priorities (practical)

### P0 (improves explainability immediately)

- Separate "core proof path" from optional/reporting tail in `run_all.py`
- Make dual Commander invocation explicit (different output or explicit refresh flag naming)
- Continue centralizing paths and model routing

### P1 (reduces bugs and duplication)

- Centralize status/error taxonomy
- Centralize goal/metric mapping
- Centralize artifact loading helpers for common agent reports

### P2 (repo readability / GitHub UX)

- Archive clearly historical top-level clutter (`v0`, `v1`, temp files) with manifest
- Keep root focused on active architecture

