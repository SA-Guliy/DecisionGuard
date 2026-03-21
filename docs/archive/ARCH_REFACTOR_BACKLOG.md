# Architecture Refactor Backlog (Based on Pass 1 + Pass 2)

## Decision rule for this backlog

Each item must improve at least one of:

- readability (defense/interview/GitHub)
- safety correctness
- reduction of duplicate logic
- easier debugging from reports back to code

## Keep (active and important)

- `scripts/run_all.py` (orchestrator, but needs slimming)
- `scripts/run_captain_sanity_llm.py`
- `scripts/run_doctor_variance.py`
- `scripts/run_commander_priority.py`
- `scripts/run_ab_preflight.py`
- `scripts/run_ab_analysis.py`
- `scripts/build_cohort_evidence_pack.py`
- `scripts/build_agent_reasoning_trace.py`
- `scripts/build_agent_interaction_friction_report.py`
- `src/llm_client.py`
- `src/decision_contract.py`
- `src/llm_contract_utils.py`
- `src/model_policy.py`

## Refactor now (P0/P1)

### P0: readability + ownership

- `run_all.py`: extract "core proof path" into a dedicated helper (or separate orchestrator module)
- `run_all.py`: make second Commander invocation explicit as refresh step with separate artifact semantics
- Add `src/paths.py` and migrate high-traffic scripts (started)

### P0: single-source policies

- Add `src/status_taxonomy.py` (AB/pipeline/error families/codes)
- Add `src/goal_metric_mapping.py` (or fold into taxonomy/policy)
- Add `src/artifact_loaders.py` for repeated `captain/doctor/evaluator/commander` loading patterns

### P1: agent contract clarity

- Commander: separate `LLM path reached` vs `core accepted` semantics into shared helper
- Doctor: explicit provider deprecation fallback chain in provenance
- Captain: keep strict schema, but move normalization/repair logic to shared utility if reused

## Archive candidates (review first, then move)

### Top-level clutter (high GitHub UX impact)

- `tmp_archived_chat_messages.tsv` (history/reference, not runtime)
- ad-hoc image/screenshot files in project root (if not used in docs/runtime)

### Historical versions (likely archive)

- `v0/`
- `v1/` (if active runtime no longer imports from it except simulation entrypoint, split carefully)

Note:
- `v1/src/run_simulation_v1.py` is still used by `run_all.py`, so `v1/` cannot be blanket-archived yet.
- Need a sub-audit of `v1/` to isolate active runtime subset vs legacy material.

## Delete later (only after archive + 2 stable runs)

- dead scripts under `scripts/legacy/` not referenced by docs/tests/orchestrator
- stale generated reports/logs if repository publishing policy excludes them

## First low-risk refactors already started

- Model routing policy centralized in `src/model_policy.py`
- Paths helper introduced in `src/paths.py`
- `build_agent_reasoning_trace.py` and `build_agent_interaction_friction_report.py` now use path helpers

## Acceptance after every refactor batch

1. `python3 -m py_compile` on touched files
2. regenerate:
   - `AGENT_REASONING_TRACE`
   - `AGENT_INTERACTION_FRICTION_REPORT`
3. compare key counters/decisions to baseline run
4. confirm no secrets/DSN leakage in modified logs/reports

