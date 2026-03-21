# Architecture Audit — Pass 1 (Top-Down: How It Was Built)

## Purpose of this pass

This pass documents how the system is currently assembled in code (not how it "should" work).
Goal: understand the built shape before refactoring.

## Entry point reality

The main orchestrator is `scripts/run_all.py`.

It currently mixes 4 responsibilities in one file:

1. Run orchestration (pipeline sequencing)
2. Environment / backend routing flags
3. Policy checks (core agent LLM authenticity, strict mode behavior)
4. Human-facing summary output + many optional report steps

This makes `run_all.py` powerful but hard to explain quickly.

## Built pipeline (observed order, active path)

### Core data + validation

1. `v1/src/run_simulation_v1.py`
2. `scripts/run_dq.py`
3. `scripts/make_metrics_snapshot_v1.py`
4. `scripts/run_synthetic_bias_audit.py` (best-effort)
5. `scripts/run_ab_preflight.py` (if experiment enabled)
6. `scripts/run_ab_analysis.py` (if experiment enabled)

### Core agents (3)

7. `scripts/run_captain_sanity_llm.py` (Agent 1: Captain)
8. `scripts/run_doctor_variance.py` (Agent 2: Doctor)
9. `scripts/run_experiment_evaluator.py` (deterministic evaluator, not one of the 3 core agents)
10. `scripts/build_cohort_evidence_pack.py` (if experiment enabled)
11. `scripts/run_commander_priority.py` (Agent 3: Commander)

### Transparency / evidence / narrative layer

12. `scripts/build_action_trace.py`
13. `scripts/build_evidence_pack.py`
14. `scripts/run_narrative_analyst.py` (legacy/secondary role relative to core 3)
15. `scripts/validate_narrative_grounding.py`
16. `scripts/build_vector_quality_signals.py`
17. `scripts/run_commander_priority.py` again (refresh approvals; non-lightweight path)

### Governance / reporting / acceptance layer

18. `scripts/run_security_check.py`
19. `scripts/build_reports.py`
20. `scripts/build_retail_mbr.py`
21. `scripts/run_agent_governance.py`
22. `scripts/run_adversarial_eval_suite.py`
23. Additional quality/eval/report scripts (mostly non-lightweight)
24. `scripts/pre_publish_audit.py`
25. `scripts/verify_acceptance.py`
26. `scripts/build_human_reports_hub.py`

## Top-down structural strengths (already present)

- Strong artifact-first design (JSON + MD outputs)
- Safety gates explicitly layered (preflight, evaluator, commander deterministic merge)
- Good observability trend: `AGENT_REASONING_TRACE`, friction report, AB failure registry
- Read-only discipline in AB preflight/analysis path

## Top-down structural problems (built-shape issues)

### 1) `run_all.py` is overloaded

The file is too large for fast explanation in a defense/interview setting.
It combines core path + optional analytics + publish checks + report generation.

Impact:
- hard to see "minimum proof path"
- hard to reason about ownership of steps
- easy to hide accidental step duplication

### 2) Script layer is too thick

Many `scripts/*.py` files contain both:
- CLI/orchestration
- reusable business logic

This makes reuse/refactor harder and spreads policy across scripts instead of `src/`.

### 3) Path construction is duplicated across scripts

Many scripts build artifact paths using repeated f-strings (e.g. `data/agent_reports/...`, `reports/L1_ops/...`).

Impact:
- hard to rename paths safely
- easy to create subtle path inconsistencies
- harder to explain file layout

### 4) Role boundaries are partially clean, partially layered by history

Core 3 agents are clear conceptually:
- Captain / Doctor / Commander

But runtime still includes legacy adjacent layers:
- evaluator
- narrative
- vector quality
- refresh commander pass

These are useful, but in code they are not clearly marked as:
- core
- supporting
- legacy/optional

## What this pass says about cleanup direction

Refactor target is not "rewrite everything".
It is:

1. thin `scripts/` entrypoints
2. centralize policy (models, paths, taxonomies)
3. isolate core proof path from optional/reporting tail
4. make active architecture visually obvious from root + docs

