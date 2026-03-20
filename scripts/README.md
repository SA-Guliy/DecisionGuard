# Scripts Map (Human-First)

This file helps navigate `scripts/` quickly during review, demo, or interview.

## Core Runtime / Orchestration (read first)

- `run_all.py` — full end-to-end orchestrator (runtime-safe)

## Core Agents (3-agent system)

- `run_captain_sanity_llm.py` — Agent 1 (Captain / Data Verifier)
- `run_doctor_variance.py` — Agent 2 (Doctor / Experiment Designer)
- `run_commander_priority.py` — Agent 3 (Commander / Decision Gatekeeper)

## AB Validity + Analysis

- `run_ab_preflight.py` — validation stop before AB stats (schema / grain / assignment / joins)
- `run_ab_analysis.py` — AB statistical analysis (after preflight)
- `build_ab_report.py` — AB human-readable report
- `build_ab_failure_registry.py` — aggregated failure causes across runs

## Core Reports / Proof / Transparency

- `build_reports.py` — primary reporting bundle
- `build_agent_reasoning_trace.py` — per-run transparency / agent reasoning trace
- `build_agent_interaction_friction_report.py` — cross-run frictions / fallback patterns
- `build_action_trace.py` — action trace
- `build_evidence_pack.py` — evidence bundle
- `build_cohort_evidence_pack.py` — cohort evidence for Commander / AB interpretation

## Data Quality / Metrics / Diagnostics

- `run_dq.py`
- `make_metrics_snapshot_v1.py`
- `run_synthetic_bias_audit.py`
- `validate_causal_claims.py`
- `validate_narrative_grounding.py`
- `build_vector_quality_signals.py`

## Evaluation / Governance / Acceptance

- `eval_agents_v2.py`
- `run_adversarial_eval_suite.py`
- `run_agent_governance.py`
- `run_agent_value_eval.py`
- `check_contracts.py`
- `check_decision_contracts.py`
- `pre_publish_audit.py`
- `verify_acceptance.py`

## Human-Facing Packs / Summaries

- `build_retail_mbr.py`
- `build_human_reports_hub.py`
- `build_weekly_pack.py`
- `build_exec_brief.py`
- `build_agent_report.py`
- `make_agent_quality_summary.py`
- `make_agent_effectiveness_report.py`
- `make_agent_quality_report.py`
- `make_agent_quality_report_v2.py`
- `make_realism_report.py`

## Admin / Maintenance / Dev Tooling (not first-read)

- `admin_setup_views.py`
- `admin_fix_default_acls.py`
- `load_raw.py`
- `archive_artifacts.py` (`--kind logs|reports`)
- `render_architecture_diagram.py`
- `update_active_experiments_registry.py` (review ownership)
- `run_ensemble.py` (review role / keep vs archive)

## Notes

- Not every script is a primary entrypoint.
- For architecture explanation, start with:
  1. `run_all.py`
  2. `run_*` core agents
  3. `run_ab_preflight.py` + `run_ab_analysis.py`
  4. `build_agent_reasoning_trace.py` + `build_agent_interaction_friction_report.py`
- Many scripts are generated-report/eval sidecars and should not be confused with the core decision path.
