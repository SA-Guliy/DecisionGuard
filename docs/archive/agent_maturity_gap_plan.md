# Agent Maturity Gap Plan (Senior-Ready, Lightweight Runtime)

## Purpose
Close the gap between:
- strong structural compliance (contracts/checklists), and
- weak semantic quality (true senior-level reasoning quality).

Constraint: no heavy runtime models. Improvements must be deterministic and lightweight.

## Principles
- Rules over extra LLM calls in runtime.
- Evidence-first decisions (no GO without measurable statistical basis).
- Fail-safe behavior: missing evidence -> HOLD / HOLD_NEED_DATA, never silent GO.

---

## Gap 1: Semantic Quality (Captain + Doctor)

### Current gap
- Fields are present, but depth/quality is inconsistent.
- Hypothesis/methodology quality is weakly enforced.

### P0 solution: Smart Heuristic Semantic Scoring
Implement deterministic `semantic_score` blocks (0..1) with explainable sub-scores.

### Captain (Data Scientist + Realism QA) metrics
- `issue_grounding_score`: issue message overlaps with DQ check/message tokens.
- `verification_quality_score`: verification steps contain SQL read-only patterns and target relevant entities.
- `realism_signal_score`: references realism checks when realism flags are enabled.
- `root_cause_specificity_score`: contains mechanism keywords, not generic phrases.
- `captain_semantic_score`: weighted aggregate.

#### Heuristic examples
- PASS pattern: issue mentions concrete check_name and at least one numeric/context token from DQ row.
- FAIL pattern: message generic (`"data problem"`), no table/check linkage.

### Doctor (Senior Analyst) metrics
- `hypothesis_format_score`: must match pattern:
  - `If <action>, then <metric/effect>, because <mechanism>`.
- `methodology_completeness_score`: requires non-empty:
  - `primary_metric`, `mde`, `confidence_level`, `required_sample_size`.
- `guardrail_binding_score`: goal-linked guardrails present with thresholds.
- `evidence_binding_score`: links to `ab_report`, `metrics_snapshot`, `dq_report`, `captain`.
- `doctor_semantic_score`: weighted aggregate.

#### Hard gate
- If `mde <= 0` or `required_sample_size <= 0` or missing confidence -> `HOLD_NEED_DATA`.

---

## Gap 2: Evidence Layer Weakness

### Current gap
- Decision logic can still pass with partial evidence quality.

### P0 solution: Evidence Contract Enforcement
Extend Doctor experiment contract with required numeric fields:
- `min_sample_size` (or required_sample_size per arm)
- `mde`
- `confidence_level` (e.g., 0.95)

Rules:
- Any missing/zero/invalid -> `HOLD_NEED_DATA`.
- `UNDERPOWERED` / `INCONCLUSIVE` in AB report cannot become GO/ROLLOUT.

Add report metric:
- `evidence_readiness = PASS|WARN|FAIL` with reasons.

---

## Gap 3: PM Prioritization Depth (Commander)

### Current gap
- Selection logic can be too shallow for portfolio-quality PM decisions.

### P0 solution: Priority Score + deterministic ranking
Add per experiment:
- `estimated_impact` (1..10)
- `confidence` (0..1 or mapped High/Med/Low -> 0.8/0.5/0.3)
- `effort` (1..10)
- `priority_score = impact * confidence / max(effort,1)`

Commander behavior:
- rank candidates by `priority_score` desc.
- in `mvp_mode_one_experiment`: choose top-1 only if gates pass.
- if top candidate missing methodology/evidence/assignment -> HOLD with explicit blocker.

Add Commander metrics:
- `ranking_consistency` (same inputs -> same top choice).
- `go_with_complete_evidence` boolean.

---

## Cross-Agent Quality Metrics (L1/L2)

### Per-run (`reports/L1_ops/<run_id>/agent_quality.md|json`)
- Captain:
  - issue_coverage, no_extra_issues, actionability, safety
  - captain_semantic_score
- Doctor:
  - hypothesis_valid, methodology_present, evidence_readiness
  - doctor_semantic_score
  - required_sample_size_present, mde_present, confidence_level_present
- Commander:
  - normalized_decision, blocked_by_count, interference_blocked
  - priority_score_selected, go_with_complete_evidence

### Weekly (`reports/L2_mgmt/...`)
- semantic score trends by agent
- `% runs blocked due to missing evidence`
- `% runs where GO had full evidence`

---

## Implementation Plan (No Heavy Dependencies)

### Phase P0.1 (fast)
1. Add `semantic_scoring.py` helper with deterministic regex/token rules.
2. Integrate Captain semantic score into captain output `eval_metrics`.
3. Integrate Doctor hard evidence gates (`mde`, `confidence_level`, sample size).
4. Add Commander `priority_score` ranking and output fields.

### Phase P0.2
5. Extend `make_agent_quality_report.py` to include new metrics.
6. Extend `make_agent_quality_summary.py` with weekly aggregates for semantic/evidence metrics.
7. Add contract checks to `check_contracts.py` for new required fields.

### Phase P0.3
8. Update README/docs with "Senior-ready decision policy".
9. Add 3-5 regression tests (static fixtures) for:
   - bad hypothesis format -> HOLD
   - missing MDE/confidence -> HOLD
   - priority ranking deterministic

---

## Definition of Done
- No GO/ROLLOUT without complete evidence fields.
- Hypothesis format quality enforced deterministically.
- Commander selects by explicit `priority_score`.
- L1/L2 reports expose semantic + evidence quality metrics.
- All checks remain lightweight and deterministic.

