# AB Methodology Spec (P0)

This document defines when uplift is trusted and when the system must hold/stop.
It now also records the **target methodology standard** for retail/darkstore AB tests, so we can evolve the
implementation without losing safety.

## Scope

- AB analysis: `scripts/run_ab_analysis.py`
- Agent-2: `scripts/run_doctor_variance.py`
- Evaluator: `scripts/run_experiment_evaluator.py`
- Agent-3: `scripts/run_commander_priority.py`
- Acceptance verifier: `scripts/verify_acceptance.py`

## Contour separation (required)

Reports must keep two contexts separate:
- `current AB contour`: metric/goal of the AB run being interpreted now.
- `next experiment contour`: Agent-2's next hypothesis/portfolio target.

Policy:
- Fatal methodology mismatch is allowed only for `current AB contour` contract mismatch.
- Difference between next contour and current AB contour is informational (planning context), not a fatal AB-method validity error by itself.

## Trust checklist (uplift can be trusted only if all pass)

1. Assignment exists and is non-empty for requested experiment.
2. SRM sanity is acceptable (no severe split mismatch).
3. Experiment unit and join path are valid (no methodology mismatch).
4. Primary metric and sample sizes are available.
5. Confidence interval and test logic are available.
6. Guardrails are not violated.

If any core item fails -> no win claim.

## Observable vs Unobservable

### OBSERVABLE

Use when AB status indicates measurable outcome:
- `OK`
- `UNDERPOWERED`
- `INCONCLUSIVE`

`UNDERPOWERED` and `INCONCLUSIVE` are still observable but not rollout-ready by default.

### UNOBSERVABLE

Use when effect cannot be measured:
- `MISSING_ASSIGNMENT`
- `METHODOLOGY_MISMATCH`
- `INVALID`
- `ASSIGNMENT_RECOVERED` (post-hoc reconstruction risk)

Required actions:
- Uplift fields must be null.
- Evaluator must be at most `STOP` or `HOLD_RISK`.
- Agent-3 must never output `RUN_AB` / `ROLLOUT_CANDIDATE`.
- Reports must show fatal measurement banner.

### BLOCKED_BY_DATA

Use when expected artifacts are missing.
Decision must remain conservative and explicit (no fake uplift).

## Test method policy

- Preferred: bootstrap-lite CI / deterministic approximation configured in AB script.
- If z-test assumptions are not met or variance unavailable:
  - do not synthesize certainty,
  - set hold reason (`HOLD_NEED_DATA`) and emit blockers.

Current status (honest):
- this is a **P0 safety/validity policy**, not yet a full methodology-first standard.
- some metrics (especially writeoff) still use proxies in AB execution and must be labeled as proxies.

## Guardrail policy

Even with positive primary metric, rollout is blocked if guardrails fail.
Examples:
- fill-rate floor violated,
- GP margin collapse,
- OOS loss worsens materially.

## Decision ceilings

- Narrative ungrounded -> Agent-3 max `HOLD_RISK`.
- Assignment recovered post-hoc -> no GO/ROLLOUT.
- Methodology mismatch -> STOP/HOLD only.

## Critical checks (release-blocking)

These checks are treated as `CRITICAL` in `scripts/verify_acceptance.py`.
If one fails, overall acceptance is `FAIL`.

| Check | Why critical | Expected behavior |
|---|---|---|
| `pre_publish_audit` present and passed | Prevent secret/safety regressions | PASS only when audit file exists and `passed=true` |
| `ab_status_valid` | Avoid fake AB conclusions | AB artifact must exist and status must be valid |
| Blind spot uplift null (`MISSING_ASSIGNMENT`/`METHODOLOGY_MISMATCH`) | No causal claim without observability | Uplift and CI fields must be null |
| Blind spot evaluator guard | Prevent unsafe promotion | Evaluator must be `STOP` or `HOLD_RISK` |
| Agent-3 unsafe decision guard | Final decision cannot override safety | No `RUN_AB`/`ROLLOUT_CANDIDATE` when evaluator/measurement status forbids it |
| Cross-artifact `run_id` consistency | Prevent mixed-artifact contamination | Evaluator/Agent-3/AB must refer to current run |
| Cross-artifact `experiment_id` consistency | Prevent wrong AB binding | Evaluator and AB must refer to same experiment |
| Narrative ungrounded ceiling | Avoid rollout from ungrounded reasoning | If ungrounded, commander must be <= `HOLD_RISK` |

## What acceptance verifies

`scripts/verify_acceptance.py` checks:
- artifact presence and minimal schema sanity,
- blind-spot constraints (uplift null + evaluator guard + MBR fatal),
- grounding and decision ceiling behavior,
- safety gate (`pre_publish_audit`) and non-trivial scoring behavior.

## P1 Target Standard (Methodology-First, Retail / Darkstore)

This is the target we are moving toward (incrementally) based on the retail AB reference.

### 1) Experiment class -> unit of randomization (default rules)

- If treatment changes **inventory / inbound / expiry / availability**:
  - default randomization unit = `store` (or `store-week`)
  - user-level randomization is not trusted by default due to interference.
- If treatment is **pure UI / cross-sell / basket UX** and does not affect availability:
  - user-level randomization may be used.
- Final report must show both:
  - `randomization_unit`
  - `analysis_unit`

### 2) Mandatory design fields (must be fixed before interpretation)

Every AB plan/report should carry these fields (even if some are `null` initially):
- `pre_period_weeks`
- `test_period_weeks` (or explicit test dates)
- `wash_in_days`
- `attribution_window_rule`
- `alpha`
- `power_target`
- `mde_target`
- `test_side` (`one-sided` / `two-sided`)
- `guardrail_thresholds` (e.g. OOS non-inferiority delta)

If missing for a high-impact experiment (especially writeoff/inbound), decisioning should remain conservative.

### 3) Pre-period / wash-in / attribution window (required for inbound/writeoff)

These are not optional for inventory/waste experiments.

- `pre-period`:
  - baseline window before test start (used for comparability and variance reduction).
- `wash-in`:
  - time after launch before treatment effect on waste is considered stable.
- `attribution window`:
  - explicit rule for which inventory/lots count as "in test".
  - Example: "count writeoff only for lots received after test start" OR "apply wash-in = N days".

Without this, writeoff results can mix old inventory with new policy effects.

### 4) Guardrails are part of the decision rule (not appendix)

Primary win is insufficient.

Decision should depend on:
- Primary metric effect (CI + threshold),
- Guardrails safe (`OOS`, `fill-rate`, `GM/CM/WIC`, cancellations/substitutions if relevant),
- Measurement/data integrity pass.

Recommended decision rule shape:
- `ROLL OUT` only if:
  - primary effect direction and CI meet threshold,
  - guardrails within allowed deltas,
  - data integrity and methodology checks pass.

### 5) SRM and invariant checks (must be explicit)

SRM should be separated from effect testing.

Required:
- SRM check (counts by randomization unit, e.g. stores/store-weeks),
- invariant checks on pre-period baselines (e.g. baseline waste, GMV volume, category mix),
- explicit note when unequal group sizes are present and how they are handled.

Current implementation note:
- P0 uses a simple SRM warning heuristic.
- Target standard is a formal SRM test (chi-square/binomial depending on design).

### 6) Writeoff / waste metric standard (canonical vs proxy)

#### Canonical (target)

- `Expiry WasteRate (COGS)` = `sum(expiry_writeoff_cogs) / sum(received_cogs)`
- analysis grain: typically `store-week` (or `store-day`, then rolled up)

#### Proxy (current acceptable fallback, must be labeled)

- `writeoff_rate_adj` = `writeoff_units / requested_units`

Rules:
- Do not label proxy metrics as canonical `Expiry WasteRate (COGS)`.
- Reports must explicitly mark proxy semantics.

### 7) Batch / lot identity in current data (surrogate strategy)

Current dataset does not expose a stable persisted `batch_id` in the active Step1 schema.
Available lot attributes in `step1.step1_writeoff_log`:
- `store_id`
- `product_id`
- `lot_received_date`
- `lot_expiry_date`

Interim standard (until real batch_id exists):
- build a **surrogate batch key** for diagnostics/attribution:
  - `surrogate_batch_id = store_id | product_id | lot_received_date | lot_expiry_date`

Important:
- this is a practical proxy, not a guaranteed globally unique warehouse batch id.
- use it for FEFO/attribution diagnostics, not as a permanent source-of-truth identifier.

### 8) Cluster-aware analysis target (for store-level tests)

For store-randomized experiments (especially inbound/waste):
- preferred analysis grain = `store-week`
- preferred methods:
  - regression with baseline adjustment (CUPED-like / baseline covariates),
  - cluster-robust SE by store
  - or cluster bootstrap as robust alternative

What to avoid:
- transaction-level t-test as primary evidence for a store-randomized effect.

### 9) Reporting minimums (AB report, methodology-first)

AB report should show, in one place:
- experiment class (inbound/waste, AOV, buyers, etc.)
- randomization unit vs analysis unit
- primary metric (and whether canonical or proxy)
- test side (`one-/two-sided`)
- chosen method + why
- effect size + CI + p-value
- MDE/power status
- SRM + invariants
- guardrails and decision rule outcome

## Implementation Phasing (Practical)

### Phase A (now, low-risk)

- keep P0 safety gates and preflight hard-fails
- formalize design fields (`pre_period`, `wash_in`, `attribution_window`) in artifacts
- label writeoff proxies explicitly
- add surrogate batch key policy in docs/contracts

### Phase B (next)

- canonical `store-week` AB fact for cluster tests
- formal SRM test + invariant checks
- cluster-aware statistics for store-level experiments

### Phase C (later)

- persisted `batch_id` / `lot_id` (or canonical lot fact)
- FEFO compliance and lot-attribution diagnostics in standard AB reports

---

## v2 Delta (Estimand-first + Formal SRM + Reasoning Trace rollout)

This section adds mandatory v2 behavior without removing current v1 fallback behavior.

### A) Inference must be estimand-first

Inference output must be anchored on experiment contract fields:

- `estimand_id`
- `primary_metric_id`
- `metric_semantics_id`
- `randomization_unit`
- `analysis_unit`

No implicit default to AOV is allowed when another primary metric is registered.

### B) Preflight before statistics (mandatory)

AB statistical computation must not start until `ab_preflight_result.v1` status is `PASS`.

If preflight is `FAIL`:

- inference status must be blocking,
- decision ceilings apply immediately,
- reports must display contract/measurement failure as primary state.

### C) Formal SRM (mandatory artifact)

SRM moves from heuristic to required formal test:

- produce `srm_check.v1`,
- include test name, p-value, observed vs expected split and imbalance,
- map to explicit status (`PASS` | `WARN` | `FAIL`).

For decisioning ceilings in v2:

- any status other than `PASS` blocks `RUN_AB` and `ROLLOUT_CANDIDATE`.

### D) Unit-aware inference constraints

`ab_inference_result.v2.unit_of_inference` must equal experiment `analysis_unit`.

Mismatch policy:

- hard status: `INVALID_METHODS`,
- no rollout-eligible decision.

### E) Decision ceilings (contract outcome)

The following states prohibit `RUN_AB` / `ROLLOUT_CANDIDATE`:

1. `measurement_state in {UNOBSERVABLE, BLOCKED_BY_DATA}`
2. `ab_preflight_result.status = FAIL`
3. `ab_inference_result.status = INVALID_METHODS`
4. `srm_check.status != PASS`
5. `causal_claims_grounded.grounded_status != PASS`

Normative contract:

- `configs/contracts/decision_contract_v2.json`

### F) Visible reasoning trace rollout (phased, low-risk first)

Feature flags:

- `ENABLE_VISIBLE_REASONING_TRACE` (default `0`)
- `CAPTAIN_ALLOW_NOVEL_ISSUES` (default `0`)
- `DOCTOR_DYNAMIC_HYPOTHESES` (default `0`)

Required provenance:

- active flag values must be recorded in `llm_provenance`.

`visible_reasoning_trace` structure (advisory first):

- `claims[]` with `claim_id`, `statement`, `evidence_refs`, `alternatives_considered`, `falsifiability_test`, `decision_impact`
- `gates_checked[]`
- `unknowns[]`

During advisory phase this trace must not change normalized decision logic.

### G) Security and robustness requirements for reasoning trace

Before persistence/publish:

1. redact secrets/tokens/DSN fragments from trace fields,
2. apply allowlist on accepted input fields,
3. enforce max length caps for trace arrays and strings,
4. keep novel issue mode gated by flag and grounding requirements.

### H) Adversarial and quality metrics rollout

New advisory metrics:

- `trace_completeness_rate`
- `alternative_hypothesis_quality`
- `falsifiability_specificity`
- `decision_change_sensitivity`

Rollout sequence:

1. advisory-only window (1-2 weeks),
2. partial critical checks,
3. full policy checks after stability sign-off.

### I) Event Bus ordering and correction policy

All AB v2 events must use common envelope and correction semantics:

- strict ordering by partition key `experiment_id` (or `run_id+experiment_id`),
- idempotency by `event_id`,
- silent correction forbidden; corrections via dedicated `...corrected.v1` events referencing original `event_id`.

### J) Tiered LLM policy for roadmap epic (approved)

This policy is normative for future implementation phases (A-F) and audit.

1. Tier 1 (primary): strong remote API model.
2. Tier 2 (fallback): local SLM (for example local Llama via Ollama), only when Tier 1 is unavailable or blocked by policy.
3. Tier 2 outputs must be explicitly marked as weak-path artifacts:
   - `audited_by_weak_model=true`
   - `tier_used="tier2_local_slm"`
   - `reconciliation_status in {PENDING, COMPLETED, EXPIRED}`
4. Weak-path decision ceiling is mandatory:
   - maximum allowed decision is `HOLD_NEED_DATA`,
   - weak-path output must never directly produce rollout-eligible decisions.
5. Asynchronous reconciliation is advisory only:
   - strong model may emit `recommended_override`,
   - automatic mutation of final decision by background worker is forbidden.
6. Human-in-the-loop is mandatory for any decision change proposed by reconciliation.

### K) Reconciliation SLA and operating mode (approved)

- SLA: `batch_nightly` only.
- Reconciliation is not real-time and must not block daytime transactional workloads.
- If nightly reconciliation does not run, weak-path artifacts remain in `HOLD_NEED_DATA` state.
- Escalation is by alert/report only, not by automatic decision rewrite.

### L) Runtime budget and request profile (8 GB total host constraint)

Runtime assumptions for planning and safety:

- host memory budget is constrained (`8 GB` total with DB + services + artifacts),
- one run corresponds to a `7-day` analytical window,
- large-context operations must be chunked.

Observed request profile from current `run_all_v13_agent_*` logs (12 runs analyzed):

- average LLM backend activations per run: `~4.83`,
- typical non-shadow run: `4` activations,
- heavier shadow/proof runs: `6-8` activations.

Request topics per run (current pipeline):

1. Agent-1 sanity validation of DQ/realism issues.
2. Agent-2 methodology/hypothesis reasoning (selection + summary path).
3. Agent-3 decision proposal and PM rationale layer.
4. Optional extra calls from retries/fallback branches.

Chunking and memory rules for roadmap implementation:

1. Build context bundles in chunks (`metrics`, `ab`, `dq`, `narrative`, `governance`) and merge by references, not by full raw concatenation.
2. Store intermediate chunk artifacts on disk and pass pointers in events.
3. Keep per-request context bounded and deterministic; do not rehydrate full historical corpora in one prompt.
4. Prefer nightly batch grouping by `run_id` and process sequentially to avoid parallel RAM spikes.

### M) Anti-loop policy (required for Tier-2 + reconciliation)

To prevent retry storms and cyclic reprocessing:

1. Per-stage retry cap must be finite and explicit.
2. Every reconciliation item must carry:
   - `reconcile_attempt_count`,
   - `max_reconcile_attempts`,
   - `next_retry_at` (for backoff),
   - terminal status when budget is exhausted.
3. Same `(run_id, experiment_id, source_event_id)` must be idempotent in reconciliation queue.
4. Reconciliation worker must never enqueue itself from its own output.
5. If attempts are exhausted or evidence remains inconsistent:
   - keep `HOLD_NEED_DATA`,
   - emit human review task,
   - stop automatic retries.

### N) Historical retrieval and mitigation policy (runtime)

1. Historical context is mandatory input for Agent-2 (`historical_context_pack_v1`) and must be built as:
   `semantic retrieval + structured fact pull` (`retrieval_mode=semantic_hybrid_mvp` in current runtime), not numeric-overlap-only heuristics.
2. Agent-3/Agent-2 must expose machine-readable proof of context usage:
   - `trace_refs[]` containing reference to `historical_context_pack`,
   - `artifact_hash_refs[]` containing `artifact_ref + sha256` for `historical_context_pack`,
   - `historical_context.used=true` and `pack_ref`.
3. `historical_retrieval_conformance_gate` must validate:
   - ref exists,
   - hash matches sidecar,
   - ref is used in reasoning/evidence sections.
   Formal reference without hash/evidence is `HISTORICAL_CONTEXT_INTEGRITY_FAIL`.
3. For `STOP/HOLD_*` decisions Agent-3 must provide mitigation-by-design:
   - either >=2 mitigation proposals with `applicability`, `risk_tradeoff`, `confidence`, `evidence_refs`, `required_data`,
   - or fallback `insufficient_evidence` with non-empty `required_data[]` + `next_validation_plan`.
4. Missing mitigation policy is fail-closed.

### O) Online/offline KPI contract

Per-run acceptance requires online KPI fields in system scorecard.
Offline KPI SLA:
- refresh age `<= 24h`: PASS,
- `24h < age <= 48h`: WARN (single-run non-blocking),
- `> 48h`: FAIL (`KPI_OFFLINE_STALE`) for nightly/release acceptance.
