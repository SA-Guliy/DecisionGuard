# AB Data Contract v1 (Draft)

This document defines **what data must exist** before AB analysis is allowed to run.

It is separate from:
- `docs/metrics_contract_v1.md` (what metrics mean),
- `docs/ab_methodology_spec.md` (how we interpret AB results),
- agent prompts (how agents explain decisions).

The goal of this contract is to prevent:
- silent fallbacks,
- fake observability,
- runtime joins that hide root cause,
- "methodology mismatch" being used for pure data/schema problems.

## Why This Exists

AB analysis should run only when:
1. The requested experiment exists.
2. The requested analysis grain is available.
3. Required columns are present.
4. Joins are valid and sufficiently complete.
5. The metric can be computed on the requested unit.

If any item fails:
- AB statistical analysis must **not** proceed,
- the system should emit a **preflight failure** with a precise error code,
- downstream agents can read the failure and request the missing data/fix.

## Contract Layers (Important Separation)

### 1) Data Contract (this doc)
"Do we have the right columns/grain/joins to run analysis?"

Examples:
- missing `customer_id`
- assignment join not available
- join coverage too low
- required artifact missing

### 2) Methodology Contract (`docs/ab_methodology_spec.md`)
"Given valid data, is the AB method/design valid?"

Examples:
- customer-randomized experiment analyzed at store level
- invalid metric-method pair
- p-value / CI contradiction

### 3) Decision Contract (`configs/contracts/decision_contract_v1.json`)
"What actions are allowed given AB/methodology state?"

Examples:
- no rollout when unobservable
- no GO when invalid methods

## Required Artifacts (AB Path)

Minimum required artifacts before final AB decisioning:

| Artifact | Purpose | Required |
|---|---|---|
| Assignment log (`step1.*experiment_assignment*`) | Defines `arm` per unit | Yes |
| Order fact (step1 / valid view) | Observed outcomes (`order_gmv`, etc.) | Yes |
| Metrics snapshot (`data/metrics_snapshots/<run_id>.json`) | Run config + context | Yes |
| Agent-2/Evaluator outputs | Goal + measurement state for alignment and report | Yes (for full v2 report) |

Planned (v2 contract hardening):
- `ab_input_fact_order` (canonical AB analysis fact)
- `customer_window_features` (cohort- and customer-level AB features)
- `cohort_evidence_pack` (compact aggregated cohorts for Agent-2/Agent-3)
- `surrogate_batch_id` (interim lot key from `store_id|product_id|lot_received_date|lot_expiry_date` for writeoff attribution diagnostics until real batch/lot id is persisted)

## Goal1 Canonical Checklist (required for writeoff/expiry decisioning)

Required fields (must be present and computable in runtime facts):
- `store_id`
- `product_id` (or `sku`)
- `date` / `iso_week`
- `received_units`
- `received_cogs`
- `sold_units`
- `sold_cogs`
- `writeoff_units`
- `writeoff_cogs`
- `writeoff_reason` (normalized taxonomy)
- `expiry_date`
- `batch_id`

Preferred fields:
- `supplier_id`
- `purchase_order_id`
- `category_id`

Coverage thresholds for Goal1-ready status:
- `writeoff_reason` coverage >= `99%`
- `expiry_date` coverage >= `99%`
- `batch_id` coverage >= `95%`

## Required Grain by Experiment Unit

### Customer-randomized experiments

Required analysis grain:
- customer-level capable data (directly or via canonical customer-window features)

Required fields (minimum):
- `run_id`
- `experiment_id`
- `customer_id`
- `arm` (or a validated deterministic join to assignment on `customer_id`)
- outcome fields required by primary metric (e.g. `order_gmv` or aggregated `customer_gmv`)

Hard fail examples:
- `customer_id` missing
- assignment exists only at store level
- join to assignment on `customer_id` not possible / coverage too low

### Store-randomized experiments

Required analysis grain:
- store-level or cluster-aware design-compatible aggregation

Required fields (minimum):
- `run_id`
- `experiment_id`
- `store_id`
- `arm`
- outcome fields for primary metric

Note:
- Large order count inside stores does **not** create independent store-level units.
- Methodology must stay cluster-aware (see `docs/ab_methodology_spec.md`).
- For writeoff/expiry analysis, attribution window and (temporary) surrogate lot/batch key policy must be explicit.

## Required Columns by Metric Family (Minimum)

| Metric family | Example metrics | Required fields (minimum) |
|---|---|---|
| Continuous means | `aov`, `gmv`, `gp_per_order` | outcome value per analysis unit + `arm` |
| Proportions | `buyers`, conversion-like rates | binary/count outcome per analysis unit + denominator logic + `arm` |
| Ratio metrics | `gp_margin`, `fill_rate_units`, `oos_lost_gmv_rate` | numerator + denominator on valid analysis unit + `arm` |

If numerator/denominator cannot be computed on the requested unit:
- this is a **data/method contract failure** (not a rollout decision issue).

## Join Rules (Do Not Hide with Fallbacks)

Rules:
1. Final AB path must not silently change analysis unit (`customer -> store`).
2. Runtime fallback joins to `raw.*` are allowed only for diagnostics, not for final decisioning.
3. Join coverage must be measured and reported.

Recommended checks (preflight):
- `missing_key_rate`
- `join_match_rate`
- duplicates after join (1:N blow-up)
- null rate on required columns

## Preflight Failure Taxonomy (Required)

Preflight must emit **precise** codes instead of broad labels.

Examples:

| error_family | error_code | Meaning |
|---|---|---|
| `DATA_SCHEMA` | `DATA_COLUMN_MISSING_CUSTOMER_ID` | Required column is absent |
| `DATA_JOIN` | `DATA_JOIN_CUSTOMER_GRAIN_UNAVAILABLE` | Cannot build valid customer-level join |
| `DATA_JOIN` | `DATA_JOIN_COVERAGE_BELOW_THRESHOLD` | Join technically works, but coverage too low |
| `DATA_ACCESS` | `DATA_PERMISSION_DENIED_RAW_ORDERS` | Role cannot read required source |
| `CONTRACT` | `CONTRACT_EXPERIMENT_ID_MISSING` | Run config / experiment id absent |
| `CONTRACT` | `CONTRACT_GOAL_METRIC_MISMATCH` | Hypothesis target goal != AB primary metric goal |
| `METHOD` | `METHOD_ANALYSIS_UNIT_MISMATCH` | Valid data exists but wrong analysis unit for design |
| `STATS` | `STATS_METHOD_INCONSISTENCY` | p-value/CI contradiction or invalid pairing |

## Human-readable Reporting Requirement

JSON is machine-first. Every AB diagnostic/preflight artifact should also have a human-readable report:
- Markdown table summary,
- grouped by blocks,
- counts + root causes + examples.

This is required for debugging patterns across runs (not only one run).

## Agent Read Rules (Current + Planned)

- Agent 1 (Agent-1 / realism-safety): reads quality/realism and safety artifacts.
- Agent 2 (Agent-2): reads Agent 1 outputs + AB preflight + cohort evidence pack.
- Agent 3 (Agent-3): reads all agent outputs + AB preflight + AB report + memory registries.

## Status of This Contract

Current status: **Draft v1**

What is already implemented (partially):
- AB failure taxonomy fields in `run_ab_analysis` output (`failure_meta`)
- AB failure registry report (`scripts/build_ab_failure_registry.py`)

What remains to implement:
- dedicated `run_ab_preflight.py`
- canonical `ab_input_fact_order`
- `customer_window_features`
- `cohort_evidence_pack`
- strict no-fallback final AB path

---

## v1.1 Delta (Estimand-first + Event Bus-ready)

This section is normative for the new architecture layer and must be read together
with the existing v1 contract text above.

### Mandatory fields in experiment contract (no silent defaults)

The following fields are now required for any new AB registration artifact:

- `estimand_id`
- `business_goal_id`
- `primary_metric_id`
- `metric_semantics_id`
- `randomization_unit`
- `analysis_unit`
- `attribution_window_rule`

Hard requirements:

1. `primary_metric_id` is immutable after registration.
2. `randomization_unit` and `analysis_unit` must be explicit (never inferred silently).
3. Any unit remap (`customer -> store`, `store -> customer`) is forbidden for final inference.
4. Any correction must be emitted as a separate `...corrected.v1` event with reference to original event id.

### Preflight and inference gate (blocking)

Preflight becomes mandatory and must execute before any AB statistical inference.

If preflight status is `FAIL`, inference is blocked.

Blocking preflight dimensions:

- required fields present/missing,
- join coverage,
- unit alignment,
- measurement state.

### Formal SRM artifact (mandatory)

SRM is not advisory anymore at contract level.
Each AB run must produce `srm_check.v1` with:

- expected split,
- observed counts by arm,
- formal test id (chi-square/binomial by design),
- p-value,
- imbalance (pp),
- `status`.

If `status != PASS`, rollout and causal claims are blocked by contract ceiling.

### Unit-aware analysis artifact

AB inference must consume `ab_unit_outcomes.v1` materialized strictly at `analysis_unit`.

Blocking invariant:

- if `unit_of_inference != analysis_unit` from experiment contract,
  output status must be `INVALID_METHODS`.

### Event Bus contracts in scope

Required topic payload schemas:

- `experiment_contract.v2` -> `ab.experiment.registered.v2`
- `assignment_log.v1` -> `ab.assignment.exposed.v1`
- `ab_preflight_result.v1` -> `ab.preflight.completed.v1`
- `srm_check.v1` -> `ab.srm.completed.v1`
- `ab_unit_outcomes.v1` -> `ab.unit_outcomes.materialized.v1`
- `metric_semantics_registry.v1` -> `metrics.semantics.published.v1`
- `guardrail_observations.v1` -> `ab.guardrails.observed.v1`
- `ab_inference_result.v2` -> `ab.inference.completed.v2`
- `decision_contract_result.v2` -> `ab.decision.proposed.v2`
- `causal_claims_grounded.v2` -> `ab.causal.grounded.v2`

Schema files live in:

- `configs/contracts/event_bus/`

### Unified event envelope requirements

All events above must be wrapped by envelope fields:

- `event_id`, `event_type`, `schema_version`, `occurred_at`,
- `producer`, `trace_id`, `run_id`, `experiment_id`, `payload_hash`.

Bus/runtime invariants:

1. Partition key: `experiment_id` (or composite `run_id+experiment_id`).
2. Idempotency: by `event_id`.
3. Upsert key: `(run_id, experiment_id, schema_version)`.
4. Schema compatibility mode: `BACKWARD_TRANSITIVE`.
5. Contract violations go to DLQ with `error_family/error_code`.

### Decision ceilings (contract-level)

If any of these conditions is true:

- `measurement_state in {UNOBSERVABLE, BLOCKED_BY_DATA}`,
- `ab_inference.status = INVALID_METHODS`,
- `ab_preflight.status = FAIL`,
- `srm_check.status != PASS`,
- `causal_claims_grounded.grounded_status != PASS`,

then decisions `RUN_AB` and `ROLLOUT_CANDIDATE` are forbidden.

See:

- `configs/contracts/decision_contract_v2.json`

### Compatibility and rollout

This upgrade is additive and supports dual-run:

1. Produce both legacy and v2 artifacts.
2. Compare decisions and false-positive rate for 2 weeks.
3. Cut over to v2 readers.
4. Remove legacy fallback paths after cutover sign-off.
