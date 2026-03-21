# Event Bus Contracts v2 (AB Domain)

This document defines the transport-level contract for AB events.
It complements:

- `docs/ab_data_contract_v1.md`
- `docs/metrics_contract_v1.md`
- `docs/ab_methodology_spec.md`

## 1) Unified Envelope (mandatory)

Every published event must include:

- `event_id`
- `event_type`
- `schema_version`
- `occurred_at`
- `producer`
- `trace_id`
- `run_id`
- `experiment_id`
- `payload_hash`
- `payload`

Schema file:

- `configs/contracts/event_bus/envelope_v1.json`

## 2) Bus Runtime Guarantees

1. Partition key: `experiment_id` (or composite `run_id+experiment_id`).
2. Idempotency key: `event_id`.
3. Upsert policy key: `(run_id, experiment_id, schema_version)`.
4. Registry compatibility mode: `BACKWARD_TRANSITIVE`.
5. Contract violations route to DLQ with explicit `error_family/error_code`.
6. Silent correction is forbidden. Corrections must publish `...corrected.v1` and include source `event_id`.

## 3) Topic -> Schema matrix

| Schema | Topic | Producer | Primary consumers |
|---|---|---|---|
| `experiment_contract.v2` | `ab.experiment.registered.v2` | orchestrator/planner | preflight, doctor, commander, reports |
| `assignment_log.v1` | `ab.assignment.exposed.v1` | assignment service | preflight, srm, ab_analysis |
| `ab_preflight_result.v1` | `ab.preflight.completed.v1` | preflight service | doctor, commander, reports |
| `srm_check.v1` | `ab.srm.completed.v1` | srm service | doctor, commander, reports |
| `ab_unit_outcomes.v1` | `ab.unit_outcomes.materialized.v1` | feature/data mart | ab_analysis |
| `metric_semantics_registry.v1` | `metrics.semantics.published.v1` | metrics governance | preflight, doctor, reports |
| `guardrail_observations.v1` | `ab.guardrails.observed.v1` | ab_analysis | commander, reports |
| `ab_inference_result.v2` | `ab.inference.completed.v2` | ab_analysis | doctor, commander, reports |
| `decision_contract_result.v2` | `ab.decision.proposed.v2` | commander | governance, reports |
| `causal_claims_grounded.v2` | `ab.causal.grounded.v2` | narrative validator | governance, reports |
| `weak_reasoning_result.v1` | `ai.reasoning.weak_path_detected.v1` | captain/doctor/commander runtime | reconciliation queue, governance, reports |
| `reconciliation_request.v1` | `ai.reconciliation.requested.v1` | runtime orchestrator | reconciliation worker |
| `reconciliation_result.v1` | `ai.reconciliation.completed.v1` | reconciliation worker | governance, acceptance, reports |
| `recommended_override.v1` | `ai.reconciliation.recommended_override.v1` | reconciliation worker | human approver UI, governance |

Schema files:

- `configs/contracts/event_bus/*.json`

## 4) Blocking invariants (must be enforced by consumers)

1. `experiment_contract.v2.primary_metric_id` is immutable.
2. `experiment_contract.v2.randomization_unit` and `analysis_unit` are mandatory.
3. `assignment_log.v1` must have unique `(experiment_id, unit_id)` and both arms present.
4. `ab_preflight_result.v1.status = FAIL` blocks inference and rollout decisions.
5. `srm_check.v1.status != PASS` blocks rollout and causal claims.
6. `ab_inference_result.v2.unit_of_inference` must equal experiment `analysis_unit`.
7. Any metric in inference/guardrails must resolve in `metric_semantics_registry.v1`.
8. Weak-path artifacts must enforce decision ceiling `HOLD_NEED_DATA`.
9. Reconciliation is advisory only: events may propose override, but must not mutate final decision automatically.
10. Every reconciliation chain must be idempotent by `(run_id, experiment_id, source_event_id)`.

## 5) Rollout model

1. Produce v1 legacy + v2 bus events in parallel.
2. Compare decision divergence and false-positive rate for 2 weeks.
3. Switch readers to v2-first.
4. Decommission legacy fallback only after cutover acceptance.

## 6) Tier-2 + Reconciliation contract rules (approved policy)

### 6.1 Weak-path event requirements

`ai.reasoning.weak_path_detected.v1` payload must include:

- `tier_used` (`tier2_local_slm`)
- `audited_by_weak_model` (`true`)
- `weak_model_name`
- `source_agent` (`captain|doctor|commander`)
- `decision_ceiling_applied` (`HOLD_NEED_DATA`)
- `source_event_id`
- `reconciliation_status` (`PENDING`)

Producer rule:

- weak-path output must never publish rollout-eligible decision events.

### 6.2 Reconciliation request and result

`ai.reconciliation.requested.v1` must include:

- `source_event_id`
- `requested_at`
- `sla_mode` (`batch_nightly`)
- `reconcile_attempt_count`
- `max_reconcile_attempts`

`ai.reconciliation.completed.v1` must include:

- `source_event_id`
- `reconciliation_status` (`COMPLETED|EXPIRED|FAILED`)
- `strong_model_name`
- `consistency_verdict` (`CONFIRMED|DISAGREED|INCONCLUSIVE`)
- `recommended_override` (object or `null`)
- `auto_decision_change_applied` (`false`, mandatory)

### 6.3 Human-in-the-loop enforcement

- `ai.reconciliation.recommended_override.v1` is a human review signal only.
- Background workers are forbidden from changing `decision` or `normalized_decision`.
- Final decision changes require explicit manual approval artifact.

## 7) Resource limits and chunking profile (8 GB host budget)

Given shared host memory constraints (8 GB total), bus consumers/producers must:

1. Process reconciliation queue in bounded nightly batches.
2. Use payload references to artifacts; avoid embedding large raw blobs in event payload.
3. Chunk heavy context by domain block (`dq`, `ab`, `metrics`, `narrative`, `governance`) and persist chunk pointers.
4. Cap concurrent reconciliation workers to prevent memory spikes.

## 8) Anti-loop and retry safety

1. Each reconciliation item must have finite retry budget.
2. Exponential backoff must be used between retries.
3. Worker must not emit a new request for the same terminal item.
4. On exhausted retries, emit terminal event and keep run in `HOLD_NEED_DATA`.
5. DLQ replay requires explicit operator action and writes a new audit event.

## 9) Runtime alignment with Blueprint v2.1

Event bus semantics are now coupled to runtime gates:

1. `historical_retrieval_gate` validates availability/integrity of historical context before Doctor.
2. `historical_retrieval_conformance_gate` validates real consumption of `historical_context_pack` by Doctor and Commander.
3. Runtime cloud policy is evaluated for all scripts executed from `run_all.py` scope.
4. Any cloud LLM path (runtime + POC) is allowed only via `src/llm_secure_gateway.py` and must emit:
   - `obfuscation_map_ref`,
   - run-scoped obfuscation manifest,
   - audit trail entry.
5. Error-code mapping is explicit in acceptance/runtime:
   - `HISTORICAL_CONTEXT_MISSING`
   - `HISTORICAL_CONTEXT_INTEGRITY_FAIL`
   - `HISTORICAL_CONTEXT_UNUSED`
   - `SANITIZATION_REQUIRED_FOR_CLOUD`
   - `SANITIZATION_MAP_POLICY_VIOLATION`
   - `SANITIZATION_AUDIT_TRAIL_MISSING`
   - `MITIGATION_PROPOSALS_MISSING`
   - `KPI_ONLINE_MISSING`
   - `KPI_OFFLINE_STALE`
   - `KPI_LEDGER_MISSING`

These violations are fail-closed in critical runtime/acceptance paths.
