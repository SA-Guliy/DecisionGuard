# Event Bus Contracts v2 (Public-Safe)

This document defines the public-safe transport contract for DecisionGuard experiment events.
It focuses on interoperability and fail-closed guarantees, without exposing internal operations playbooks.

Related specs:
- `docs/ab_data_contract_v1.md`
- `docs/metrics_contract_v1.md`
- `docs/ab_methodology_spec.md`

## 1) Unified Event Envelope (Required)

Every event must include:
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

Envelope schema:
- `configs/contracts/event_bus/envelope_v1.json`

## 2) Runtime Guarantees

- Partitioning is deterministic by experiment context.
- Event processing is idempotent by `event_id`.
- Contract incompatibility is fail-closed and routed to dead-letter handling.
- Silent mutation/correction is forbidden; corrected outputs must be explicit events with source linkage.

## 3) Public Topic Families

DecisionGuard uses versioned event families for:
- experiment registration and context,
- assignment and preflight outcomes,
- statistical inference and guardrail observations,
- governance decision proposals,
- reconciliation request/result lifecycle.

Exact schema files remain in `configs/contracts/event_bus/` as source of truth.

## 4) Blocking Invariants (Consumer-Side)

Consumers must enforce:
- experiment identity and metric identity consistency across related events;
- preflight and assignment validity before rollout-eligible decisions;
- no rollout-eligible decision when required guardrail/inference evidence is missing;
- immutable audit linkage across correction/reconciliation chains.

Violation of these invariants is fail-closed.

## 5) Reconciliation and Override Policy

- Weak/provisional paths are marked explicitly in events.
- Reconciliation outputs are advisory by default.
- Automated background workers must not silently mutate final governance decision artifacts.
- Decision changes require explicit governance/human approval artifacts per policy.

## 6) Anti-Loop and Retry Safety

- Reconciliation queue processing uses bounded retries.
- Backoff is mandatory for repeated failures.
- Terminal failures produce terminal status events.
- Replay requires explicit operator/governance action.

## 7) Naming and Public Narrative Alignment

Public narrative uses:
- `Agent-1` (data hygiene/sanity),
- `Agent-2` (hypothesis and causal analysis),
- `Agent-3` (final governance decision).

Low-level runtime identifiers may differ internally, but public-facing docs and contracts should keep this role mapping stable.

## 8) Public-Safe Scope

This document intentionally excludes:
- secret handling instructions,
- exact infrastructure sizing assumptions,
- internal-only migration/rollback paths,
- operator runbook details.

Those details belong to internal operations documentation, not public repository contracts.
