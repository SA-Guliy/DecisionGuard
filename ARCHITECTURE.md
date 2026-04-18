# ARCHITECTURE (Public-Safe)

## Purpose
DecisionGuard is a fail-closed decision-governance runtime for experiments.

Public architecture goals:
- keep decision continuity under backend/model failures;
- protect sensitive data in cloud inference paths;
- preserve auditability and artifact integrity;
- enforce explicit gates before rollout-eligible decisions.

## System Boundaries
- Orchestration entrypoint: `scripts/run_all.py`
- Core role model:
  - `Agent-1`: data hygiene / sanity
  - `Agent-2`: hypothesis and causal analysis
  - `Agent-3`: final governance decision
- Runtime contour is broader than the simplified role chain and includes additional gated steps (for example evaluator/acceptance/publish checks).

Source of truth for runtime order, gates, and artifacts:
- `src/architecture_v3.py`

## Runtime Overview

### 1) Failover and Continuity
Decision execution uses deterministic fallback semantics:
1. cloud path
2. edge/local model path
3. deterministic local safe path

Public guarantees:
- fallback is explicit (never silent);
- provisional paths are marked and require reconciliation;
- policy violations are fail-closed.

Source of truth:
- `src/runtime_failover.py`
- `src/model_policy.py`

### 2) Secure LLM Gateway
Any cloud LLM path must pass secure gateway controls.

Public guarantees:
- sanitization before cloud call;
- controlled local re-mapping/deobfuscation;
- contract integrity checks for gateway policies;
- auditable artifact trail with integrity sidecars.

Source of truth:
- `src/llm_secure_gateway.py`
- `src/sanitization_transform.py`
- `configs/contracts/sanitization_policy_v2.json`

### 3) Integrity and Audit
DecisionGuard treats integrity as blocking:
- missing required artifact/sidecar => fail-closed;
- invalid schema/contract => fail-closed;
- inconsistent gate sequence => fail-closed.

Audit surfaces include:
- gate results,
- fallback provenance,
- reconciliation markers,
- decision artifacts.

## Decision Governance Lifecycle

Conceptual lifecycle used in product narrative:
`S1 -> S2 -> S3 -> S4 -> S5`

Where:
- `S1`: Data hygiene (Agent-1)
- `S2`: Hypothesis draft (Agent-2)
- `S3`: Prelaunch audit (Agent-3)
- `S4`: Experiment run
- `S5`: Final governance (Agent-3)

Important:
- This lifecycle is conceptual;
- runtime execution includes additional machine gates and checks beyond the simplified 5-step view.

## Evidence Layers
Decision quality is built on multiple evidence layers:
- current run metrics and guardrails,
- historical retrieval context (RAG-style retrieval),
- statistical evidence artifacts used by runtime policy/gates.

Public principle:
- outcome metrics alone are not sufficient for final governance;
- rationale must be evidence-linked and gate-compliant.

## Paired Experiment and Safe Ceiling
When paired context is incomplete/failed, decision ceilings are applied.

Public guarantee:
- incomplete evidence cannot silently produce aggressive rollout decisions.

## Reconciliation Model
If decisioning used fallback/provisional paths:
- run is marked for reconciliation;
- reconciliation is auditable;
- policy determines whether human/governance approval is required for any decision change.

## Failure Semantics
DecisionGuard prefers explicit failure over silent degradation.

Examples of fail-closed classes:
- contract/integrity violations,
- missing required evidence artifacts,
- disallowed cloud path behavior,
- critical gate failures.

## Operational Scope (Public-Safe)
This document intentionally does not include:
- secret material instructions,
- internal runbook commands and migration paths,
- environment-specific operational thresholds,
- internal-only troubleshooting playbooks.

Internal operations runbooks are maintained separately from public architecture docs.

## References
- `README.md`
- `AGENT_EVAL.md`
- `src/architecture_v3.py`
- `src/runtime_failover.py`
- `src/llm_secure_gateway.py`
- `src/model_policy.py`
