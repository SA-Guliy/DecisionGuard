# PRD — Privacy-First AI Decision Governance Layer (Public)

## 1) Product Positioning
**Product:** Privacy-First AI Decision Governance Layer  
**Category:** Decision risk-control runtime for experimentation programs  
**Tagline:** Prevent false-success rollouts without slowing safe iteration.

This document is a **public PRD** for GitHub. It defines testable behavior, engineering constraints, and scope boundaries for the MVP.

## 2) Problem Statement
Teams often ship initiatives that look successful on one primary metric but silently degrade guardrail metrics (margin, availability, retention, support load).  
The system must detect those hidden risks early, produce auditable decisions, and preserve business continuity under cloud outages.

## 3) MVP Scope (In Scope)
1. Domain-agnostic decision runtime driven by external `domain_template`.
2. Multi-agent sequence (`Captain -> Doctor -> Commander`) with contract gates.
3. Historical context retrieval (semantic + structured facts) for decision support.
4. Fail-closed acceptance and pre-publish checks.
5. Edge fallback (`cloud -> edge -> deterministic`) with provisional tagging, reconciliation metadata, and runtime reconciliation worker (accept/update with human approval gate — see §9).
6. Consolidated executive reporting for batch runs.
7. Synthetic simulation engine: live PostgreSQL-backed darkstore environment, +7 days per run, parameterizable demand/supply/ops knobs, built-in realism scorer.

## 4) User Stories & Acceptance Criteria (Given / When / Then)

### US-1 Domain template is mandatory
**Given** a run without `--domain-template` or with invalid template schema  
**When** `scripts/run_all.py` starts  
**Then** execution must stop before agent calls with `ConfigurationError` and non-zero exit.

### US-1a Experiment context is mandatory
**Given** a run without `--experiment-id`  
**When** `scripts/run_all.py` starts  
**Then** execution must stop fail-closed with `EXPERIMENT_CONTEXT_REQUIRED` and actionable remediation text.

### US-1b 14-day decision eligibility
**Given** an experiment with fewer than 14 observed days for the same `experiment_id`  
**When** governance gates execute before evaluator/commander  
**Then** aggressive final decisions (`GO`, `RUN_AB`, `ROLLOUT_CANDIDATE`) are blocked and decision ceiling remains `HOLD_NEED_DATA`.

### US-2 Fail-closed integrity
**Given** any required artifact/contract without valid `.sha256` sidecar (strict mode)  
**When** runtime or acceptance loads the artifact  
**Then** run is blocked (`HOLD_NEED_DATA` or hard fail) and audit event is recorded.

### US-3 Captain routing determinism
**Given** Captain output with `sanity_status=PASS`  
**When** orchestration evaluates routing  
**Then** Doctor and Commander must execute (no false short-circuit).

### US-4 Historical risk detection
**Given** a hypothesis with local primary uplift and historically similar guardrail breaches  
**When** Doctor/Commander process `historical_context_pack`  
**Then** decision must be `HOLD_NEED_DATA` or `STOP_ROLLOUT` with explicit rationale and mitigation actions.

### US-5 Safe iteration support (Calculated Risk)
**Given** a hypothesis with clear primary lift and no material guardrail evidence  
**When** Commander issues final decision  
**Then** decision may be `GO`, with monitoring conditions in `next_steps`.

### US-6 Zero-downtime continuity
**Given** cloud model/API outage
**When** agents execute via failover policy
**Then** system continues via edge (Ollama) or deterministic local path, marks output `[PROVISIONAL - LOCAL EDGE FALLBACK]`, sets `needs_cloud_reconciliation=true`, and returns a usable decision artifact to the operator.

### US-6a Provisional decision is operationally usable
**Given** a provisional decision produced under cloud outage
**When** operator receives the decision artifact
**Then** the artifact contains a complete decision (`GO` / `HOLD_NEED_DATA` / `STOP_ROLLOUT`), rationale, and explicit provisional warning — it is not a partial or empty response.

### US-6b Cloud reconciliation on recovery
**Given** a run previously marked `needs_cloud_reconciliation=true`
**When** cloud API becomes available again and reconciliation worker executes
**Then** the worker re-runs the same case against the cloud LLM and produces one of two outcomes:
- **ACCEPTED**: cloud decision matches provisional → artifact is sealed with `reconciliation_status=accepted`
- **UPDATED**: cloud decision differs → provisional artifact is replaced with the cloud version, `reconciliation_status=updated`, and the delta is logged for audit

**Implementation status**: US-6, US-6a, and US-6b are all implemented. See §9 for remaining open items.

### US-7 Executive observability
**Given** any completed run  
**When** traces and ledgers are written  
**Then** per-agent tokens, latency, model, backend tier, and estimated cost are available in machine-readable artifacts.

### US-8 Batch reporting without artifact spam
**Given** batch execution
**When** consolidated report is generated
**Then** one grouped markdown report is produced from summary SoT, and per-case spam artifacts are not persisted in active paths.

### US-8a Audit trail completeness
**Given** any LLM call through the secure gateway
**When** the call completes (success or failure)
**Then** an entry is appended to the immutable `audit_log.jsonl` containing: `run_id`, `policy_ref`, `backend`, `model`, `timestamp`, `obfuscation_map_ref`. No call may be made without an audit entry.

### US-8b Artifact integrity enforcement
**Given** any critical artifact (contract, gate result, decision record) loaded at runtime
**When** the artifact is read
**Then** its SHA256 sidecar must be present and match. Mismatch or missing sidecar = immediate `FAIL` with `INTEGRITY_SIDECAR_MISMATCH` error code. No silent skip.

### US-9 Synthetic simulation advances state
**Given** a configured simulation environment with PostgreSQL
**When** `scripts/make_metrics_snapshot_v1.py` runs
**Then** the simulation clock advances by +7 days, all 8 simulation tables are updated, and the built-in realism scorer validates `fill_rate_mean ∈ [0.93, 0.97]`.

### US-10 Synthetic realism guard
**Given** a simulation run where realism scorer detects out-of-range metrics
**When** snapshot is finalized
**Then** scorer emits a recommendation report with specific knob adjustments — it does not silently accept unrealistic data.

## 5) System & Technical Requirements (Non-Functional)

### 5.1 Reliability & Governance
1. Default mode is fail-closed.
2. Mandatory gate order is contract-driven and auditable.
3. Final aggressive decision eligibility requires at least 14 days of evidence for the same `experiment_id`.
4. No autonomous rollout mutation; only recommendation output with Human-in-the-Loop approval. When reconciliation produces an `updated` outcome (cloud decision differs from provisional), `human_approval_required=true` is set in the artifact — cloud override is never auto-applied.
5. Provisional decisions are complete operational outputs, not error states. Every provisional artifact must contain a full decision, rationale, and `needs_cloud_reconciliation=true` flag.
6. Reconciliation outcome must be one of two explicit states: `accepted` (provisional confirmed) or `updated` (cloud decision replaces provisional). Silent reconciliation is not permitted.
7. Doctor and Commander must be served by a reasoning model for at least the first two fallback tiers. Model policy (`src/model_policy.py`) is the single source of truth: Doctor chain — `qwen/qwen3-32b` → `openai/gpt-oss-120b` → `llama-3.3-70b-versatile` → `openai/gpt-oss-20b`; Commander chain — `qwen/qwen3-32b` → `openai/gpt-oss-20b` → `llama-3.3-70b-versatile`. `openai/gpt-oss-*` models confirmed as reasoning via `reasoning_tokens` in API response.

### 5.2 Performance & Capacity
1. Host memory budget target: 8 GB total.
2. Runtime concurrency target: `concurrency=1` for stable memory behavior.
3. Reconciliation SLA for MVP: `batch_nightly` — runtime worker implemented (see §9 for remaining gaps).
4. Batch mode must support large case sets without per-case markdown explosion.

### 5.3 Security & Privacy
1. Cloud LLM calls are allowed only through secure gateway.
2. Sanitization/obfuscation policy is required for cloud path. Sensitive values must be replaced with vectorized placeholders before any cloud call; reverse mapping is applied to response.
3. Obfuscation maps must be encrypted (AES-256-CBC + PBKDF2, KMS envelope with separated data key and master key). Roundtrip decrypt verification is required before map is stored.
4. ACL enforcement: obfuscation map reads are gated by `allowed_readers` list from sanitization policy contract.
5. No direct runtime DDL execution in decision path.
6. Secret leakage checks run before publish.
7. Integrity sidecars are required in strict mode for critical artifacts.

### 5.4 Observability Standards
1. Per-agent trace fields: `model`, `backend`, `prompt_tokens`, `completion_tokens`, `total_tokens`, `latency_ms`, `cost_usd_estimate`.
2. Run-level status fields include fallback/reconciliation flags.
3. Batch-level KPI snapshot includes availability, FPR/FNR. Reconciliation match-rate metric is available once the E2E integration test baseline is established (P3 backlog — see §9).

## 6) Scope Definition

### 6.1 In Scope (MVP)
1. A/B governance for experiment decisioning with guardrail focus.
2. Historical context pack from existing local artifacts.
3. Edge fallback + provisional marking + reconciliation worker (accept/update with human approval gate, anti-loop guard, delta audit log).
4. Executive consolidated reporting and ROI scorecard generation.
5. Synthetic simulation engine for darkstore domain (live, not static fixtures).

### 6.2 Out of Scope (Current MVP)
1. Full autonomous rollout execution.
2. Real-time reconciliation worker with sub-minute SLA.
3. Proprietary business formulas and internal strategic playbooks in public repo.
4. Competitor intelligence, internal market strategy notes, confidential unit-economics formulas.
5. Managed external vector database operations as required infrastructure (MVP uses lightweight/local retrieval modes).

## 7) Public vs Private Documentation Policy

### 7.1 Public (GitHub)
- User stories and acceptance criteria.
- Runtime behavior and non-functional constraints.
- Security posture at policy level.
- MVP boundaries and known limitations.

### 7.2 Private (Do not publish)
- Real margin/COGS/profit formulas and board-level KPI decomposition.
- Sensitive unit-economics thresholds and pricing strategy logic.
- Internal competitor analysis and GTM battlefield notes.
- Internal incident postmortems with sensitive operational details.

Recommended private locations (outside public repo):
- `.cursor/prd/` (private local workspace)
- secure internal docs storage / private repository

## 8) Release Readiness (Public Checklist)
1. All critical acceptance checks pass in strict mode.
2. No secrets or private strategy content in repo artifacts.
3. Consolidated reports are generated from verified SoT inputs.
4. Failover metadata and provisional tagging are present and auditable.
5. Public PRD and README remain aligned with implemented behavior.
6. Known gaps documented honestly (see §9) — no overstated capability claims.

## 9) Known Gaps & Calibration Roadmap

These are intentional PoC simplifications. Each is documented in code and tracked for production readiness.

| Gap | Current State | Status | Path to Production |
|-----|--------------|--------|--------------------|
| Reconciliation runtime | Worker implemented: fallback, provisional tagging, re-run on recovery, `accepted`/`updated` outcomes, delta logging, human approval gate, anti-loop guard | `IMPLEMENTED` | Monitor reconciliation match rate; establish E2E test baseline (P3) |
| Doctor primary goal alignment | Fixed: `ab_primary_goal` added to experiment header; goal alignment enforced at prompt level. `reasoning_quality` score: **0.42 → 0.74** (`v13_agent_value_001` → stable production); Doctor score: **0.10 → 0.50**. Source: `data/agent_eval/`. Regression in `prod_011/013` (score capped at 0.30, `ab_status_invalid_methods`) resolved by this fix. | `IMPLEMENTED` (2026-03-20) | Stable — included in ongoing eval runs |
| Paired experiment mode | Control and treatment run under the same experiment ID; paired registry with lifecycle governance, fail-closed ceiling enforcement for partial runs, 4 new error codes, 46 new tests | `IMPLEMENTED` (2026-03-21, v2.2) | Activate via `--mode paired`; corpus auto-update after 4+ complete paired runs |
| GROQ API key auto-loading | Runtime auto-loads key from `~/.groq_secrets` on startup — no manual `export` required; key never printed or logged; format validated before use | `IMPLEMENTED` (2026-03-21) | Stable — documented in Quick Start and `.env.example` |
| Structured reasoning output (Staff-level) | Agents produce Layer 3 (historical) only; no live statistical evidence in reasoning; `reasoning_confidence` is a static default, not computed | `IN PROGRESS` | Stat engine (live p-value/CI per metric) + structured CoT template for all agents; dynamic confidence score |
| Live statistical evidence in agent reasoning | `src/stat_engine.py` implemented: Welch's t-test, Delta Method for ratio metrics, SRM detection, `StatEvidenceBundle` output. Infrastructure complete; injection into Doctor/Commander prompt context is next sprint | `IMPLEMENTED (infrastructure)` — agent context injection in progress | Inject `StatEvidenceBundle` into Doctor/Commander system prompt; requires paired mode active |
| Reasoning confidence calibration | `src/reasoning_confidence.py` implemented: policy-driven score from `reasoning_confidence_policy_v1.json`; caps at 0.60 for partial/failed runs, 0.64 single-mode, penalties per missing layer | `IMPLEMENTED` (2026-03-21) | Stable — validated against demo suite (avg confidence 0.77 across 3 cases) |
| Reconciliation directory guard | `_find_pending_runs` may fail if `data/reconciliation/` does not exist on clean install | `P2 — open` | Add `Path.exists()` guard before glob; return `[]` on missing directory |
| Reconciliation E2E integration test | 6 unit tests pass. No end-to-end pipeline test of full `run_all.py` → worker → artifact flow | `P3` — backlog | Add integration test that runs full chain and asserts reconciliation artifact state |
| FPR calibration | 40% in mass_test_003 (conservative by design at PoC stage) | Known — by design | Structured CoT improvements targeting FPR <15% |
| GP Margin definition | `revenue − product COGS` only | Intentional PoC simplification | Add delivery cost allocation when real cost ledger is available |
| Churn rate in short windows | Returns 0.0 on short simulation runs | Expected — insufficient history | Minimum 30-day window recommended for non-zero churn signal |
| Real data validation | Not yet tested on production data | PoC stage | Required before production deployment |
| `blocked_by_data` metrics | `doi`, `inventory_turnover`, `days_to_expiry_dist`, `aged_inventory_share` return null | Data not yet in simulation tables | Add to simulation schema in next iteration |
