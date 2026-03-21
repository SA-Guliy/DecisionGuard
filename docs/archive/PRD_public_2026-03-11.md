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
5. Edge fallback (`cloud -> edge -> deterministic`) with provisional tagging and reconciliation path.
6. Consolidated executive reporting for batch runs.

## 4) User Stories & Acceptance Criteria (Given / When / Then)

### US-1 Domain template is mandatory
**Given** a run without `--domain-template` or with invalid template schema  
**When** `scripts/run_all.py` starts  
**Then** execution must stop before agent calls with `ConfigurationError` and non-zero exit.

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
**Then** system continues via edge path, marks output `[PROVISIONAL - LOCAL EDGE FALLBACK]`, sets `needs_cloud_reconciliation=true`.

### US-7 Executive observability
**Given** any completed run  
**When** traces and ledgers are written  
**Then** per-agent tokens, latency, model, backend tier, and estimated cost are available in machine-readable artifacts.

### US-8 Batch reporting without artifact spam
**Given** batch execution  
**When** consolidated report is generated  
**Then** one grouped markdown report is produced from summary SoT, and per-case spam artifacts are not persisted in active paths.

## 5) System & Technical Requirements (Non-Functional)

### 5.1 Reliability & Governance
1. Default mode is fail-closed.
2. Mandatory gate order is contract-driven and auditable.
3. No autonomous rollout mutation; only recommendation output with Human-in-the-Loop approval.

### 5.2 Performance & Capacity
1. Host memory budget target: 8 GB total.
2. Runtime concurrency target: `concurrency=1` for stable memory behavior.
3. Reconciliation SLA for MVP: `batch_nightly`.
4. Batch mode must support large case sets without per-case markdown explosion.

### 5.3 Security & Privacy
1. Cloud LLM calls are allowed only through secure gateway.
2. Sanitization/obfuscation policy is required for cloud path.
3. No direct runtime DDL execution in decision path.
4. Secret leakage checks run before publish.
5. Integrity sidecars are required in strict mode for critical artifacts.

### 5.4 Observability Standards
1. Per-agent trace fields: `model`, `backend`, `prompt_tokens`, `completion_tokens`, `total_tokens`, `latency_ms`, `cost_usd_estimate`.
2. Run-level status fields include fallback/reconciliation flags.
3. Batch-level KPI snapshot includes availability, FPR/FNR, and reconciliation match-rate.

## 6) Scope Definition

### 6.1 In Scope (MVP)
1. A/B governance for experiment decisioning with guardrail focus.
2. Historical context pack from existing local artifacts.
3. Edge fallback + provisional marking + reconciliation metadata.
4. Executive consolidated reporting and ROI scorecard generation.

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
4. Failover and reconciliation metadata are present and auditable.
5. Public PRD and README remain aligned with implemented behavior.
