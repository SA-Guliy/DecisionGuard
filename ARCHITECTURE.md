# ARCHITECTURE: Runtime Failover and Secure LLM Gateway

## Purpose
This document describes two core runtime mechanisms:
- `runtime_failover`: continuity of decisioning under model/backend outages.
- `llm_secure_gateway`: privacy-preserving cloud inference with reversible local obfuscation.

The goal is to keep **availability high** while preserving **data sovereignty** and **fail-closed safety**.

## System Boundaries
- Orchestration entrypoint: `scripts/run_all.py`
- Agent chain: `Captain -> Doctor -> Commander`
- Shared controls:
  - `src/runtime_failover.py`
  - `src/llm_secure_gateway.py`
  - `src/sanitization_transform.py`

## Runtime Failover
### Policy
The failover order is deterministic:
1. `groq` (cloud, preferred)
2. `ollama` (edge/local model server)
3. deterministic local output (hard fallback)

`local_mock` is disallowed by policy in `runtime_failover`.

### Implementation Path
1. Each agent builds tiers with `build_runtime_failover_tiers(...)`.
2. Generation is executed through `generate_with_runtime_failover(...)`.
3. The runtime tries each tier in order; on error, it records attempt metadata and continues.
4. If all model tiers fail, deterministic fallback is used (if provided).

### Emitted Provenance
Each call emits machine-readable metadata, including:
- `fallback_tier`
- `used_fallback`
- `fallback_reason`
- `provisional_local_fallback`
- `needs_cloud_reconciliation`
- `attempts[]`

This data drives acceptance checks and reconciliation workflows.

## Secure LLM Gateway
### Security Contract Loading
For cloud paths, gateway enforces:
- sanitization policy contract integrity
- sanitization transform contract integrity
- ACL constraints (`SANITIZATION_READER_ROLE`)

Any violation is fail-closed.

### Request Flow
1. Raw prompt/system text enters gateway.
2. `apply_transform(...)` converts sensitive numeric/identifier fragments into placeholders.
3. If vectorization/transform requirements are not met, call fails with `SANITIZATION_REQUIRED_FOR_CLOUD`.
4. Cloud backend receives only transformed content.
5. Response is locally deobfuscated using replacement map.

### Obfuscation Map Lifecycle
1. Gateway writes map payload for each cloud call.
2. Payload is encrypted in envelope form (AES-256-CBC + PBKDF2 via OpenSSL).
3. KMS-like master secret is read from `SANITIZATION_KMS_MASTER_KEY`.
4. Map is stored under `data/security/obfuscation_maps/` with:
   - integrity sidecar (`.sha256`)
   - manifest registration
   - audit log entry
   - TTL purge handling

### Response Integrity Semantics
Gateway records:
- `response_deobfuscation_required`
- `response_deobfuscation_applied_actual`
- `response_deobfuscation_hit_count`

Acceptance and pre-publish enforce consistency:
- `applied_actual == (hit_count > 0)`

## Reconciliation for Provisional Decisions
When fallback makes a run provisional:
- `needs_cloud_reconciliation=true` is emitted.
- Reconciliation worker compares provisional and cloud decisions.
- Match-rate is persisted for governance and ROI scorecards.

## Failure Modes (Fail-Closed)
Examples that hard-stop or mark run unsafe:
- missing/invalid contract sidecar
- cloud call without sanitization transform
- map encryption or audit-trail failure
- policy violation in runtime failover path

## Operational Controls
Minimum required env vars for secure runtime:
- `SANITIZATION_KMS_MASTER_KEY` (non-empty, local demo value allowed)
- `SANITIZATION_READER_ROLE=runtime_orchestrator`

Optional runtime controls:
- `LLM_ALLOW_REMOTE`
- backend/model selection flags per script

## Why This Matters for Enterprise
- Privacy-first by default on cloud inference.
- Transparent fallback semantics for business continuity.
- Traceable governance through structured artifacts and integrity checks.
- Explicit failure behavior preferred over silent degradation.

---

## Paired Experiment Mode

Paired mode runs control and treatment branches under the same `experiment_id` and governs the full lifecycle from launch through decision.

### Data Flow
1. `--mode paired` triggers `_run_ctrl_foundation_only` — control simulation and metrics snapshot.
2. Treatment pipeline runs against the same experiment context.
3. On completion, `PairedExperimentContext` is written to `data/agent_context/<run_id>_paired_experiment_v2.json`.
4. Doctor receives live `StatEvidenceBundle` (p-value, CI, effect size per metric) — enabling Layers 1+2 of reasoning.
5. Commander enforces `guardrail_status_check[]` — any statistical breach blocks aggressive decisions.

### Lifecycle States
| Status | Meaning | Decision Ceiling |
|--------|---------|-----------------|
| `COMPLETE` | Both arms succeeded; all three reasoning layers active | No forced ceiling |
| `PARTIAL` | Treatment failed after ctrl succeeded | Forced `HOLD_NEED_DATA` |
| `TREATMENT_FAILED` | Treatment pipeline failed (preserved distinct from PARTIAL for audit) | Forced `HOLD_NEED_DATA` |
| `CTRL_FAILED` | Control failed; treatment not attempted; no decision issued | Hard stop |

### Fail-Closed Guarantees
- Aggressive decisions (`GO/RUN_AB/ROLLOUT_CANDIDATE`) are blocked at runtime **and** re-checked at acceptance for any `partial-like` status.
- Partial-like status cannot be written back to `COMPLETE` — no status regression.
- Registry stored at `data/paired_registry/<exp_id>__<run_id>.json` with SHA256 sidecar and path-injection guard.

---

## Experiment Governance Gates

Two mandatory gates enforce experiment hygiene before any agent reasoning begins.

### Experiment Context Gate
Every run requires `--experiment-id`. Without it, execution stops immediately with `EXPERIMENT_CONTEXT_REQUIRED` — there is no opt-out path in the orchestrator. Anonymous runs cannot produce governance artifacts.

### 14-Day Duration Gate
Aggressive final decisions are gated by a minimum 14-day coverage window for the same `experiment_id`. If coverage is below threshold, the decision ceiling is forced to `HOLD_NEED_DATA` regardless of what the LLM concludes. This prevents premature rollouts on underpowered observations.

Both gates are enforced in order by the V3 contract set and are auditable in `data/gates/`.

---

## API Key Auto-Loading

The runtime automatically loads `GROQ_API_KEY` from `~/.groq_secrets` at startup via `_inject_groq_key_if_needed()`.

### Security guarantees
- Key value is never printed, logged, or returned in any artifact.
- `override=False` — an explicitly set environment variable always takes precedence over the file.
- Key format is validated (`gsk_` prefix, minimum 20 characters) before being accepted.
- File path is not disclosed in log messages.
- Failure is non-fatal: agents fall through to deterministic fallback with an informational message.

This means operators and automated agents can run the full cloud path without manual `export` steps or hardcoding keys in configuration files.
