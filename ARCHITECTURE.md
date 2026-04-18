# ARCHITECTURE: Runtime Failover and Secure LLM Gateway

## Purpose
This document describes two core runtime mechanisms:
- `runtime_failover`: continuity of decisioning under model/backend outages.
- `llm_secure_gateway`: privacy-preserving cloud inference with reversible local obfuscation.

The goal is to keep **availability high** while preserving **data sovereignty** and **fail-closed safety**.

## System Boundaries
- Orchestration entrypoint: `scripts/run_all.py`
- Agent chain: `Agent-1 -> Agent-2 -> Agent-3`
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

### Agent Model Policy (`src/model_policy.py`)

Each agent has a dedicated model chain. Agent-2 and Agent-3 use **reasoning models** (confirmed via `reasoning_tokens` in API response). Single source of truth: `src/model_policy.py`.

| Agent | Role | Model chain (priority order) | Reasoning tiers |
|---|---|---|---|
| **Agent-1** | Sanity & realism check | `llama-3.1-8b-instant` (Groq) | — (not required for QA gate) |
| **Agent-2** | Hypothesis audit | `qwen/qwen3-32b` → `openai/gpt-oss-120b` → `llama-3.3-70b-versatile` → `openai/gpt-oss-20b` | 3 of 4 |
| **Agent-3** | Final governance decision | `qwen/qwen3-32b` → `openai/gpt-oss-20b` → `llama-3.3-70b-versatile` | 2 of 3 |
| **Local fallback** | API outage only | `gemma3:1b` (Ollama) | — (provisional, pending reconciliation) |

`openai/gpt-oss-120b` and `openai/gpt-oss-20b` are reasoning models served via Groq — API responses include a `reasoning` field and non-zero `reasoning_tokens` in usage. `llama-3.3-70b-versatile` is the last-resort non-reasoning fallback before dropping to Ollama.

### Reasoning Continuity Under Model Decommissions

Groq frequently removes models from service without advance notice. This is a real operational risk: a model that worked yesterday may return `model_not_found` today.

DecisionGuard handles this at two levels:

**Level 1 — Known decommissions (pre-call filter).**
`DECOMMISSIONED_GROQ_MODELS` in `src/runtime_failover.py` lists models confirmed as removed. These are skipped before the API call — no latency cost, no error log noise. Current decommissioned list: `deepseek-r1-distill-qwen-32b`, `mixtral-8x7b-32768`, `llama-3.1-70b-versatile`.

**Level 2 — Unknown failures (runtime catch).**
Any model not in the decommission list is attempted. On exception (HTTP 404, 503, timeout), the error is logged as `[DEBUG CLOUD ERROR]` and the runtime automatically advances to the next tier — no manual intervention required.

**Reasoning guarantee.**
Both Agent-2 and Agent-3 have at least two reasoning-capable tiers before falling to a non-reasoning model:
- If `qwen/qwen3-32b` is decommissioned → `openai/gpt-oss-120b` (Agent-2) or `openai/gpt-oss-20b` (Agent-3) takes over, both confirmed reasoning.
- Only if both reasoning tiers fail does the system fall to `llama-3.3-70b-versatile` (non-reasoning, still produces a decision).

**Updating the model chain.**
When Groq announces a decommission: add the model ID to `DECOMMISSIONED_GROQ_MODELS` and optionally add a new model to the agent's chain — both in `src/model_policy.py`. No other files need to change.

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
4. Agent-2 receives live `StatEvidenceBundle` (p-value, CI, effect size per metric) — enabling Layers 1+2 of reasoning.
5. Agent-3 enforces `guardrail_status_check[]` — any statistical breach blocks aggressive decisions.

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

## Statistical Inference Layer

Two deterministic components provide mathematical grounding for agent reasoning. Neither calls an LLM — they are pure computation that runs before agents receive context.

### stat_engine (`src/stat_engine.py`)

Computes a `StatEvidenceBundle` from paired control/treatment metric snapshots:

| Metric type | Method | Why |
|---|---|---|
| Sample means (AOV, GMV, orders) | Welch's t-test (`ttest_ind_from_stats`, `equal_var=False`) | Real A/B data rarely has equal variance between arms |
| Ratio metrics (gp_margin, fill_rate, oos_lost_gmv_rate) | Aggregate-only path, verdict `UNDERPOWERED` | Row-level variance is undefined for ratios computed from aggregates — standard t-test is statistically invalid |
| Sample Ratio Mismatch | 10% drift threshold on n_ctrl vs n_trt | Detects assignment bugs before reasoning begins |

Output (`StatEvidenceBundle`) fields: `layers_present`, `metrics[]` (p-value, CI, effect_size, verdict per metric), `guardrail_status_check[]`, `srm_flag`.

Bundle is written to `data/stat_evidence/<run_id>_stat_evidence_bundle_v1.json` with SHA256 sidecar and consumed by Agent-2 and Agent-3 contexts.

### reasoning_confidence (`src/reasoning_confidence.py`)

Computes a dynamic confidence score from `configs/contracts/reasoning_confidence_policy_v1.json`. Replaces the previous hardcoded constant.

Penalty system (applied to base score of 0.58):
- `layer1_missing`: −0.20
- `layer2_missing`: −0.15
- `guardrail_data_incomplete`: −0.15
- `underpowered_or_no_data`: −0.18
- `srm_failed`: −0.12

Hard caps (ceiling, not floor):
- `partial_or_failed_paired_status`: 0.60 — incomplete treatment evidence cannot produce high-confidence decisions
- `single_mode_no_live_evidence`: 0.64
- `missing_layers12`: 0.62

Bonus: +0.07 if primary metric p-value < 0.05 (significant result confirmed by data).

Returns `(float, list[str])` — score and basis list for full auditability.

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
