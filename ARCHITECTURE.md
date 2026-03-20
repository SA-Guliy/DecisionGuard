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
