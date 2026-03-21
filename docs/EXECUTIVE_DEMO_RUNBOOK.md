# Executive Demo Runbook

Official Seed-pitch demo playbook for the Privacy-First AI Decision Governance Layer.

## 1. Preflight (Mandatory)

1. `GROQ_API_KEY` is available via `~/.groq_secrets`.
2. `SANITIZATION_KMS_MASTER_KEY` is set in local env.
3. `SANITIZATION_READER_ROLE=runtime_orchestrator`.
4. Required contracts + sidecars exist:
   - `configs/contracts/sanitization_policy_v2.json`
   - `configs/contracts/sanitization_transform_v1.json`
   - `configs/contracts/reconciliation_policy_v1.json`

Local demo key is supported (no external AWS/GCP KMS credential lookup required):

```bash
export SANITIZATION_KMS_MASTER_KEY=local_demo_key
export SANITIZATION_READER_ROLE=runtime_orchestrator
```
⚠️ `local_demo_key` is sandbox-only. **DO NOT USE IN PRODUCTION**.

## 2. Demo Run Commands (Exact Order)

```bash
python3 -m py_compile \
  src/sanitization_transform.py \
  src/llm_secure_gateway.py \
  src/runtime_failover.py \
  scripts/run_all.py \
  scripts/verify_acceptance.py \
  scripts/pre_publish_audit.py \
  scripts/run_reconciliation_worker.py \
  scripts/run_batch_eval.py
```

```bash
python3 -m unittest \
  tests/test_blueprint_v21_runtime_enforcement.py \
  tests/test_historical_retrieval_gate_v32.py \
  tests/test_kpi_ledger_integrity_v2.py \
  tests/test_architecture_v3_runtime_contracts.py \
  tests/test_runtime_limits_enforcement.py
```

```bash
python3 scripts/generate_synthetic_history.py \
  --run-demo 0 \
  --out-sot data/poc/history_sot_v1.json \
  --out-index data/poc/history_vector_index_v1.json
```

```bash
python3 scripts/run_poc_e2e.py \
  --run-id executive_demo_case_001 \
  --backend groq \
  --top-k 3 \
  --query "..." \
  --interactive
```

Interactive mode is intentional for live demo Q&A with Commander (type `exit` / `quit` to close).

```bash
python3 scripts/run_batch_eval.py \
  --batch-id executive_batch_001 \
  --backend groq \
  --max-cases 20 \
  --max-retries 3 \
  --sleep-seconds 1.5

python3 scripts/build_batch_consolidated_report.py --batch-id executive_batch_001

python3 scripts/cleanup_poc_artifacts.py
```

```bash
python3 scripts/verify_acceptance.py --run-id executive_demo_case_001
python3 scripts/pre_publish_audit.py --run-id executive_demo_case_001 --strict 1
python3 scripts/build_executive_roi_report.py --batch-id executive_batch_001
# legacy-only fallback (if historical artifacts do not yet have .sha256 sidecars):
# python3 scripts/build_executive_roi_report.py --batch-id executive_batch_001 --integrity-required 0
```

Integrity mode policy: default is fail-closed (`--integrity-required 1`); demo override `--integrity-required 0` is allowed only for legacy artifacts.
Cleanup policy: default is fail-closed (`cleanup_poc_artifacts.py` uses strict-integrity by default); missing sidecar is blocking.
Golden policy: only one golden pair is allowed under `reports/L1_ops/demo_golden_example`.
Cleanup migration artifacts:
- `_PROJECT_TRASH/MIGRATION_MANIFEST.json`
- `_PROJECT_TRASH/MIGRATION_MANIFEST.md`
- `_PROJECT_TRASH/rollback.sh`

## 3. GO Thresholds (Must Pass)

1. Security/sanitization:
   - `sanitization_policy_contract=PASS`
   - `sanitization_transform_contract=PASS`
   - `map_encryption_verified=PASS`
   - `sanitization_vectorization_applied=PASS`
   - `response_deobfuscation_required=PASS`
   - `response_deobfuscation_applied=PASS`
   - `llm_secure_gateway_enforced=PASS`
2. Resilience:
   - `provisional_requires_reconciliation=PASS`
   - outage case has `fallback_agents` including `captain,doctor,commander`
   - `needs_cloud_reconciliation=true` when fallback occurs
3. Quality:
   - `historical_retrieval_gate=PASS`
   - `historical_retrieval_conformance_gate=PASS`
   - `commander_mitigation_policy=PASS`
4. ROI/batch:
   - `availability_kpi >= 0.95`
   - `false_negative_rate <= 0.05`
   - `false_positive_rate <= 0.20`
   - `failed_api_cases / max_cases <= 0.05`
5. KPI ledger:
   - `online_kpi_present=PASS`
   - no `KPI_LEDGER_MISSING`
   - `would_have_prevented_loss_rate` and `decision_regret_rate` are computed

## 4. Hard NO-GO (Automatic Stop)

1. Any CRITICAL `FAIL` in `verify_acceptance`.
2. Missing reconciliation artifacts for provisional fallback.
3. Direct cloud SDK calls outside secure gateway policy.
4. Missing/invalid encrypted obfuscation maps or audit trail.
5. `false_negative_rate > 0.05` in batch summary.
6. Residual Sprint-2 artifacts outside golden path:
   - `reports/**/POC_DECISION_CARD_SPRINT2.md`
   - `data/**/*_poc_sprint2.json`
   - `reports/**/*_poc_sprint2.json`
7. Consolidated report built from non-summary source.

## Security & Tech Debt (Path to Production)

This runbook supports Seed-pitch demo velocity. The following POC shortcuts are explicit and must be closed before production go-live.

1. Network / Proxy posture
   - Current demo posture:
     Local runs may execute without enterprise outbound proxy/DLP constraints.
   - Production requirement:
     Route all external model traffic through corporate proxy with certificate trust chain and egress policy controls.

2. KMS master key sourcing
   - Current demo posture:
     `SANITIZATION_KMS_MASTER_KEY=local_demo_key` is allowed for local sandbox usage.
   - Production requirement:
     Master key material must come from managed secret systems (AWS KMS / HashiCorp Vault), with rotation and audited access controls.

3. Integrity strictness
   - Current demo posture:
     ROI report supports legacy override `--integrity-required 0` for old artifacts without sidecars.
   - Production requirement:
     Enforce strict mode only (`--integrity-required 1`) and block the override in release pipelines.

4. Profile separation
   - Current demo posture:
     Demo and production controls can coexist in one operational path.
   - Production requirement:
     Separate demo profile from production profile with environment-enforced policy gates.

## Scope Freeze (Seed Pitch)

Section 5 from internal checklist (chaos tests, adversarial tests, red-teaming) is intentionally **de-scoped** for this Seed demo runbook.

## 6. Executive Artifact Pack (Deliverables)

1. `data/agent_reports/<run_id>_poc_sprint2.json`
2. `reports/L1_ops/<run_id>/POC_DECISION_CARD_SPRINT2.md`
3. `data/batch_eval/<batch_id>_summary.json`
4. `data/reports/<batch_id>_BATCH_CONSOLIDATED_REPORT.md`
5. `data/cost/<run_id>_cost_ledger.json` (if produced by run)
6. `data/reports/EXECUTIVE_ROI_SCORECARD.md`
7. Acceptance and pre-publish outputs showing PASS
