# Executable PRD v1

## Scope

This document defines runtime-enforced DoD for Blueprint v2.1.

## DoD (runtime)

1. Gate order is enforced in runtime artifacts (`data/gates/*_gate_result.json`) exactly as:
   required sequence:
   `historical_retrieval_gate -> doctor -> handoff_contract_guard -> evaluator -> commander -> acceptance -> pre_publish`;
   full runtime sequence:
   `context_frame -> historical_retrieval_gate -> doctor -> handoff_contract_guard -> anti_goodhart_sot -> evaluator -> commander -> historical_retrieval_conformance_gate -> quality_invariants -> reasoning_score_policy -> governance_ceiling -> acceptance -> pre_publish`.
2. Doctor cannot run without `historical_context_pack_v1` (integrity-verified).
3. Commander and Doctor expose historical context usage markers.
4. Runtime scripts use centralized `llm_secure_gateway` only.
5. Sanitization policy contract is integrity-loaded and enforced.
6. Obfuscation maps are confined to `data/security/obfuscation_maps/`.
7. Cloud path uses `sanitization_transform -> llm_secure_gateway -> response deobfuscation`; encrypted obfuscation map is mandatory.
8. `map_encryption_verified`, `sanitization_vectorization_applied`, `response_deobfuscation_applied` are CRITICAL acceptance checks.
9. Any provisional local fallback (`captain/doctor/commander`) requires reconciliation job + reconciliation result artifacts.
10. Online KPI fields are present in per-run scorecard.
11. Real KPI ledger fields are mandatory acceptance signals:
   `would_have_prevented_loss_rate`, `decision_regret_rate`, `sample_size`, `label_window_days`, `ground_truth_source`.
12. Proxy KPI cannot pass acceptance without valid real KPI ledger.
13. Real KPI acceptance requires labeled outcomes count and unique outcome ids above mode threshold (`run/nightly/release`) with integrity-verified `ground_truth_refs[]`.
14. STOP/HOLD decisions include mitigation-by-design or explicit `insufficient_evidence` fallback.
15. Batch transport forbids stdout-ingest; `run_poc_e2e` writes batch records only via `--batch-record-out`.
16. `build_batch_consolidated_report.py` reads only `data/batch_eval/<batch_id>_summary.json` (summary-only SoT).
17. Cleanup policy blocks residual Sprint-2 artifacts outside golden pair:
   - `reports/**/POC_DECISION_CARD_SPRINT2.md`
   - `data/**/*_poc_sprint2.json`
   - `reports/**/*_poc_sprint2.json`
18. Cleanup integrity strict mode is default (`--strict-integrity 1`), sidecar missing/mismatch is blocking.

## Acceptance matrix

| Control | Runtime gate/check | Failure code | Severity |
|---|---|---|---|
| Missing historical context | historical_retrieval_gate | HISTORICAL_CONTEXT_MISSING | CRITICAL |
| Context integrity mismatch | historical_retrieval_gate | HISTORICAL_CONTEXT_INTEGRITY_FAIL | CRITICAL |
| Context not used by agents | historical_retrieval_conformance_gate | HISTORICAL_CONTEXT_UNUSED | CRITICAL |
| Direct cloud call outside gateway | acceptance policy check | SANITIZATION_REQUIRED_FOR_CLOUD | CRITICAL |
| Obfuscation map policy violation | gateway + acceptance/pre_publish | SANITIZATION_MAP_POLICY_VIOLATION | CRITICAL |
| Obfuscation map encryption missing/invalid | gateway + acceptance/pre_publish | MAP_ENCRYPTION_VERIFIED | CRITICAL |
| Sanitization audit trail missing | acceptance/pre_publish | SANITIZATION_AUDIT_TRAIL_MISSING | CRITICAL |
| Provisional fallback without reconciliation | acceptance | PROVISIONAL_REQUIRES_RECONCILIATION | CRITICAL |
| Missing mitigation proposals on HOLD/STOP | commander policy check | MITIGATION_PROPOSALS_MISSING | CRITICAL |
| Missing per-run online KPI | acceptance | KPI_ONLINE_MISSING | CRITICAL |
| Missing real KPI ledger/backtest | acceptance | KPI_LEDGER_MISSING | CRITICAL |
| Offline KPI freshness SLA | acceptance | KPI_OFFLINE_STALE | PASS <=24h, WARN 24-48h, CRITICAL FAIL >48h (nightly/release) |
| Residual Sprint-2 POC JSON in data/reports | acceptance + pre_publish | POC_*_CLEANUP_REQUIRED | CRITICAL |
| Consolidated report reads non-summary sources | acceptance + pre_publish | CONSOLIDATED_SUMMARY_ONLY_VIOLATION | CRITICAL |

## Required contracts

- `configs/contracts/historical_context_pack_v1.json`
- `configs/contracts/reasoning_memory_ledger_v1.json`
- `configs/contracts/decision_outcomes_ledger_v1.json`
- `configs/contracts/offline_kpi_backtest_v1.json`
- `configs/contracts/sanitization_transform_v1.json`
- `configs/contracts/sanitization_policy_v2.json`
- `configs/contracts/reconciliation_policy_v1.json`
- `configs/contracts/error_taxonomy_v1.json`
- `configs/contracts/artifact_spam_prevention_v2.json`
- `configs/contracts/golden_pair_policy_v2.json`
- `configs/contracts/cleanup_integrity_policy_v2.json`
- `configs/contracts/batch_record_transport_policy_v2.json`
- `configs/contracts/batch_record_v2.json`
- `configs/contracts/cleanup_manifest_v1.json`
- `configs/contracts/consolidated_report_v1.json`

All required contracts must have valid `.sha256` sidecars.
