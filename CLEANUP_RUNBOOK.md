# CLEANUP RUNBOOK (staging_only release)

This runbook defines safe cleanup for public packaging.

## 1) Safety Principles
- Quarantine-only moves (`_PROJECT_TRASH`), no irreversible delete.
- Execute in two phases: dry-run first, apply second.
- Strict integrity by default (`--strict-integrity 1`).
- Any missing sidecar in strict mode is blocking (`non-zero exit`).

## 2) Golden + Evidence Keep Set (mass_test_003)

Preserve reference cases:
- `mass_test_003_safe_012` (expected `GO`)
- `mass_test_003_risk_007` (expected `STOP_ROLLOUT`/blocked)
- `mass_test_003_safe_020` (stability safe case)

Preserve required showcase artifacts:
- `data/batch_eval/mass_test_003_summary.json`
- `data/reports/INVESTOR_ROI_SCORECARD.md` (or `EXECUTIVE_ROI_SCORECARD.md` if renamed)

Preserve evidence-chain artifacts when present:
- `reports/L1_ops/demo_golden_example/POC_DECISION_CARD_SPRINT2.md`
- `reports/L1_ops/demo_golden_example/mass_test_003_risk_007_poc_sprint2.json`
- `data/security/obfuscation_maps/mass_test_003_*_obfuscation_manifest.json`
- `data/security/obfuscation_maps/mass_test_003_*_obfuscation_manifest.json.sha256`
- `data/reconciliation/**/*mass_test_003*`
- `data/cost/**/*mass_test_003*`
- `data/acceptance/**/*mass_test_003*`

## 3) Keep-list Patch Block

```bash
TRASH="_PROJECT_TRASH"
mkdir -p "$TRASH"
KEEP="$TRASH/KEEP_RELATIVE_PATHS.txt"
cat > "$KEEP" << 'EOF'
data/poc/history_sot_v1.json
data/poc/history_vector_index_v1.json
data/batch_eval/mass_test_003_summary.json
data/reports/INVESTOR_ROI_SCORECARD.md
data/reports/EXECUTIVE_ROI_SCORECARD.md
reports/L1_ops/demo_golden_example/POC_DECISION_CARD_SPRINT2.md
reports/L1_ops/demo_golden_example/mass_test_003_risk_007_poc_sprint2.json
data/security/obfuscation_maps/mass_test_003_safe_012_obfuscation_manifest.json
data/security/obfuscation_maps/mass_test_003_safe_012_obfuscation_manifest.json.sha256
data/security/obfuscation_maps/mass_test_003_risk_007_obfuscation_manifest.json
data/security/obfuscation_maps/mass_test_003_risk_007_obfuscation_manifest.json.sha256
data/security/obfuscation_maps/mass_test_003_safe_020_obfuscation_manifest.json
data/security/obfuscation_maps/mass_test_003_safe_020_obfuscation_manifest.json.sha256
EOF
```

## 4) Cleanup Execution

Dry-run:

```bash
python3 scripts/cleanup_poc_artifacts.py --strict-integrity 1 --apply 0
```

Apply (only after dry-run PASS):

```bash
python3 scripts/cleanup_poc_artifacts.py --strict-integrity 1 --apply 1
```

Legacy override (explicit only):

```bash
python3 scripts/cleanup_poc_artifacts.py --strict-integrity 0 --apply 1
```

## 5) Post-move Verification

```bash
for p in \
  "data/batch_eval/mass_test_003_summary.json" \
  "reports/L1_ops/demo_golden_example/POC_DECISION_CARD_SPRINT2.md" \
  "reports/L1_ops/demo_golden_example/mass_test_003_risk_007_poc_sprint2.json"
do
  test -e "$p" || echo "MISSING: $p"
done
```

## 6) Required Artifacts After Cleanup
- `_PROJECT_TRASH/MIGRATION_MANIFEST.json`
- `_PROJECT_TRASH/MIGRATION_MANIFEST.md`
- `_PROJECT_TRASH/rollback.sh`
- `MIGRATION_MANIFEST.json` (release root copy/update)
- `MIGRATION_MANIFEST.md` (release root copy/update)

