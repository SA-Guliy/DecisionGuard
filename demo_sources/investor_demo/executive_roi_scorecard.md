# Executive ROI Scorecard

- Generated at: `2026-03-20T22:30:00Z`
- Demo batch: `investor_demo_batch_v2`
- Source root: `<PROJECT_ROOT>/examples/investor_demo`
- Backend profile: `groq/llama-3.3-70b`

## Portfolio Summary

- Total runs: **3**
- Cloud-path runs: **3 (100%)**
- Deterministic fallback runs: **0**
- Final `GO` decisions: **1**
- Final `HOLD_NEED_DATA` decisions: **2**

## Decision Quality

- FPR (aggressive on risk): **0% (0/2 risk cases approved)**
- FNR (blocked safe iteration): **0% (0/1 safe cases blocked)**
- Avg reasoning confidence: **0.77**
- Avg cost per run: **$0.0031**

## Case Outcomes

### 1) demo_case_001_aov_uplift_approved
- Scenario: Dynamic bundling offers
- Result: `GO`
- Primary signal: `AOV +6.2%` (`p=0.021`, 95% CI `[+0.94, +4.18]` absolute)
- Guardrails: fill-rate and GP margin within acceptable range
- Confidence: `0.87`

### 2) demo_case_002_gmv_uplift_guardrail_breach
- Scenario: Aggressive discount on slow-moving SKUs
- Result: `HOLD_NEED_DATA`
- Primary signal: `GMV +4.1%` (`p=0.003`, 95% CI `[+1.4%, +6.8%]`)
- Blocking guardrails:
  - `gp_margin -2.8%` (`p=0.001`) -> BREACH
  - `oos_lost_gmv_rate +2.6%` (`p=0.008`) -> BREACH
- Confidence: `0.91`

### 3) demo_case_003_partial_run_treatment_failed
- Scenario: Paired execution where treatment arm failed mid-run
- Result: `HOLD_NEED_DATA` (forced ceiling)
- Paired status: `TREATMENT_FAILED`
- Governance reason: no aggressive decision allowed on incomplete treatment evidence
- Confidence: `0.54` (capped at 0.60 by partial/failed paired status policy)

## Business Value Estimate

- Unsafe rollout blocks with material downside: **2/2**
- Safe rollout approvals: **1/1**
- Estimated prevented-loss signal: **strong (demo proxy)**

## Governance Notes

- Fail-closed policy applied in all three cases.
- No run emitted `GO/RUN_AB/ROLLOUT_CANDIDATE` when guardrail breaches or partial paired state were present.
- Human approval remains mandatory for any decision update during reconciliation.
