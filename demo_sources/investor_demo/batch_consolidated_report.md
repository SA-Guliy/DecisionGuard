# Batch Consolidated Report — Investor Demo v2

- Generated at: `2026-03-20T22:30:00Z`
- Demo batch: `investor_demo_batch_v2`
- Source root: `<PROJECT_ROOT>/examples/investor_demo`

## Case Matrix

| Case ID | Scenario | Primary Outcome | Guardrail Outcome | Paired Status | Final Decision |
|---|---|---|---|---|---|
| `demo_case_001_aov_uplift_approved` | Dynamic bundling offers | `AOV +6.2%` (`p=0.021`) | No significant breach | `COMPLETE` | **GO** |
| `demo_case_002_gmv_uplift_guardrail_breach` | Aggressive discount on slow-moving SKUs | `GMV +4.1%` (`p=0.003`) | `gp_margin` and `oos_lost_gmv_rate` breached | `COMPLETE` | **HOLD_NEED_DATA** |
| `demo_case_003_partial_run_treatment_failed` | Treatment arm failed mid-execution | Incomplete treatment evidence | Forced governance ceiling | `TREATMENT_FAILED` | **HOLD_NEED_DATA** |

## Detailed Notes

### demo_case_001_aov_uplift_approved
- Control: `aov=41.30`, `aov_stddev=28.10`, `n=2180`
- Treatment: `aov=43.86`, `aov_stddev=29.40`, `n=2215`
- 95% CI (absolute delta): `[+0.94, +4.18]`
- Guardrails:
  - fill_rate delta `-0.003` (`p=0.34`) -> not significant
  - gp_margin delta `+0.004` (`p=0.19`) -> not significant
- Decision rationale: positive primary lift without statistically significant operational harm.

### demo_case_002_gmv_uplift_guardrail_breach
- Control: `gmv=94,200`, `gmv_stddev=12,400`, `n=2180`
- Treatment: `gmv=98,070`, `gmv_stddev=13,100`, `n=2215`
- 95% CI (relative lift): `[+1.4%, +6.8%]`
- Guardrails:
  - `gp_margin`: `0.312 -> 0.284` (`delta=-0.028`, `p=0.001`) -> BREACH
  - `oos_lost_gmv_rate`: `0.041 -> 0.067` (`delta=+0.026`, `p=0.008`) -> BREACH
- Historical analog: `exp_darkstore_discount_2024_q3` shows similar short-term lift with prolonged margin damage.
- Decision rationale: growth signal exists but risk profile breaches hard guardrails.

### demo_case_003_partial_run_treatment_failed
- `ctrl_completed=true`, `treatment_completed=false`
- `paired_status=TREATMENT_FAILED`
- Forced ceiling: `HOLD_NEED_DATA`
- Error code: `PAIRED_PARTIAL_CEILING_VIOLATION`
- Decision rationale: no aggressive decision permitted when treatment evidence is incomplete.

## Batch-Level Governance Outcome

- Portfolio verdict: **Policy-conformant**
- Cloud and fallback behavior: **Cloud path available for all 3 cases; deterministic fallback not used**
- Safety posture: **Fail-closed preserved**
- Actionability: case #1 is rollout candidate, #2 and #3 require additional mitigation/reconciliation evidence.
