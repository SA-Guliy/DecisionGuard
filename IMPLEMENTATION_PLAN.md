# Implementation Plan

All open engineering items tracked here. Each item has: exact file + line,
what to change, why, how to verify. Nothing is vague.

Status legend: `OPEN` | `IN PROGRESS` | `DONE`

---

## Sprint 1 — Live Statistics in Agent Reasoning (Priority: Critical)

**Goal:** Inject StatEvidenceBundle into Doctor and Commander LLM prompts so
agents see p-values, confidence intervals, SRM status, and guardrail verdicts
when making decisions. Expected FPR reduction: 40% → ~15%.

**Current state:** `src/stat_engine.py` computes the bundle and saves it to
`data/agent_context/<run_id>_stat_evidence_bundle_v1.json`. The bundle is
loaded in both agent scripts and used for gate checks — but it is NOT
included in the text passed to the LLM. Agents reason without seeing it.

---

### S1-A: Doctor — inject StatEvidenceBundle into hypothesis generation prompt

**File:** `scripts/run_doctor_variance.py`

**What to add:**
A helper function `_format_stat_evidence_for_prompt(stat_bundle: dict) -> str`
that formats the bundle into a compact, LLM-readable text block.

Example output:
```
## Statistical Evidence (Layer 1 + 2)
Primary metric (aov): p=0.021, CI=[+0.94, +4.18], verdict=SIGNIFICANT, effect_size=0.34
SRM: PASS (n_ctrl=4821, n_trt=4798, drift=0.5%)
Guardrail checks:
  gp_margin: p=0.001 → BREACH (delta=-2.8%, threshold=-5%)
  fill_rate_units: p=0.31 → OK
  oos_lost_gmv_rate: p=0.008 → BREACH (delta=+2.6%)
```

**Where to inject:**
Function `_build_hypothesis_portfolio()` at line ~1702.
Currently the `llm_input` dict (line ~2069) contains: `metrics`, `captain_issues`,
`synthetic_bias_signals`.
Add: `"stat_evidence": _format_stat_evidence_for_prompt(stat_bundle)` when bundle
is non-empty and status is PASS or PARTIAL.

**Signature change:**
`_build_hypothesis_portfolio(run_id, metrics, captain, synthetic_bias, *, dynamic_enabled)`
→
`_build_hypothesis_portfolio(run_id, metrics, captain, synthetic_bias, *, dynamic_enabled, stat_bundle=None)`

Call site at line ~3686 already has stat_bundle_payload available — pass it:
`_build_hypothesis_portfolio_with_mode(..., stat_bundle=stat_bundle_payload)`

**Fail-safe:** if stat_bundle is None or empty dict → inject nothing, behaviour
unchanged. No hard dependency.

**Status:** `OPEN`

---

### S1-B: Commander — inject StatEvidenceBundle into decision prompt

**File:** `scripts/run_commander_priority.py`

**What to add:**
Reuse the same `_format_stat_evidence_for_prompt()` helper (extract to
`src/stat_evidence_formatter.py` so both scripts share it without duplication).

**Where to inject:**
Function `_commander_llm_input(payload)` at line 732.
Add a `"stat_evidence"` key to the returned dict when payload contains
`"stat_bundle"`. The Commander's LLM call at line ~824 uses this dict directly.

`payload` is assembled in the main Commander flow. At line ~2599 `stat_bundle`
is loaded — add `payload["stat_bundle"] = stat_bundle` before calling
`_commander_llm_decision_proposal(payload, ...)`.

**Fail-safe:** `payload.get("stat_bundle", {})` — empty dict if not available.

**Status:** `OPEN`

---

### S1-C: Extract shared formatter to src/stat_evidence_formatter.py

**File:** `src/stat_evidence_formatter.py` (new file)

**Why:** Doctor and Commander both need the same formatting logic.
One function in one place — no drift between the two scripts.

**Function signature:**
```python
def format_stat_evidence_for_prompt(stat_bundle: dict | None) -> str:
    """
    Returns a compact, human-readable text block for LLM consumption.
    Returns empty string if bundle is None, empty, or status is not PASS/PARTIAL.
    Never raises — safe to call unconditionally.
    """
```

**Inputs consumed from bundle:**
- `status` — PASS / PARTIAL / FAIL
- `metrics[]` — per-metric: metric_id, p_value, ci_lower, ci_upper, verdict, effect_size
- `srm_flag` — bool
- `n_ctrl`, `n_trt` — sample sizes
- `guardrail_status_check[]` — per-guardrail: metric_id, verdict, delta_pct, threshold

**Status:** `OPEN`

---

### S1-D: Add full decision artifact persistence in batch mode

**File:** `scripts/run_all.py` (or whichever batch runner calls individual cases)

**Problem:** In batch mode, only the final verdict is saved per case.
When the system errors (e.g., risk_009), there is no artifact to inspect.

**Fix:** After each case completes in batch, write a minimal decision record:
```json
{
  "run_id": "mass_test_003_risk_009",
  "decision": "GO",
  "doctor_decision": "...",
  "commander_decision": "...",
  "stat_bundle_status": "...",
  "layer1_verdict": "...",
  "guardrail_breaches": [],
  "top_reasons": []
}
```
Path: `data/batch_eval/artifacts/<batch_id>/<case_id>_decision_record.json`

**Fail-safe:** write errors must be caught and logged; they must not abort the batch.

**Status:** `OPEN`

---

### S1 Verification

After implementing S1-A through S1-D:
1. Run `python scripts/run_doctor_variance.py` on a single case — confirm
   `stat_evidence` key appears in the LLM prompt log
2. Run `python scripts/run_commander_priority.py` — confirm same
3. Run the investor_demo_batch — compare FPR before/after
4. Inspect a batch artifact in `data/batch_eval/artifacts/`
5. Run existing tests: `python -m pytest tests/ -k "doctor or commander" -v`

---

## Sprint 2 — Granular Reasoning Scoring

**Goal:** Upgrade `grounded_claim_rate` and `causal_chain_completeness` from
binary (0/1) to three-level scoring, making the eval more discriminating.

**File:** `scripts/make_agent_quality_report_v2.py`

### S2-A: Three-level grounded_claim_rate

**Current:** each claim is 1 (has reference) or 0 (no reference)

**New:**
```
0.0 — no data at all ("customers may be dissatisfied")
0.5 — metric named but no number ("GMV improved")
1.0 — metric + number + context ("GMV +3.2%, CI [1.4%, 4.9%], p=0.021")
```

**Where:** function that computes `grounded_claim_rate` in the eval script.
Look for `_ratio(with_refs, len(metric_claims))` — replace with weighted sum.

**Status:** `OPEN`

---

### S2-B: Per-component chain scoring

**Current:** chain is 1 (all 4 parts present) or 0 (incomplete)

**New:** 0.25 per component present — Observation / Cause / Consequence / Action
Partial chains now get credit proportional to completeness.

**Where:** function that computes `causal_chain_completeness`.

**Status:** `OPEN`

---

### S2 Verification

Run `python scripts/make_agent_quality_report_v2.py` on existing eval data
and compare new scores to old. Scores should be more distributed (fewer
extremes at 0.0 and 1.0).

---

## Sprint 3 — Evaluation Report Generator

**Goal:** `scripts/make_evaluation_report.py` auto-generates
`EVALUATION_REPORT.md` and archives to `EVALUATION_HISTORY.md`.

**File:** `scripts/make_evaluation_report.py` (new file)

### S3 Design Constraints

- Read-only: reads JSON files, writes markdown. No DB, no LLM calls.
- Deterministic: same inputs → same output every time.
- Safe archive: appends to EVALUATION_HISTORY.md with a dated separator,
  never overwrites history.
- No external dependencies beyond stdlib + pathlib.
- Fails loud: if required source files are missing, prints clear error and
  exits non-zero. Does not silently produce a partial report.

### S3 Logic

```
1. Find 2 most recent batch summary files in data/batch_eval/
   (sort by mtime, take last 2, skip staging/ subdir)
2. Load agent eval JSONs from data/agent_eval/
3. Load investor_demo scorecard from
   examples/investor_demo/reports_for_humans/executive_roi_scorecard.md
4. Archive current EVALUATION_REPORT.md to EVALUATION_HISTORY.md
   (prepend dated section header, append full content)
5. Render new EVALUATION_REPORT.md from template + data
```

### S3 Template sections (in order)

Header with generated_at timestamp, source batch IDs, generator path.
Section 1: Decision accuracy table from batch summaries.
Section 2: Reasoning quality table from agent eval JSONs.
Section 3: Known limitations (static text from this plan + dynamic from batch).
Section 4: Auto-update instructions (static).

**Status:** `OPEN`

---

## Backlog — Simulation Engine Documentation

**Goal:** Create `SIMULATION_ENGINE.md` explaining how synthetic data
generation works in plain language (Russian draft first, then English).

**What to document:**
- PostgreSQL-backed live simulation (not static fixtures)
- Simulation clock advances +7 days per run
- Parameterisable knobs: demand shocks, supply realism, competitor prices
- Realism scorer: fill_rate_mean ∈ [0.93, 0.97] validation
- 8 simulation tables updated per run
- How to run: `scripts/run_simulation_v1.py` + `scripts/make_metrics_snapshot_v1.py`
- Why this enables near-live experiments

**Status:** `OPEN` — Russian draft discussion first

---

## Backlog — Report Quality Review

**Goal:** After Sprint 1 runs, evaluate whether reasoning quality scores
improve and by how much. Update EVALUATION_REPORT.md with new data.

**Trigger:** Run a new mass test batch after S1-A/B are deployed.
Compare: old mass_test_003 (FPR=40%, FNR=10%) vs new batch.

**Status:** `OPEN` — depends on Sprint 1

---

## Backlog — Reconciliation Directory Guard (P2)

**File:** `src/reconciliation_worker.py` (or wherever `_find_pending_runs` is)

**Fix:** Add `Path.exists()` check before glob on `data/reconciliation/`.
If directory missing → return `[]` immediately with a log warning.

**Status:** `OPEN`
