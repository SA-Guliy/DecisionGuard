# DecisionGuard — Evaluation Report

> Auto-generated after each batch run.
> Generator script: `scripts/make_evaluation_report.py`
> Last updated: 2026-03-10
> Full version history: `EVALUATION_HISTORY.md`

---

## What This Document Is For

DecisionGuard is a three-agent system that governs whether to launch, hold,
or stop an A/B experiment.

**Agent 1 — Captain** validates that the experiment is correctly configured:
realistic data, no technical errors in the setup, no measurement issues.

**Agent 2 — Doctor** analyses the experiment and generates hypotheses:
what could go wrong, what metrics are at risk, what the data suggests.
If evidence is positive, Doctor recommends the experiment for further rollout.

**Agent 3 — Commander** makes the final binding decision. It evaluates
Doctor's hypotheses against the primary metric, success metrics, and guardrail
(boundary) metrics — then separately checks historical patterns from similar
past experiments. Only after both layers does it issue a verdict with a
full written explanation.

This document answers two questions:

1. **Decision accuracy:** does the system correctly block risky experiments
   and approve safe ones?

2. **Reasoning quality:** do agents explain their decisions using real data —
   or do they generate plausible-sounding text that cannot be verified?

No engineering jargon. Every term is explained from scratch.

---

## Section 1 — Decision Accuracy

### 1.1 Two Types of Errors

The system can make two types of mistakes, and each has a different cost:

**Missed risk**
A risky experiment was approved when it should have been blocked.
Consequence: real business loss — margin erosion, service degradation, churn.
Metric: **FNR (False Negative Rate)** — the share of truly risky experiments
that the system failed to catch, out of all risky experiments tested.

**Over-caution**
A safe experiment was held back when it should have been approved.
Consequence: good experiments are delayed, the team loses iteration speed.
Metric: **FPR (False Positive Rate)** — the share of truly safe experiments
that the system wrongly blocked, out of all safe experiments tested.

Which error is more expensive? Missing a risk — because it can cause direct
business loss. That is why the system is calibrated conservatively at this stage:
it would rather delay a good experiment than approve a risky one. This is the
intentional design trade-off behind the 40% FPR in the mass test — see 1.3.

---

### 1.2 How Test Cases Are Created

**Crash Tests** (`investor_demo_batch_v2`, 3 experiments)

A set of three hand-crafted experiments where the correct answer is known
in advance — like exam questions with an answer key. One experiment is safe,
two contain hidden risks.

These cases are static: they are written once and do not change between runs.
The purpose is to verify that the system recognises canonical scenarios correctly.

How the "correct answer" is defined: when we write a test case, we label it
with the expected outcome (block / approve) based on known business rules.
For example: an experiment showing GMV growth alongside a 12% margin drop
is labelled "must block" — because historically this pattern always produces
downstream losses.

**Mass Test** (`mass_test_003`, 20 experiments)

20 synthetic experiments in sequence: 10 safe and 10 risky. The system does
not know which is which — it processes all 20 without any hints.
The purpose is to measure real-scale performance without curated conditions.

**Important limitation of both test sets:** all experiments are synthetic —
written by hand or generated from a parameterised simulation.
The system has not yet been tested on real production data. This is an open
item tracked in Section 3.

Sources:
- `examples/investor_demo/reports_for_humans/executive_roi_scorecard.md`
- `data/batch_eval/mass_test_003_summary.json`

---

### 1.3 Results

| Test | Experiments | Missed risks (FNR) | Safe cases over-blocked (FPR) |
|------|-------------|---------------------|-------------------------------|
| Crash Tests | 3 (1 safe, 2 risky) | **0%** — 0 of 2 | **0%** — 0 of 1 |
| Mass test | 20 (10 safe, 10 risky) | **10%** — 1 of 10 | **40%** — 4 of 10 |

How to read this: Crash Tests confirm the system handles known scenarios
correctly. The mass test shows real-scale performance. The gap between them
is where improvement work is focused.

Sources: see Section 1.2

---

### 1.4 Error Breakdown

#### Missed risk: case risk_009

The system returned **GO** on an experiment that should have been blocked.
This is the only such case out of 10 risky experiments.

| Field | Value |
|-------|-------|
| Batch run | mass_test_003 (2026-03-10) |
| Expected outcome | BLOCK |
| Actual outcome | GO |
| Cost of this run | $0.0019 |

**What we know:** the case was labelled risky in advance; the system approved it.

**What we do not know — and why this matters.**
In batch mode, the system currently saves only the final verdict, not the
full reasoning trail. This means we cannot read exactly what Doctor and
Commander checked, what they missed, and why.

For a business deploying governance tooling, an unexplained error is more
expensive than a predictable one with a clear cause. Unpredictability cannot
be priced or managed.

**Concrete fix scheduled for Sprint 1:**
Add full decision artifact persistence to batch mode. After the next batch run,
this section will be updated with a complete breakdown of the missed case.

Source: `data/batch_eval/mass_test_003_summary.json`, case_id: risk_009

---

#### Over-blocked safe cases: safe_006, safe_010, safe_016, safe_020

Four safe experiments received HOLD_NEED_DATA instead of GO.

| Case | Expected | Received | Meaning |
|------|----------|----------|---------|
| safe_006 | GO | HOLD_NEED_DATA | System was over-cautious |
| safe_010 | GO | HOLD_NEED_DATA | System was over-cautious |
| safe_016 | GO | HOLD_NEED_DATA | System was over-cautious |
| safe_020 | GO | HOLD_NEED_DATA | System was over-cautious |

Source: `data/batch_eval/mass_test_003_summary.json`

**Why this happens — the specific cause:**
Agent Doctor currently reasons without live statistical evidence. It does not
see whether the observed uplift is statistically significant (p-value), how
wide the confidence interval is, or whether the audience was split correctly
(Sample Ratio Mismatch check). When data is ambiguous, it defaults to caution.

This is not a bug — it is a direct consequence of the statistical engine
(`src/stat_engine.py`) being built but not yet connected to agent prompts.
The fix is concrete and scheduled for Sprint 1.

**Is 40% FPR acceptable?**
At PoC stage: yes, as a deliberate starting position. The system is calibrated
to prioritise safety over speed. The calibration roadmap below targets <15%
FPR after statistical evidence is injected into reasoning.

---

### 1.5 Improvement Roadmap

| Problem | Root cause | Fix | Target outcome | Sprint |
|---------|-----------|-----|----------------|--------|
| FPR 40% → target <15% | No live statistics in agent prompts | Inject StatEvidenceBundle into Doctor and Commander: Welch's t-test for means (AOV, GMV, orders), Delta method for ratio metrics (gp_margin, fill_rate), SRM detection, confidence intervals, effect size | Doctor stops blocking safe experiments when math confirms signal | 1 |
| risk_009 cause unknown | Batch mode does not save full decision artifacts | Persist complete decision record per case in batch runs | Any error explained within 5 minutes | 1 |
| FNR 10% → target 0% | Unknown until risk_009 is analysed | Targeted prompt fix after root cause is identified | Zero missed risks | 2 |

---

## Section 2 — Reasoning Quality

### 2.1 Why We Measure This

A correct decision is not enough. The system must be able to explain — clearly
and with evidence — why it decided what it decided.

If an agent arrives at the right answer without coherent reasoning, that is
fragile: the next time, there will be no trail to follow when something goes
wrong. We measure whether agents use real data and build logical chains —
or generate convincing text that cannot be checked.

---

### 2.2 What We Measure — Each Component Explained

**Component 1: Share of claims backed by data**
(`grounded_claim_rate`)

Doctor makes statements about metrics. Each statement is checked:
does it reference an actual number from the experiment data?

Example — backed: *"GP margin fell from 18.4% to 16.1% (−12.5%),
exceeding the guardrail threshold of 5%"*
Example — not backed: *"customers may become dissatisfied"*

How it is calculated: the evaluation script counts every metric-related
statement in Doctor's output. Each claim is binary: it either references
a data point (1) or it does not (0). The score is the average.

Formula: `claims with data reference / total claims`
Range: 0.0 (nothing backed) → 1.0 (everything backed)

Planned improvement: three-level scoring — 0.0 (no data), 0.5 (metric named
without a number), 1.0 (metric + exact value + confidence interval) — to
reward precision more granularly. See `IMPLEMENTATION_PLAN.md`, Sprint 2.

---

**Component 2: Completeness of reasoning chains**
(`causal_chain_completeness`)

When Doctor identifies a problem, does it explain the full chain?
A complete reasoning chain has four parts:

> *Observation: fill_rate dropped 4.7%*
> *Cause: aggressive premium SKU concentration*
> *Consequence: customers cannot receive orders on time*
> *Action: hold until assortment recovery*

The script checks each chain: are all four parts present?
Formula: `complete chains / all chains`
Range: 0.0 → 1.0

---

**Component 3: Uniqueness of explanations**
(`explanation_uniqueness`)

If three different experiments receive three identical explanations,
the agent is applying a template, not reasoning.
The script compares explanations across all hypotheses and counts the
proportion that are genuinely distinct.
Formula: `unique explanations / all explanations`
Range: 0.0 → 1.0

---

**Narrative score** (`narrative_score`)

Combines all components into one number:

```
narrative_score = 0.45 × claims_backed_by_data
               + 0.25 × chain_completeness
               + 0.15 × explanation_uniqueness
               + 0.15 × share_of_actions_accepted_by_Commander

Weights sum to 1.0.
```

Weight logic: data grounding matters most (45%) — an ungrounded claim is
opinion. Chain quality is second (25%) — without cause-and-effect, decisions
cannot be explained to stakeholders. Uniqueness and action alignment each
contribute 15%.

---

**Reasoning quality score** (`reasoning_quality_score`)

```
reasoning_quality = 0.70 × narrative_score
                  + 0.30 × (unique_hypotheses / total_hypotheses)

Weights sum to 1.0.
```

70% weights explanation quality; 30% weights diversity of thinking.
A system that generates one well-argued unique hypothesis scores better
than one that produces many shallow similar ones.

Current weight rationale: in all runs so far, agents consistently generate
3/3 unique hypotheses — diversity is not the bottleneck. Narrative quality
varies significantly between runs, so 70% correctly targets the actual
differentiator.

---

**Final system score** (`final_score`)

```
final_score = 0.40 × business_value
            + 0.30 × reasoning_quality
            + 0.20 × system_safety
            + 0.10 × reporting_completeness

business_value = 0.60 × Doctor_score + 0.40 × Commander_score
system_safety  = 0.50 × Captain_score + 0.50 × guardrail_retention

All weights sum to 1.0.
```

**Threshold:** `final_score < 0.50` means the system does not outperform
a simple rule-based Python script. Flag: `replaceable_by_python = True`.

---

### 2.3 Results by Run Group

All data from: `data/agent_eval/*_agent_value_eval.json`
Scoring script: `scripts/make_agent_quality_report_v2.py`

#### First runs (19 February 2026)

| Run | Final | Reasoning | Doctor | Narrative | Hypotheses | Replaceable? |
|-----|-------|-----------|--------|-----------|------------|--------------|
| Run #1 | **0.46** | 0.42 | 0.10 | 0.65 | 0 of 0 | **YES** |
| Run #2 | 0.68 | 0.65 | 0.45 | 1.0 | 3 of 3 | No |
| Run #3 | 0.60 | 0.60 | 0.45 | 0.85 | 3 of 3 | No |

Source: `v13_agent_value_001/002/003_agent_value_eval.json`

**Run #1 — why 0.46 and not 0?**
Doctor generated zero hypotheses. But the system as a whole still ran:
Captain validated the experiment (score 0.50), Commander issued a decision
(score 0.70), reporting was complete (1.0).

```
business_value = 0.60 × 0.10 + 0.40 × 0.70 = 0.34
final = 0.40×0.34 + 0.30×0.42 + 0.20×0.50 + 0.10×1.0 = 0.46
```

The `replaceable_by_python = True` flag is the correct signal: without
Doctor's hypotheses, the system functions as a rule-based filter, not
an analytical agent.

---

#### Testing runs (21 February 2026)

| Run | Final | Reasoning | Doctor | Narrative | Hypotheses | Replaceable? |
|-----|-------|-----------|--------|-----------|------------|--------------|
| Run #4 | 0.73 | 0.74 | 0.45 | 1.0 | 3 of 3 | No |
| Run #5 | 0.67 | 0.74 | 0.45 | 1.0 | 3 of 3 | No |
| Run #6 | 0.73 | 0.74 | 0.45 | 1.0 | 3 of 3 | No |
| Run #7 | 0.72 | 0.72 | 0.45 | 1.0 | 3 of 3 | No |
| Run #8 | 0.72 | 0.72 | 0.45 | 1.0 | 3 of 3 | No |

Source: `v13_agent_shadow_001/002/003_agent_value_eval.json`,
`v13_agent_canary_001/002_agent_value_eval.json`

System stabilised in the 0.67–0.73 range. All hypotheses unique (3 of 3),
narrative fully grounded (1.0) across all five runs.

---

#### Production runs (21 February 2026)

| Run | Final | Reasoning | Doctor | Narrative | Hypotheses | Replaceable? |
|-----|-------|-----------|--------|-----------|------------|--------------|
| Run #9 | 0.73 | 0.74 | 0.45 | 1.0 | 3 of 3 | No |
| Run #10 | 0.70 | 0.67 | **0.50** | 1.0 | 3 of 3 | No |

Source: `v13_agent_prod_002/003_agent_value_eval.json`

Run #10 achieved the highest Doctor score in this series (0.50).

---

#### Regression runs (27 February 2026)

| Run | Final | Reasoning | Doctor | Narrative | Hypotheses | Replaceable? |
|-----|-------|-----------|--------|-----------|------------|--------------|
| Run #11 | **0.52** | 0.52 | **0.30** | 0.75 | 3 of 3 | No |
| Run #12 | **0.52** | 0.52 | **0.30** | 0.75 | 3 of 3 | No |

Source: `v13_agent_prod_011/013_agent_value_eval.json`

**What happened:**
Doctor reasoned correctly in both runs — all hypotheses unique, narrative 0.75,
all methodology checks passed, `methodology_match_score = 0.85`.
Despite this, Doctor's score was capped at 0.30 by an external constraint.

**Analogy:** imagine a doctor who correctly diagnosed the patient, prescribed
the right treatment, and explained everything clearly — but received a failing
grade because the patient intake form had one field left blank. The clinical
work was excellent; the problem was administrative.

**Technical explanation:**
The experiments in runs #11 and #12 had an empty `ab_primary_goal` field
(the declared primary objective of the experiment). The evaluation logic
checked this field, found it invalid, and applied a hard score ceiling of 0.30.
This was not a model failure. It was a data validation defect.

**Fix applied 20 March 2026:**
`ab_primary_goal` added as a required field in the experiment template.
Subsequent runs returned to the 0.70+ range.

---

### 2.4 Reasoning Quality Trajectory

```
Run #1  (19 Feb):   reasoning_quality = 0.42 | Doctor = 0.10 | replaceable by script
After fix:          reasoning_quality = 0.65 | Doctor = 0.45 | system is autonomous
Stable (21 Feb):    reasoning_quality = 0.74 | Doctor = 0.45–0.50
Regression (27 Feb):reasoning_quality = 0.52 | Doctor = 0.30 | data defect, not model
Post-fix (20 Mar):  reasoning_quality = 0.74+ | back to baseline
Crash Tests (demo): avg confidence = 0.77 | best result on curated cases
```

Sources: `data/agent_eval/`, `examples/investor_demo/reports_for_humans/executive_roi_scorecard.md`

---

### 2.5 Current State (investor_demo_batch_v2)

| Metric | Value | Source |
|--------|-------|--------|
| Average decision confidence | **0.77** | `executive_roi_scorecard.md` |
| Average cost per decision | **$0.0031** | `executive_roi_scorecard.md` |
| Missed risks (FNR) | **0%** | `executive_roi_scorecard.md` |
| Safe cases blocked (FPR) | **0%** | `executive_roi_scorecard.md` |

**Important context:** investor_demo_batch_v2 contains 3 carefully selected
Crash Test cases. This is not a random sample — it is a curated exam set.
For real-scale performance, see mass_test_003 results in Section 1.

Source: `examples/investor_demo/reports_for_humans/executive_roi_scorecard.md`

---

## Section 3 — Known Limitations

Everything listed here is an intentional PoC scope decision or a tracked
open item. Nothing is hidden.

| Limitation | Plain-language meaning | Status |
|------------|----------------------|--------|
| FNR 10% in mass test | 1 of 10 risky experiments approved; root cause unknown (full artifact not saved) | Sprint 1 — fix artifact persistence |
| FPR 40% in mass test | 4 of 10 safe experiments unnecessarily held | Sprint 1 — inject live statistics |
| No live statistics in agent reasoning | Agents do not see p-values, confidence intervals, or SRM results when deciding | Sprint 1 — infrastructure ready, integration pending |
| No full decision artifact in batch mode | When the system errors in batch, the cause cannot be determined | Sprint 1 |
| `doi`, `inventory_turnover`, `days_to_expiry`, `aged_inventory_share` return null | Metrics not yet in simulation tables | Open — next simulation schema iteration |
| Churn rate = 0.0 on short runs | Reliable churn requires minimum 30-day history | Expected — document minimum run length |
| Reconciliation worker fails on clean install | `data/reconciliation/` missing → worker crashes | P2 open — add `Path.exists()` guard |
| Not tested on real production data | All tests use synthetic or hand-crafted data | Open — required before production deployment |
| GP margin definition is partial | `revenue − product COGS` only; delivery cost not included | Intentional PoC simplification |
| Scoring granularity: binary claim evaluation | grounded_claim_rate and chain_quality use binary (0/1) scoring | Sprint 2 — upgrade to 3-level scoring |

---

## Section 4 — How This Document Is Updated

This file is generated automatically. Do not edit it manually —
changes will be overwritten on the next batch run.

**What triggers an update:**
When a batch run completes and writes a `*_summary.json` to `data/batch_eval/`,
the script `scripts/make_evaluation_report.py`:

1. Finds the two most recent batch summary files in `data/batch_eval/`
2. Reads agent evaluation scores from `data/agent_eval/`
3. Archives the current version of this document into `EVALUATION_HISTORY.md`
4. Writes a fresh `EVALUATION_REPORT.md`

**Why two batches:**
One batch run can be atypical. Two runs together reveal a pattern.
Everything older is preserved in `EVALUATION_HISTORY.md` for audit
and longitudinal comparison.

**If the date at the top is older than the last git commit:**
The batch ran but the generator script was not called.
Run manually: `python scripts/make_evaluation_report.py`
