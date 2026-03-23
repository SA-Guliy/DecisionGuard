# Agent Evaluation Framework

## Why This Document Exists

Most AI agent projects ship without a measurement system.
This document defines how DecisionGuard measures reasoning quality, not only output correctness.

The core belief is simple: a system that returns the right answer for the wrong reason will fail silently in production.

## 1. Evaluation Philosophy

A correct decision is not the same as correct reasoning.

For LLM-based governance systems, outcome-only metrics (for example FPR/FNR) are necessary but not sufficient:
- They do not show whether evidence was complete.
- They do not show whether guardrails were actively enforced.
- They do not show whether the same decision logic is stable across similar contexts.

DecisionGuard therefore evaluates the reasoning path itself, not only the final label.

## 2. Reasoning Layer Model

| Layer | What it measures | Why it matters |
|---|---|---|
| L1 - Live Primary Delta | Statistical evidence on primary metric between control and treatment | Prevents decisions driven by noise |
| L2 - Live Guardrail Deltas | Per-metric guardrail breach detection with statistical context | Detects hidden degradations before rollout |
| L3 - Historical Analog Patterns | Semantic similarity to prior experiments and outcomes | Grounds decisions in operational memory |

A decision produced with all three layers active is held to a higher confidence standard than one built from historical context only.

## 3. Scoring Dimensions

### Dimension 1: Reasoning Layer Coverage
- Which layers were active for this decision?
- Was reasoning grounded in live statistical evidence?

### Dimension 2: Statistical Grounding
- Did the agent cite p-values and confidence intervals?
- Were alternative hypotheses considered?

### Dimension 3: Guardrail Sensitivity
- Did the agent enumerate all guardrail metrics?
- Were breaches treated as hard blockers, not soft suggestions?

### Dimension 4: Decision Calibration
- False Positive Rate: aggressive decision when risk was present.
- False Negative Rate: HOLD decision when rollout was actually safe.

### Dimension 5: Hypothesis Articulation
- Were H0 and H1 stated explicitly?
- Was the claim falsifiable?

## 4. Staff-Level Reasoning Standard

### What "Staff-Level Reasoning" Means Here

Junior analyst reasoning: correct conclusion, missing explicit assumptions.

Mid-level reasoning: conclusion plus primary metric evidence.

Senior reasoning: conclusion plus evidence plus guardrail check.

Staff-level reasoning: all of the above, plus:
- Explicit H0/H1 and significance threshold.
- Confidence intervals, not only point estimates.
- Alternative explanations considered and ruled out.
- Temporal dynamics (stable, decaying, or delayed effects).
- Sensitivity analysis (what would change the decision).
- Historical analog grounding with similarity score.

DecisionGuard is built to this standard. The evaluation framework exists to measure the current gap and systematically close it.

## 5. Evaluation Methodology

Evaluation is performed as a repeatable process:
- Adversarial test suite for fail-closed behavior.
- Structured chain-of-thought template compliance checks.
- Cross-run consistency scoring.
- Human expert calibration baseline.

## 7. Validation Results

> Source: `investor_demo_batch_v2` · Backend: `groq/llama-3.3-70b` · 3 cases · Full artifacts: [`examples/investor_demo/`](examples/investor_demo/)

### Portfolio Summary

| Metric | Value |
|---|---|
| Total runs | 3 |
| Cloud-path runs | 3 (100%) |
| Final `GO` decisions | 1 |
| Final `HOLD_NEED_DATA` decisions | 2 |
| FPR (aggressive decision on risk case) | **0%** (0/2) |
| FNR (blocked safe iteration) | **0%** (0/1) |
| Avg reasoning confidence | **0.77** |
| Avg cost per run | **$0.0031** |

### Per-Case Scoring

| Case | Scenario | Paired Status | Layers Active | Decision | Confidence |
|---|---|---|---|---|---|
| `demo_case_001` | Dynamic bundling offers | `COMPLETE` | L1 + L2 + L3 | `GO` | 0.87 |
| `demo_case_002` | Aggressive discount, slow-moving SKUs | `COMPLETE` | L1 + L2 + L3 | `HOLD_NEED_DATA` | 0.91 |
| `demo_case_003` | Treatment arm failed mid-run | `TREATMENT_FAILED` | L3 only | `HOLD_NEED_DATA` | 0.54 |

### Scoring Dimensions — Demo Suite Evidence

**Dimension 1 — Reasoning Layer Coverage**

Cases 001 and 002 ran with `paired_status=COMPLETE`: all three layers active (L1 live primary delta, L2 guardrail deltas, L3 historical). Case 003 had `TREATMENT_FAILED`: no live statistics available, L3 only, confidence correctly capped at 0.54 (policy ceiling: 0.60 for partial/failed runs).

**Dimension 2 — Statistical Grounding**

- Case 001: primary metric AOV `+6.2%` (`p=0.021`, 95% CI `[+0.94, +4.18]`); guardrail deltas cited with p-values (`fill_rate p=0.34`, `gp_margin p=0.19`) — not significant, decision `GO`.
- Case 002: primary GMV `+4.1%` (`p=0.003`, 95% CI `[+1.4%, +6.8%]`); two guardrail breaches with p-values: `gp_margin 0.312→0.284` (`p=0.001`), `oos_lost_gmv_rate 0.041→0.067` (`p=0.008`) — decision `HOLD_NEED_DATA` despite positive primary signal.

**Dimension 3 — Guardrail Sensitivity**

Case 002 is the key test: primary metric was statistically significant and positive, yet the system issued `HOLD_NEED_DATA` because two guardrail metrics breached independently with high confidence. Guardrail breaches were treated as hard blockers, not soft suggestions. Case 003: incomplete treatment arm → hard governance ceiling regardless of primary metric value.

**Dimension 4 — Decision Calibration**

FPR = 0%: both risk cases (002, 003) correctly held. FNR = 0%: the safe case (001) correctly approved.

**Dimension 5 — Hypothesis Articulation**

Explicit H0/H1 formulation and sensitivity analysis are not yet present in agent outputs. This is the primary gap between current Senior-level reasoning and Staff-level standard. Infrastructure is built (stat engine, confidence policy); structured CoT template injection into agent prompts is the next sprint.

---

## 6. Implementation Status

| Capability | Status |
|---|---|
| Live `StatEvidenceBundle` injected into Doctor and Commander contexts | Implemented |
| Dynamic `reasoning_confidence` replacing hardcoded constant | Implemented |
| Per-metric statistical method selection (Welch / Delta Method / Bootstrap) | Implemented |
| Automated evaluation pipeline with regression detection | Planned |

