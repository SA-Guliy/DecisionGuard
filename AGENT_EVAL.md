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

## 6. Implementation Status

| Capability | Status |
|---|---|
| Live `StatEvidenceBundle` injected into Doctor and Commander contexts | Implemented |
| Dynamic `reasoning_confidence` replacing hardcoded constant | Implemented |
| Per-metric statistical method selection (Welch / Delta Method / Bootstrap) | Implemented |
| Automated evaluation pipeline with regression detection | Planned |

