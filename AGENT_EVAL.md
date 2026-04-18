# DecisionGuard Agent Evaluation Framework

## Why This Document Exists

Most AI-agent evaluations focus on final correctness, not on reasoning quality that produced the output.

This document defines how DecisionGuard evaluates reasoning quality, not only output correctness.

Core principle: a system that is sometimes right for the wrong reason will silently degrade in production.

> **Status:** project is in active development; the evaluation contour is still being hardened.
> Public benchmark claims in this document are restricted by public-safe machine-checkable source policy.
> Strong decision KPI alone do not prove that the staff-level reasoning gap is closed.

---

## 1. Evaluation Philosophy

A correct decision is not the same as correct reasoning.

For LLM governance systems, outcome-only metrics such as FPR/FNR are not sufficient:
- they do not prove evidence completeness;
- they do not prove guardrail enforcement quality;
- they do not prove reasoning stability across similar contexts;
- they do not separate format discipline from semantic depth.

Canonical metric definitions are in `METRICS_GLOSSARY.md`.

DecisionGuard therefore evaluates reasoning-path, not only the final label.

---

## 2. Benchmark and Public-Claim Context

Public communication is split into two layers:

- **canonical claims**: machine-checkable benchmark metrics tied to source-of-truth artifacts;
- **curated deep-dive**: explanatory reasoning analysis on limited demo scope.

This distinction is required so explanatory sections do not override canonical benchmark claims.

---

## 3. Reasoning Layer Model

| Layer | What it measures | Why it matters |
|---|---|---|
| **L1 — Live Primary Delta** | Statistical evidence for primary metric between control and treatment | Prevents decisions on noise |
| **L2 — Live Guardrail Deltas** | Guardrail-breach detection with statistical context | Detects hidden degradations before rollout |
| **L3 — Historical Analog Patterns** | Similarity to relevant historical precedents and outcomes | Adds operational memory to current decision |

A decision with all three layers active should be held to a stricter confidence standard than one based on historical context only.

---

## 4. Scoring Dimensions

### Dimension 1 — Reasoning Layer Coverage
- Which reasoning layers were active?
- Was reasoning grounded in live statistical evidence?

### Dimension 2 — Statistical Grounding
- Did the agent cite p-values and confidence intervals?
- Were alternative explanations considered?

### Dimension 3 — Guardrail Sensitivity
- Were relevant guardrail metrics explicitly covered?
- Were breaches treated as hard blockers instead of soft recommendations?

### Dimension 4 — Decision Calibration
- False Negative Rate: risky experiment approved by mistake.
- False Positive Rate: safe experiment blocked by mistake.

### Dimension 5 — Hypothesis Articulation
- Are H0/H1 explicitly defined?
- Is the claim falsifiable?

### Dimension 6 — Format Compliance
- Are required reasoning fields populated?
- Are evidence links verifiable?
- Are required schema/contract fields respected?

### Dimension 7 — Semantic Depth
- Is reasoning tied to case-specific evidence instead of universal templates?
- Are counterfactual and uncertainty blocks concrete?
- Is it explicit what would change the decision and why?

---

## 5. Staff-Level Reasoning Standard

### What Staff-Level Reasoning Means Here

**Junior-level reasoning:** correct conclusion, hidden assumptions not explicit.

**Mid-level reasoning:** conclusion plus primary-metric evidence.

**Senior-level reasoning:** conclusion plus evidence plus guardrail-check.

**Staff-level reasoning:** all above, plus:
- explicit H0/H1 and significance threshold;
- confidence intervals, not only point estimates;
- alternative explanations considered and rejected;
- time-dynamics considered;
- sensitivity analysis;
- historical analog grounding;
- case-specific evidence linkage without template dependence.

DecisionGuard targets this standard. The framework is used to measure and close the gap systematically.

---

## 6. Evaluation Methodology

Evaluation runs as a repeatable process:
- adversarial test suite for fail-closed behavior;
- structured reasoning schema compliance checks;
- cross-run consistency scoring;
- calibration against human expert baseline.

---

## 7. Current Evaluation-Contour Updates (2026)

### 7.1 Outcome Quality and Semantic Depth Are Split

In the internal evaluation contour, scoring is split into:
- decision outcome quality;
- structural reasoning correctness;
- semantic reasoning depth.

This lowers the risk of formal pass-through based only on template-friendly formatting.

### 7.2 Depth-Aware Release Checker

In the internal release-checker contour, gating uses not only decision KPI but also depth-aware reasoning signals.

Strong FPR/FNR alone does not imply staff-level reasoning quality.

### 7.3 Anti-Gaming Hardening

Internal reasoning checks require both format correctness and verifiable evidence linkage:
- either a valid link to a corresponding evidence artifact;
- or confirmed structured historical context.

This reduces risk of inflated scores from templated reasoning fields.

### 7.4 CI and Evaluation Contour

Public blocking CI covers baseline critical evaluation checks.

Full regression/evaluation contour still runs via a separate protocol, not as a single minimal CI pass.

### 7.5 Release-Candidate Restrictions

The internal release-candidate contour enforces additional policy constraints for fallback behavior and runtime artifact provenance.

This keeps release sign-off stricter than exploratory runtime.

### 7.6 Score Interpretation Rule

Growth in governance/staff reasoning score is not equivalent to pure model intelligence growth.

The number is influenced by:
- updated rubric and scoring scale;
- stricter/more structured reasoning format;
- reduced technical-default and fallback noise;
- possible partial score gains from template-style inputs.

Correct external framing:

> **On the current synthetic benchmark, governance score and decision stability improved significantly.**
> **Semantic depth reasoning continues to be strengthened in a separate depth-aware contour and should not be over-interpreted from aggregate score alone.**

---

## 8. Public-Safe Canonical Claims Policy

In the public repository, canonical benchmark claims are published only if all conditions hold:

- source artifact is tracked in git;
- source artifact has valid `.sha256` sidecar;
- claim passes CI consistency checks;
- source artifact is outside private deny/ignore zones.

Current public status for this document:

- detailed machine-checkable benchmark metrics are **not published here**;
- detailed benchmark summaries and deep-dive sources are maintained in internal contour;
- public SoT for demo artifact layout is `examples/investor_demo/DEMO_GUIDE.md`.

This is an intentional public-safe and privacy constraint, not a refusal to measure KPI internally.

---

## 9. Curated Deep-Dive Policy (Public-Safe)

Curated deep-dive is used for qualitative reasoning analysis, but in public-safe mode:

- case-level internal artifacts are not published;
- private human reports and internal benchmark summaries are not published;
- metrics that cannot be independently verified via tracked public source paths are not published.

What remains public:

- reasoning evaluation methodology;
- score interpretation rules;
- outcome-quality vs semantic-depth separation;
- evidence-link and anti-gaming requirements.

This prevents mismatch between public claims and actual public source availability.

---

## 10. Implementation Status (Public-Safe View)

| Capability | Public status |
|---|---|
| Statistical runtime core (`src/stat_engine.py`, `src/reasoning_confidence.py`) | Publicly tracked |
| Retrieval runtime foundation (`src/retrieval_runtime.py`) | Publicly tracked |
| A2/A3 depth-scoring contour and depth-aware release checker | Internal contour (not fully published in tracked public set) |
| Automated full evaluation pipeline with regression detection | Planned / In Progress |

---

## 11. Capability Status (PRD SoT)

Status source: `PRD.md` (private draft; `PRD_SOT_V1_START` block is exported by CI into machine artifact).
Publicly, these statuses are governance declarations and can require internal artifacts for full independent verification.

| capability_id | status |
|---|---|
| `paired_experiment_mode` | `IMPLEMENTED` |
| `reconciliation_runtime` | `IMPLEMENTED` |
| `staff_level_reasoning` | `IN_PROGRESS` |
| `fpr_non_go_remediation_program` | `IN_PROGRESS` |

Release-candidate policy gating for high `fpr_non_go` remains active in acceptance; runtime remediation to reduce false positives is still in progress.
