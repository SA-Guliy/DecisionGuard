# Methodology Tree (Simple Version for HR + 10 y.o.)

This is a plain-language map of how the project works from data generation to decision.

## 0) Build a synthetic world

We first create a practice world (synthetic data), not real customer data.

- We generate orders, products, customers, time effects, and shocks.
- We use deterministic seeds so results are repeatable.
- Goal: create realistic-but-safe training data for experiments.

## 1) Simulate operations

We run the darkstore simulation:

- requested units (demand),
- fulfilled units (what we could deliver),
- losses (OOS and write-off),
- economics (GMV, GP, margin).

Think of this as a “game replay” where every action has numbers.

## 2) Data quality gate (Captain)

Before trusting any result, we check data sanity:

- missing/negative values,
- impossible identities,
- anti-gaming checks (e.g., fake improvement by starving availability).

If quality fails, decisions become conservative.

## 3) A/B observability gate

We only trust experiment uplift if A/B setup is valid:

- assignment exists (control/treatment are real),
- unit is correct (customer vs store),
- method is measurable (no blind spot).

States:

- `OBSERVABLE` = we can measure effect,
- `UNOBSERVABLE` = we cannot measure effect safely,
- `BLOCKED_BY_DATA` = key inputs are missing.

## 4) Doctor (Experiment Scientist)

Doctor creates a portfolio of hypotheses:

- what action to test,
- expected metric impact,
- guardrails,
- falsifiability rule (“if X does not improve, reject”).

If measurement is impossible, Doctor must output a fix plan (not fake uplift).

## 5) Evaluator (Fact-first judge)

Evaluator converts evidence into decision:

- stop/hold/run based on AB status + guardrails.

No storytelling can override this.

## 6) Commander (Final decision with safety ceiling)

Commander can prioritize, but cannot break safety rules:

- no rollout when measurement is blind,
- no aggressive decision if evaluator says hold/stop.

## 7) Narrative Analyst (explain WHY)

Narrative gives causal explanations with evidence:

- observation,
- cause hypothesis,
- alternatives,
- confidence,
- what would disprove the claim.

If ungrounded, system enforces safe ceiling.

## 8) Acceptance verification (single command)

`scripts/verify_acceptance.py` checks end-to-end:

- required artifacts exist,
- critical safety rules pass,
- no fake wins in blind spots,
- reports are consistent.

Output:

- `data/acceptance/<run_id>_acceptance.json`
- `reports/L1_ops/<run_id>/ACCEPTANCE_REPORT.md`

## 9) Why this is not “just scripts”

- Python enforces safety and consistency.
- Agents generate hypotheses and causal reasoning.
- Validation checks whether reasoning is grounded.
- Final decisions remain deterministic and auditable.

This balance gives creativity + safety at the same time.
