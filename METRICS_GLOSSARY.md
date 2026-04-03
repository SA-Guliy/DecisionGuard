# Metrics Glossary (Canonical)

This glossary defines classification metrics used across public DecisionGuard documents.

## Core Definitions

- `FNR` (False Negative Rate): risky experiments incorrectly approved.
  - Formula: `FN / risky_cases`
  - `FN` means: `expected_block=true` and model decision is not blocking (`predicted_block=false`).
- `FPR` (False Positive Rate): safe experiments incorrectly blocked.
  - Formula: `FP / safe_cases`
  - `FP` means: `expected_block=false` and model decision is blocking (`predicted_block=true`).

## Reporting Rule

- Every published FNR/FPR value must include denominator context:
  - Example: `10% (1/10 risky)`
  - Example: `40% (4/10 safe)`

## Source of Truth

- Canonical batch metrics source:
  - `examples/investor_demo/reports_for_agents/batch_summary.json`
- Human-facing reports must match this source for the same batch.

