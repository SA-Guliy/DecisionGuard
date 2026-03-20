# Investor Demo Guide

This folder is the single Source of Truth for public demo artifacts.

## Layout
- `reports_for_humans/decision_card.md`
- `reports_for_humans/batch_consolidated_report.md`
- `reports_for_humans/executive_roi_scorecard.md`
- `reports_for_agents/batch_summary.json`
- `reports_for_agents/agent_run_sample.json`
- `reports_for_agents/cost_ledger.json`
- `reports_for_agents/reconciliation_summary.json`
- `synthetic_data/synthetic_dataset_sample.json`

## Release Policy
- publish_mode is `staging_only`.
- Runtime artifacts outside `examples/investor_demo/` are not public demo sources.
- Artifacts are sanitized: local absolute paths, secret-source fields, and machine-specific refs are removed.
- Safe key allowlist is preserved in sanitization: `prompt_tokens`, `completion_tokens`, `total_tokens`, `token_count`, `ttl`, `ttl_hours`, and `*_ttl` fields.
- Markdown artifact integrity is enforced with per-file `.sha256` sidecars and export-manifest hash chain.
