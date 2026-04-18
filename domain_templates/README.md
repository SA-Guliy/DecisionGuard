# Domain Templates

`domain_templates/` stores external domain-physics contracts for runtime agents.

- `darkstore_fresh_v1.json`: default template for current darkstore/fresh domain.
- `*.json.sha256`: integrity sidecars used by strict runtime profiles.
- Values in public templates are synthetic/illustrative demo thresholds only.
- No proprietary supplier/category naming or private operating coefficients should be stored here.

Core agents (`Agent-1`, `Agent-2`, `Agent-3`, evaluator/status taxonomy) should read domain-specific goal/metric/guardrail mappings from this folder through `src/domain_template.py`.
