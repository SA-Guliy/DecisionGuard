# Domain Templates

`domain_templates/` stores external domain-physics contracts for runtime agents.

- `darkstore_fresh_v1.json`: default template for current darkstore/fresh domain.
- `*.json.sha256`: integrity sidecars used by strict runtime profiles.

Core agents (`Captain`, `Doctor`, `Commander`, evaluator/status taxonomy) should read domain-specific goal/metric/guardrail mappings from this folder through `src/domain_template.py`.
