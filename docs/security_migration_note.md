# Security Migration Note (Integrity Fail-Closed)

## What changed
- Production and lightweight runtime profiles now enforce artifact integrity with a final `integrity_finalize` gate.
- `artifact_manifest.json` + `*.sha256` are required for critical JSON reads in production runtime contexts.
- `pre_publish_audit` and `verify_acceptance` now enforce strict manifest scope checks (extra run-scoped JSON not listed in manifest causes fail).

## Legacy runs (no manifest yet)
1. Rebuild run reports to generate fresh `links.json` and manifest:
   - `python3 scripts/build_reports.py --run-id <RUN_ID>`
2. Finalize integrity state:
   - `python3 scripts/integrity_finalize.py --run-id <RUN_ID>`
3. Re-run acceptance gates:
   - `python3 scripts/pre_publish_audit.py --run-id <RUN_ID> --strict 1 --out-json data/agent_quality/<RUN_ID>_pre_publish_audit.json`
   - `python3 scripts/verify_acceptance.py --run-id <RUN_ID> --require-pre-publish 1`

## Temporary compatibility guidance
- Avoid weakening production guardrails.
- If a historical artifact is irrecoverable, regenerate from source pipeline steps and re-run `integrity_finalize`.
- Do not manually edit JSON after `integrity_finalize`; if edits are required, rerun `integrity_finalize` before publish gates.
