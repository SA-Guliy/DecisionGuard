# PUBLISH AUDIT CHECKLIST

- Generated at: `2026-03-21T03:50:09.893648+00:00`
- Publish mode: `staging_only`
- Publish root: `github_publish`

## Blocking checks
- `publish_root_exists`: **PASS**
- `historical_corpus_lock`: **PASS**
- `export_manifest_integrity`: **PASS**
- `whitelist_conformance`: **PASS**
- `denylist_conformance`: **PASS**
- `banned_pattern_scan`: **FAIL**
- `secret_scan`: **FAIL**
- `markdown_link_check`: **FAIL**
- `py_compile`: **PASS**
- `unit_smoke_tests`: **PASS**

## Notes
- publish_files_count: `272`
- blocking_failures: `3`

## Blocking Pre-Push Controls
- `git add demo_sources/investor_demo/*`
- Ensure the command above is executed before final push/commit for publish release.

