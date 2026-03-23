#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import ast
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import verify_sha256_sidecar

DEFAULT_SMOKE_TESTS = [
    "tests/test_commander_hypothesis_review_v1.py",
    "tests/test_historical_retrieval_gate_v32.py",
]
BANNED_PATTERNS = [
    (re.compile(r"/Users/[^\s`\"'<>]+"), "absolute_unix_path"),
    (re.compile(r"[A-Za-z]:\\\\[^\s`\"'<>]+"), "absolute_windows_path"),
    (re.compile(r"\.groq_secrets\b"), "secret_file_ref"),
    (re.compile(r"secrets_source", re.IGNORECASE), "secrets_source"),
    (re.compile(r"sanitization_kms_source", re.IGNORECASE), "sanitization_kms_source"),
    (re.compile(r"file://[^\s`\"'<>]+"), "file_uri"),
]
SECRET_PATTERNS = [
    (re.compile(r"\bgsk_[A-Za-z0-9_\-]{20,}\b"), "groq_key"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), "api_key"),
    (
        re.compile(
            r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*"
            r"[\"'](?=[^\"']*[A-Z])(?=[^\"']*(?:\d[^\"']*){2,})[A-Za-z0-9_\-]{24,}[\"']"
        ),
        "secret_kv",
    ),
]
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
LOCKED_CORPUS_DIR = ROOT / "not_delete_historical_patterns/metrics_snapshots"
LOCKED_CORPUS_MIN_JSON_SIDECAR_PAIRS = 2


def _load_lines(path: Path) -> list[str]:
    if not path.exists():
        raise SystemExit(f"missing_control_file:{path}")
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def _match_any(path: str, globs: list[str]) -> bool:
    norm = path.replace("\\", "/")
    return any(fnmatch.fnmatch(norm, g.replace("\\", "/")) for g in globs)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _iter_publish_files(publish_root: Path) -> list[Path]:
    out: list[Path] = []
    for p in publish_root.rglob("*"):
        if not p.is_file():
            continue
        out.append(p)
    return sorted(out)


def _scan_patterns(
    files: list[Path],
    patterns: list[tuple[re.Pattern[str], str]],
    *,
    publish_root: Path,
    skip_python_for_banned: bool = False,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in files:
        suffix = path.suffix.lower()
        if suffix not in {".json", ".md", ".txt", ".yaml", ".yml", ".py", ".sql", ".sh"}:
            continue
        if skip_python_for_banned and suffix == ".py":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        rel = path.relative_to(publish_root).as_posix()
        for i, line in enumerate(text.splitlines(), start=1):
            for rx, name in patterns:
                if rx.search(line):
                    findings.append(
                        {
                            "type": name,
                            "path": rel,
                            "line": i,
                            "snippet": line[:200],
                        }
                    )
    return findings


def _check_markdown_links(files: list[Path], *, publish_root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in files:
        if path.suffix.lower() != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(publish_root).as_posix()
        for i, line in enumerate(text.splitlines(), start=1):
            for m in MARKDOWN_LINK_RE.finditer(line):
                target = m.group(1).strip()
                if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                local = (path.parent / target).resolve()
                try:
                    local.relative_to(publish_root.resolve())
                except Exception:
                    findings.append(
                        {
                            "type": "markdown_link_outside_publish_root",
                            "path": rel,
                            "line": i,
                            "target": target,
                        }
                    )
                    continue
                if not local.exists():
                    findings.append(
                        {
                            "type": "markdown_link_missing",
                            "path": rel,
                            "line": i,
                            "target": target,
                        }
                    )
    return findings


def _run_cmd(cmd: list[str], *, cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    tail = "\n".join((proc.stdout or "").splitlines()[-20:] + (proc.stderr or "").splitlines()[-20:])
    return proc.returncode, tail.strip()


def _check_py_compile(publish_root: Path) -> tuple[bool, str]:
    errors: list[str] = []
    seen = 0
    for rel_dir in ("src", "scripts", "tests"):
        d = publish_root / rel_dir
        if not d.exists():
            continue
        for p in d.rglob("*.py"):
            seen += 1
            try:
                ast.parse(p.read_text(encoding="utf-8"), filename=p.as_posix())
            except Exception as exc:
                errors.append(f"{p.relative_to(publish_root).as_posix()}: {exc}")
                if len(errors) >= 20:
                    break
        if len(errors) >= 20:
            break
    if seen == 0:
        return False, "missing_python_targets_in_publish_root"
    if errors:
        return False, "\n".join(errors[:20])
    return True, "ok"


def _check_smoke_tests(enabled: bool) -> tuple[bool, str]:
    if not enabled:
        return True, "skipped"
    rc, tail = _run_cmd(["python3", "-m", "unittest", *DEFAULT_SMOKE_TESTS], cwd=ROOT)
    return rc == 0, tail


def _check_historical_corpus_lock(
    corpus_root: Path,
    *,
    denylist_globs: list[str],
    min_pairs: int = LOCKED_CORPUS_MIN_JSON_SIDECAR_PAIRS,
) -> tuple[bool, dict[str, Any]]:
    try:
        corpus_label = corpus_root.relative_to(ROOT).as_posix() if corpus_root.is_absolute() else str(corpus_root)
    except Exception:
        corpus_label = str(corpus_root)
    details: dict[str, Any] = {
        "corpus_root": corpus_label,
        "min_pairs_required": int(min_pairs),
        "pairs_found": 0,
        "integrity_issues": [],
        "denylist_hits": [],
    }
    if not corpus_root.exists() or not corpus_root.is_dir():
        details["reason"] = "corpus_root_missing"
        return False, details

    pair_count = 0
    integrity_issues: list[str] = []
    for payload in sorted(corpus_root.glob("*.json")):
        ok, reason = verify_sha256_sidecar(payload, required=True)
        if not ok:
            integrity_issues.append(f"{payload.relative_to(ROOT).as_posix()}:{reason}")
            continue
        pair_count += 1

    details["pairs_found"] = int(pair_count)
    details["integrity_issues"] = integrity_issues[:50]

    corpus_rel_prefix = corpus_root.relative_to(ROOT).as_posix().rstrip("/")
    deny_hits = [g for g in denylist_globs if _match_any(f"{corpus_rel_prefix}/sentinel.json", [g])]
    details["denylist_hits"] = deny_hits[:20]

    if deny_hits:
        details["reason"] = "corpus_path_denied_by_publish_policy"
        return False, details
    if pair_count < int(min_pairs):
        details["reason"] = "insufficient_json_sidecar_pairs"
        return False, details
    if integrity_issues:
        details["reason"] = "corpus_integrity_failed"
        return False, details
    details["reason"] = "ok"
    return True, details


def _check_export_manifest(
    publish_root: Path,
    export_manifest_path: Path,
    payload_files: list[Path],
) -> tuple[bool, list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not export_manifest_path.exists():
        findings.append({"type": "export_manifest_missing", "path": export_manifest_path.relative_to(ROOT).as_posix()})
        return False, findings, {}
    try:
        payload = json.loads(export_manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append({"type": "export_manifest_invalid_json", "path": export_manifest_path.relative_to(ROOT).as_posix(), "detail": str(exc)})
        return False, findings, {}
    if not isinstance(payload, dict):
        findings.append({"type": "export_manifest_invalid_payload", "path": export_manifest_path.relative_to(ROOT).as_posix()})
        return False, findings, {}
    rows = payload.get("files")
    if not isinstance(rows, list):
        findings.append({"type": "export_manifest_missing_files", "path": export_manifest_path.relative_to(ROOT).as_posix()})
        return False, findings, payload

    listed: dict[str, str] = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            findings.append({"type": "export_manifest_row_invalid", "index": i})
            continue
        rel = str(row.get("path", "")).strip()
        sha = str(row.get("sha256", "")).strip().lower()
        if not rel or not sha:
            findings.append({"type": "export_manifest_row_missing_fields", "index": i})
            continue
        listed[rel] = sha

    actual = {p.relative_to(publish_root).as_posix(): _sha256_file(p) for p in payload_files}
    listed_set = set(listed.keys())
    actual_set = set(actual.keys())
    missing = sorted(listed_set - actual_set)
    extra = sorted(actual_set - listed_set)
    if missing:
        findings.append({"type": "export_manifest_missing_files_on_disk", "paths": missing[:50]})
    if extra:
        findings.append({"type": "export_manifest_unlisted_files_on_disk", "paths": extra[:50]})
    for rel, expected_sha in listed.items():
        got = actual.get(rel)
        if got is None:
            continue
        if got.lower() != expected_sha:
            findings.append({"type": "export_manifest_hash_mismatch", "path": rel, "expected": expected_sha, "actual": got})
    return len(findings) == 0, findings, payload


def _render_checklist(payload: dict[str, Any]) -> str:
    checks = payload.get("checks", {})
    lines = [
        "# PUBLISH AUDIT CHECKLIST",
        "",
        f"- Generated at: `{payload.get('generated_at')}`",
        f"- Publish mode: `{payload.get('publish_mode')}`",
        f"- Publish root: `{payload.get('publish_root')}`",
        "",
        "## Blocking checks",
    ]
    for key in [
        "publish_root_exists",
        "historical_corpus_lock",
        "export_manifest_integrity",
        "whitelist_conformance",
        "denylist_conformance",
        "banned_pattern_scan",
        "secret_scan",
        "markdown_link_check",
        "py_compile",
        "unit_smoke_tests",
    ]:
        row = checks.get(key, {})
        status = "PASS" if row.get("pass") else "FAIL"
        lines.append(f"- `{key}`: **{status}**")
    lines.append("")
    lines.append("## Notes")
    lines.append(f"- publish_files_count: `{payload.get('publish_files_count', 0)}`")
    lines.append(f"- blocking_failures: `{payload.get('blocking_failures', 0)}`")
    lines.append("")
    lines.append("## Blocking Pre-Push Controls")
    lines.append("- `git add examples/investor_demo/src/*`")
    lines.append("- Ensure the command above is executed before final push/commit for publish release.")
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Blocking pre-push audit for GitHub staging-only release.")
    parser.add_argument("--publish-mode", default="staging_only", choices=["staging_only"])
    parser.add_argument("--strict", type=int, default=1, choices=[0, 1])
    parser.add_argument("--run-smoke-tests", type=int, default=1, choices=[0, 1])
    parser.add_argument("--publish-root", default="github_publish")
    parser.add_argument("--export-manifest", default="")
    parser.add_argument("--whitelist", default="PUBLISH_WHITELIST.txt")
    parser.add_argument("--denylist", default="PUBLISH_DENYLIST.txt")
    parser.add_argument("--out-json", default="_PROJECT_TRASH/publish_audit_latest.json")
    parser.add_argument("--out-md", default="PUBLISH_AUDIT_CHECKLIST.md")
    args = parser.parse_args()

    publish_root = ROOT / args.publish_root
    export_manifest_path = Path(args.export_manifest) if args.export_manifest else (publish_root / "PUBLISH_EXPORT_MANIFEST.json")
    if not export_manifest_path.is_absolute():
        export_manifest_path = ROOT / export_manifest_path

    whitelist_globs = _load_lines(ROOT / args.whitelist)
    denylist_globs = _load_lines(ROOT / args.denylist)

    publish_root_exists = publish_root.exists() and publish_root.is_dir()
    all_files = _iter_publish_files(publish_root) if publish_root_exists else []
    payload_files = [
        p
        for p in all_files
        if p.relative_to(publish_root).as_posix()
        not in {
            "PUBLISH_EXPORT_MANIFEST.json",
            "PUBLISH_EXPORT_MANIFEST.json.sha256",
            "PUBLISH_EXPORT_MANIFEST.md",
        }
    ]

    manifest_ok, manifest_findings, manifest_payload = _check_export_manifest(publish_root, export_manifest_path, payload_files) if publish_root_exists else (False, [{"type": "publish_root_missing"}], {})

    payload_rels = [p.relative_to(publish_root).as_posix() for p in payload_files]
    whitelist_violations = [rel for rel in payload_rels if not _match_any(rel, whitelist_globs)]
    denylist_hits = [rel for rel in payload_rels if _match_any(rel, denylist_globs)]
    banned_hits = (
        _scan_patterns(
            payload_files,
            BANNED_PATTERNS,
            publish_root=publish_root,
            skip_python_for_banned=True,
        )
        if publish_root_exists
        else []
    )
    secret_hits = _scan_patterns(payload_files, SECRET_PATTERNS, publish_root=publish_root) if publish_root_exists else []
    markdown_hits = _check_markdown_links(payload_files, publish_root=publish_root) if publish_root_exists else []
    compile_ok, compile_tail = _check_py_compile(publish_root) if publish_root_exists else (False, "publish_root_missing")
    smoke_ok, smoke_tail = _check_smoke_tests(bool(int(args.run_smoke_tests)))
    corpus_ok, corpus_meta = _check_historical_corpus_lock(
        LOCKED_CORPUS_DIR,
        denylist_globs=denylist_globs,
        min_pairs=LOCKED_CORPUS_MIN_JSON_SIDECAR_PAIRS,
    )

    checks = {
        "publish_root_exists": {"pass": publish_root_exists, "path": publish_root.as_posix()},
        "historical_corpus_lock": {"pass": corpus_ok, "details": corpus_meta},
        "export_manifest_integrity": {"pass": manifest_ok, "issues": manifest_findings[:50]},
        "whitelist_conformance": {
            "pass": len(whitelist_violations) == 0 and len(payload_files) > 0,
            "violations": whitelist_violations[:50],
        },
        "denylist_conformance": {"pass": len(denylist_hits) == 0, "hits": denylist_hits[:50]},
        "banned_pattern_scan": {"pass": len(banned_hits) == 0, "hits": banned_hits[:50]},
        "secret_scan": {"pass": len(secret_hits) == 0, "hits": secret_hits[:50]},
        "markdown_link_check": {"pass": len(markdown_hits) == 0, "hits": markdown_hits[:50]},
        "py_compile": {"pass": compile_ok, "tail": compile_tail},
        "unit_smoke_tests": {"pass": smoke_ok, "tail": smoke_tail},
    }
    blocking_failures = sum(1 for row in checks.values() if not bool(row.get("pass")))
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "publish_mode": args.publish_mode,
        "publish_root": publish_root.relative_to(ROOT).as_posix() if publish_root.is_absolute() else str(publish_root),
        "strict": bool(int(args.strict)),
        "publish_files_count": len(payload_files),
        "checks": checks,
        "blocking_failures": blocking_failures,
        "status": "PASS" if blocking_failures == 0 else "FAIL",
        "manifest_file_count": int(manifest_payload.get("file_count", 0)) if isinstance(manifest_payload, dict) else 0,
    }

    out_json = Path(args.out_json)
    if not out_json.is_absolute():
        out_json = ROOT / out_json
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    out_md = Path(args.out_md)
    if not out_md.is_absolute():
        out_md = ROOT / out_md
    out_md.write_text(_render_checklist(payload), encoding="utf-8")

    print(
        "ok: run_publish_release_audit "
        f"status={payload['status']} publish_files={len(payload_files)} blocking_failures={blocking_failures} "
        f"publish_root={payload['publish_root']}"
    )
    if bool(int(args.strict)) and blocking_failures > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
