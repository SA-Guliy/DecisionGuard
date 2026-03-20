#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import shutil
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import write_sha256_sidecar


DEMO_ROOT = ROOT / "examples/investor_demo"
HUMAN_DIR = DEMO_ROOT / "reports_for_humans"
AGENT_DIR = DEMO_ROOT / "reports_for_agents"
SYNTH_DIR = DEMO_ROOT / "synthetic_data"
DEMO_SOURCE_ROOT = ROOT / "demo_sources/investor_demo"

UNIX_ABS_RE = re.compile(r"/Users/[^\n`\"'<>]+")
WIN_ABS_RE = re.compile(r"[A-Za-z]:\\\\[^\s`\"'<>]+")
FILE_URI_RE = re.compile(r"file://[^\s`\"'<>]+")
TOKEN_RE = re.compile(r"\b(?:gsk|sk)-[A-Za-z0-9_\-]{8,}\b")
SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|access[_-]?token|refresh[_-]?token|bearer[_-]?token|password|secret|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)
SECRET_FILE_RE = re.compile(r"\.groq_secrets\b")
SAFE_NON_SECRET_KEYS = {
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "token_count",
    "ttl",
    "ttl_hours",
}

REDACTED_LOCAL = "<REDACTED_LOCAL_PATH>"
REDACTED_FILE = "<REDACTED_SECRET_FILE>"
REDACTED_TOKEN = "<REDACTED_TOKEN>"


def _sanitize_text(text: str) -> str:
    out = str(text or "")
    out = UNIX_ABS_RE.sub(REDACTED_LOCAL, out)
    out = WIN_ABS_RE.sub(REDACTED_LOCAL, out)
    out = FILE_URI_RE.sub(REDACTED_LOCAL, out)
    out = SECRET_FILE_RE.sub(REDACTED_FILE, out)
    out = TOKEN_RE.sub(REDACTED_TOKEN, out)
    return out


def _sanitize_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for key, value in obj.items():
            k = str(key)
            k_lower = k.lower()
            if k.endswith("_secrets_source"):
                continue
            if k in {"sanitization_kms_source"}:
                continue
            # Keep known non-secret telemetry counters/TTL fields untouched.
            if k_lower in SAFE_NON_SECRET_KEYS or k_lower.endswith("_ttl"):
                cleaned[k] = _sanitize_obj(value)
                continue
            if SECRET_KEY_RE.search(k):
                if isinstance(value, str):
                    cleaned[k] = REDACTED_TOKEN
                elif isinstance(value, list):
                    cleaned[k] = [REDACTED_TOKEN for _ in value]
                else:
                    cleaned[k] = value
                continue
            cleaned[k] = _sanitize_obj(value)
        return cleaned
    if isinstance(obj, list):
        return [_sanitize_obj(x) for x in obj]
    if isinstance(obj, str):
        return _sanitize_text(obj)
    return obj


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"invalid_json_payload:{path}")
    return payload


def _write_json(path: Path, payload: dict[str, Any], *, apply: bool) -> None:
    if not apply:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(path)


def _write_text(path: Path, text: str, *, apply: bool) -> None:
    if not apply:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    write_sha256_sidecar(path)


def _build_cost_ledger(summary: dict[str, Any]) -> dict[str, Any]:
    completed = int(summary.get("completed_cases", 0) or 0)
    total_cost = float(summary.get("total_cost_usd_estimate", 0.0) or 0.0)
    return {
        "version": "investor_demo_cost_ledger.v1",
        "batch_id": str(summary.get("batch_id", "mass_test_003")),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "data/batch_eval/mass_test_003_summary.json",
        "total_cost_usd_estimate": round(total_cost, 6),
        "completed_cases": completed,
        "avg_cost_per_case_usd": round(total_cost / completed, 6) if completed > 0 else None,
        "notes": "Sanitized demo ledger. Runtime raw cost files are intentionally excluded from public pack.",
    }


def _build_reconciliation_summary(summary: dict[str, Any], sample_run: dict[str, Any]) -> dict[str, Any]:
    runtime_flags = sample_run.get("runtime_flags", {}) if isinstance(sample_run.get("runtime_flags"), dict) else {}
    return {
        "version": "investor_demo_reconciliation_summary.v1",
        "batch_id": str(summary.get("batch_id", "mass_test_003")),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "provisional_completed_cases": int(summary.get("provisional_completed_cases", 0) or 0),
        "needs_cloud_reconciliation": bool(sample_run.get("needs_cloud_reconciliation", False)),
        "reconciliation_status": str(sample_run.get("reconciliation_status", "")).strip()
        if isinstance(sample_run.get("reconciliation_status"), str)
        else "",
        "cloud_path_used": bool(
            (sample_run.get("captain_usage", {}) if isinstance(sample_run.get("captain_usage"), dict) else {}).get(
                "cloud_path", False
            )
            or (sample_run.get("doctor_usage", {}) if isinstance(sample_run.get("doctor_usage"), dict) else {}).get(
                "cloud_path", False
            )
            or (sample_run.get("commander_usage", {}) if isinstance(sample_run.get("commander_usage"), dict) else {}).get(
                "cloud_path", False
            )
        ),
        "provisional_local_fallback": bool(runtime_flags.get("provisional_local_fallback", False)),
        "notes": "If no reconciliation events exist in demo scope, this file remains informational.",
    }


def _build_synthetic_sample(history_sot: dict[str, Any], source_ref: str) -> dict[str, Any]:
    rows = history_sot.get("reports")
    if not isinstance(rows, list):
        rows = history_sot.get("experiments")
    if not isinstance(rows, list):
        rows = []
    sample = rows[:3]
    return {
        "version": "investor_demo_synthetic_sample.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source_ref,
        "sample_count": len(sample),
        "sample": sample,
    }


def _resolve_demo_sources() -> tuple[dict[str, Path], str]:
    demo_candidates = {
        "batch_summary": DEMO_SOURCE_ROOT / "batch_summary.json",
        "decision_card": DEMO_SOURCE_ROOT / "decision_card.md",
        "agent_run_sample": DEMO_SOURCE_ROOT / "agent_run_sample.json",
        "batch_consolidated_report": DEMO_SOURCE_ROOT / "batch_consolidated_report.md",
        "executive_roi_scorecard": DEMO_SOURCE_ROOT / "executive_roi_scorecard.md",
        "history_sot": DEMO_SOURCE_ROOT / "history_sot_v1.json",
    }
    if all(p.exists() for p in demo_candidates.values()):
        return demo_candidates, "demo_sources"
    runtime_candidates = {
        "batch_summary": ROOT / "data/batch_eval/mass_test_003_summary.json",
        "decision_card": ROOT / "reports/L1_ops/demo_golden_example/POC_DECISION_CARD_SPRINT2.md",
        "agent_run_sample": ROOT / "reports/L1_ops/demo_golden_example/mass_test_003_risk_007_poc_sprint2.json",
        "batch_consolidated_report": ROOT / "data/reports/BATCH_CONSOLIDATED_REPORT.md",
        "executive_roi_scorecard": ROOT / "data/reports/EXECUTIVE_ROI_SCORECARD.md",
        "history_sot": ROOT / "data/poc/history_sot_v1.json",
    }
    return runtime_candidates, "runtime_fallback"


def _build_demo_guide() -> str:
    return (
        "# Investor Demo Guide\n\n"
        "This folder is the single Source of Truth for public demo artifacts.\n\n"
        "## Layout\n"
        "- `reports_for_humans/decision_card.md`\n"
        "- `reports_for_humans/batch_consolidated_report.md`\n"
        "- `reports_for_humans/executive_roi_scorecard.md`\n"
        "- `reports_for_agents/batch_summary.json`\n"
        "- `reports_for_agents/agent_run_sample.json`\n"
        "- `reports_for_agents/cost_ledger.json`\n"
        "- `reports_for_agents/reconciliation_summary.json`\n"
        "- `synthetic_data/synthetic_dataset_sample.json`\n\n"
        "## Release Policy\n"
        "- publish_mode is `staging_only`.\n"
        "- Runtime artifacts outside `examples/investor_demo/` are not public demo sources.\n"
        "- Artifacts are sanitized: local absolute paths, secret-source fields, and machine-specific refs are removed.\n"
        "- Safe key allowlist is preserved in sanitization: `prompt_tokens`, `completion_tokens`, `total_tokens`, "
        "`token_count`, `ttl`, `ttl_hours`, and `*_ttl` fields.\n"
        "- Markdown artifact integrity is enforced with per-file `.sha256` sidecars and export-manifest hash chain.\n"
    )


def _load_globs(path: Path) -> list[str]:
    if not path.exists():
        raise SystemExit(f"missing_publish_control_file:{path}")
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def _match_any(rel: str, globs: list[str]) -> bool:
    norm = rel.replace("\\", "/")
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


def _plan_publish_payload_files(
    whitelist_globs: list[str],
    denylist_globs: list[str],
    publish_root_rel: str,
) -> list[str]:
    files: list[str] = []
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        if ".git" in p.parts:
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith(f"{publish_root_rel}/"):
            continue
        if _match_any(rel, whitelist_globs) and not _match_any(rel, denylist_globs):
            files.append(rel)
    return sorted(set(files))


def _write_export_manifest(
    publish_root: Path,
    payload_files: list[str],
    *,
    apply: bool,
    publish_mode: str,
) -> tuple[Path, Path]:
    manifest_json = publish_root / "PUBLISH_EXPORT_MANIFEST.json"
    manifest_md = publish_root / "PUBLISH_EXPORT_MANIFEST.md"
    entries = []
    for rel in payload_files:
        path = publish_root / rel
        entries.append({"path": rel, "sha256": _sha256_file(path), "size_bytes": path.stat().st_size})
    payload = {
        "version": "publish_export_manifest.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "publish_mode": publish_mode,
        "publish_root": publish_root.name,
        "file_count": len(entries),
        "files": entries,
    }
    md_lines = [
        "# PUBLISH EXPORT MANIFEST",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Publish mode: `{publish_mode}`",
        f"- Publish root: `{publish_root.name}`",
        f"- File count: `{len(entries)}`",
        "",
        "## Files",
        "",
    ]
    md_lines.extend([f"- `{row['path']}` `{row['sha256']}`" for row in entries[:200]])
    if len(entries) > 200:
        md_lines.append(f"- ... truncated (`{len(entries)-200}` more)")
    if apply:
        manifest_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(manifest_json)
        manifest_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return manifest_json, manifest_md


def main() -> None:
    parser = argparse.ArgumentParser(description="Build sanitized investor demo and staging-only publish root.")
    parser.add_argument("--publish-mode", default="staging_only", choices=["staging_only"])
    parser.add_argument("--apply", type=int, default=1, choices=[0, 1], help="0=dry-run, 1=write files")
    parser.add_argument("--publish-root", default="github_publish", help="Physical staging-only publish root.")
    parser.add_argument("--whitelist", default="PUBLISH_WHITELIST.txt")
    parser.add_argument("--denylist", default="PUBLISH_DENYLIST.txt")
    parser.add_argument("--out-json", default="_PROJECT_TRASH/publish_staging_report.json")
    args = parser.parse_args()

    apply = bool(int(args.apply))
    publish_root = ROOT / args.publish_root
    publish_root_rel = Path(args.publish_root).as_posix().strip("/")
    whitelist_globs = _load_globs(ROOT / args.whitelist)
    denylist_globs = _load_globs(ROOT / args.denylist)

    sources, source_profile = _resolve_demo_sources()
    src_batch_summary = sources["batch_summary"]
    src_decision_card = sources["decision_card"]
    src_run_sample = sources["agent_run_sample"]
    src_consolidated = sources["batch_consolidated_report"]
    src_roi = sources["executive_roi_scorecard"]
    src_history = sources["history_sot"]

    required = [
        src_batch_summary,
        src_decision_card,
        src_run_sample,
        src_consolidated,
        src_roi,
        src_history,
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise SystemExit(f"missing_required_demo_sources:{','.join(missing)}")

    batch_summary = _sanitize_obj(_load_json(src_batch_summary))
    run_sample = _sanitize_obj(_load_json(src_run_sample))
    history_sot = _sanitize_obj(_load_json(src_history))

    batch_consolidated_md = _sanitize_text(src_consolidated.read_text(encoding="utf-8"))
    executive_roi_md = _sanitize_text(src_roi.read_text(encoding="utf-8"))
    decision_card_md = _sanitize_text(src_decision_card.read_text(encoding="utf-8"))

    cost_ledger = _build_cost_ledger(batch_summary)
    reconciliation_summary = _build_reconciliation_summary(batch_summary, run_sample)
    synthetic_sample = _build_synthetic_sample(history_sot, str(src_history.relative_to(ROOT)))
    if int(synthetic_sample.get("sample_count", 0) or 0) <= 0:
        raise SystemExit("invalid_synthetic_sample:sample_count_zero")

    demo_outputs = [
        HUMAN_DIR / "decision_card.md",
        HUMAN_DIR / "batch_consolidated_report.md",
        HUMAN_DIR / "executive_roi_scorecard.md",
        AGENT_DIR / "batch_summary.json",
        AGENT_DIR / "agent_run_sample.json",
        AGENT_DIR / "cost_ledger.json",
        AGENT_DIR / "reconciliation_summary.json",
        SYNTH_DIR / "synthetic_dataset_sample.json",
        DEMO_ROOT / "DEMO_GUIDE.md",
        DEMO_ROOT / "DEMO_MANIFEST.json",
    ]

    if apply:
        for path in (HUMAN_DIR, AGENT_DIR, SYNTH_DIR):
            path.mkdir(parents=True, exist_ok=True)

    _write_text(HUMAN_DIR / "decision_card.md", decision_card_md, apply=apply)
    _write_text(HUMAN_DIR / "batch_consolidated_report.md", batch_consolidated_md, apply=apply)
    _write_text(HUMAN_DIR / "executive_roi_scorecard.md", executive_roi_md, apply=apply)
    _write_json(AGENT_DIR / "batch_summary.json", batch_summary, apply=apply)
    _write_json(AGENT_DIR / "agent_run_sample.json", run_sample, apply=apply)
    _write_json(AGENT_DIR / "cost_ledger.json", cost_ledger, apply=apply)
    _write_json(AGENT_DIR / "reconciliation_summary.json", reconciliation_summary, apply=apply)
    _write_json(SYNTH_DIR / "synthetic_dataset_sample.json", synthetic_sample, apply=apply)
    _write_text(DEMO_ROOT / "DEMO_GUIDE.md", _build_demo_guide(), apply=apply)

    demo_manifest = {
        "version": "investor_demo_manifest.v1",
        "publish_mode": args.publish_mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "apply": apply,
        "sources": {
            "decision_card": str(src_decision_card.relative_to(ROOT)),
            "batch_consolidated_report": str(src_consolidated.relative_to(ROOT)),
            "executive_roi_scorecard": str(src_roi.relative_to(ROOT)),
            "batch_summary": str(src_batch_summary.relative_to(ROOT)),
            "agent_run_sample": str(src_run_sample.relative_to(ROOT)),
            "synthetic_source": str(src_history.relative_to(ROOT)),
            "source_profile": source_profile,
        },
        "outputs": [str(p.relative_to(ROOT)) for p in demo_outputs],
        "sanitization": {
            "removed_fields": ["secret_source_fields", "kms_source_field"],
            "redacted_patterns": [
                "absolute_local_paths_unix",
                "absolute_local_paths_windows",
                "file_uri_refs",
                "secret_file_refs",
                "token_like_values",
            ],
        },
    }
    _write_json(DEMO_ROOT / "DEMO_MANIFEST.json", demo_manifest, apply=apply)

    payload_files = _plan_publish_payload_files(whitelist_globs, denylist_globs, publish_root_rel)
    manifest_json = publish_root / "PUBLISH_EXPORT_MANIFEST.json"
    manifest_md = publish_root / "PUBLISH_EXPORT_MANIFEST.md"

    if apply:
        if publish_root.exists():
            shutil.rmtree(publish_root)
        publish_root.mkdir(parents=True, exist_ok=True)
        for rel in payload_files:
            src = ROOT / rel
            dst = publish_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        manifest_json, manifest_md = _write_export_manifest(
            publish_root,
            payload_files,
            apply=True,
            publish_mode=args.publish_mode,
        )

    out_path = Path(args.out_json)
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "publish_mode": args.publish_mode,
        "apply": apply,
        "publish_root": publish_root_rel,
        "source_profile": source_profile,
        "missing_sources": missing,
        "demo_outputs": [str(p.relative_to(ROOT)) for p in demo_outputs],
        "publish_payload_file_count": len(payload_files),
        "publish_payload_files_sample": payload_files[:50],
        "publish_export_manifest_json": str(manifest_json.relative_to(ROOT))
        if apply and manifest_json.exists()
        else str(manifest_json.relative_to(ROOT)),
        "publish_export_manifest_md": str(manifest_md.relative_to(ROOT))
        if apply and manifest_md.exists()
        else str(manifest_md.relative_to(ROOT)),
        "status": "PASS" if (not missing and len(payload_files) > 0) else "FAIL",
    }
    out_path.write_text(json.dumps(out_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out_path)

    print(
        f"ok: build_investor_demo_staging status={out_payload['status']} "
        f"apply={int(apply)} demo_outputs={len(demo_outputs)} publish_payload_files={len(payload_files)} "
        f"publish_root={publish_root_rel} report={out_path}"
    )
    if missing or not payload_files:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
