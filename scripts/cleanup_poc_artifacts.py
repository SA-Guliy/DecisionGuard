#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar


SPAM_POLICY_PATH = ROOT / "configs/contracts/artifact_spam_prevention_v2.json"
GOLDEN_POLICY_PATH = ROOT / "configs/contracts/golden_pair_policy_v2.json"
INTEGRITY_POLICY_PATH = ROOT / "configs/contracts/cleanup_integrity_policy_v2.json"
CLEANUP_MANIFEST_CONTRACT_PATH = ROOT / "configs/contracts/cleanup_manifest_v1.json"


def _load_contract(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"Missing contract: {path}")
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        raise SystemExit(f"Contract integrity error: {reason}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Invalid contract JSON ({path}): {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid contract payload type: {path}")
    return payload


def _is_excluded(path: Path, exclude_globs: list[str]) -> bool:
    norm = str(path).replace("\\", "/")
    return any(path.match(g) or norm == g for g in exclude_globs)


def _collect_candidates(forbidden_globs: list[str], exclude_globs: list[str]) -> list[Path]:
    out: set[Path] = set()
    for pattern in forbidden_globs:
        if not str(pattern).strip():
            continue
        for hit in Path().glob(pattern):
            if not hit.is_file():
                continue
            rel = Path(str(hit).replace("\\", "/"))
            if str(rel).startswith("_PROJECT_TRASH/"):
                continue
            if _is_excluded(rel, exclude_globs):
                continue
            out.add(rel)
    return sorted(out)


def _sidecar_of(path: Path) -> Path:
    return Path(f"{path}.sha256")


def _validate_integrity(paths: list[Path], *, strict_integrity: bool) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for p in paths:
        if strict_integrity:
            ok, reason = verify_sha256_sidecar(p, required=True)
            if not ok:
                errors.append({"path": str(p), "reason": reason})
        else:
            ok, reason = verify_sha256_sidecar(p, required=False)
            if not ok:
                errors.append({"path": str(p), "reason": reason, "severity": "WARN"})
    return errors


def _move_to_trash(path: Path, *, trash_root: Path) -> tuple[str, str]:
    src = ROOT / path
    dst = ROOT / trash_root / path
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return str(path), str((trash_root / path).as_posix())


def _validate_cleanup_manifest(payload: dict[str, Any], contract: dict[str, Any]) -> None:
    required_top = contract.get("required_top_level", [])
    if isinstance(required_top, list):
        missing = [k for k in required_top if k not in payload]
        if missing:
            raise SystemExit(f"Cleanup manifest schema error: missing_top_level={','.join(missing)}")
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        raise SystemExit("Cleanup manifest schema error: summary must be object")
    req_sum = contract.get("required_summary_fields", [])
    if isinstance(req_sum, list):
        missing_sum = [k for k in req_sum if k not in summary]
        if missing_sum:
            raise SystemExit(f"Cleanup manifest schema error: missing_summary_fields={','.join(missing_sum)}")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("Cleanup manifest schema error: entries must be array")
    req_entry = contract.get("required_entry_fields", [])
    if isinstance(req_entry, list):
        for i, row in enumerate(entries):
            if not isinstance(row, dict):
                raise SystemExit(f"Cleanup manifest schema error: entry_not_object:{i}")
            missing_entry = [k for k in req_entry if k not in row]
            if missing_entry:
                raise SystemExit(
                    f"Cleanup manifest schema error: missing_entry_fields:{i}:{','.join(missing_entry)}"
                )


def _write_migration_artifacts(
    *,
    trash_root: Path,
    manifest_payload: dict[str, Any],
    entries: list[dict[str, Any]],
) -> tuple[Path, Path, Path]:
    trash_abs = ROOT / trash_root
    trash_abs.mkdir(parents=True, exist_ok=True)
    manifest_json_path = trash_abs / "MIGRATION_MANIFEST.json"
    manifest_md_path = trash_abs / "MIGRATION_MANIFEST.md"
    rollback_path = trash_abs / "rollback.sh"

    manifest_json_path.write_text(json.dumps(manifest_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(manifest_json_path)

    md_lines: list[str] = []
    md_lines.append("# MIGRATION MANIFEST")
    md_lines.append("")
    md_lines.append(f"- Generated at: `{manifest_payload.get('generated_at')}`")
    md_lines.append(f"- Applied: `{manifest_payload.get('applied')}`")
    md_lines.append(f"- Strict integrity: `{manifest_payload.get('strict_integrity')}`")
    summary = manifest_payload.get("summary", {}) if isinstance(manifest_payload.get("summary"), dict) else {}
    md_lines.append(f"- Candidate count: `{summary.get('candidate_count', 0)}`")
    md_lines.append(f"- Moved count: `{summary.get('moved_count', 0)}`")
    md_lines.append(f"- Passed: `{summary.get('passed')}`")
    md_lines.append("")
    md_lines.append("## Entries")
    md_lines.append("")
    if entries:
        for row in entries:
            md_lines.append(
                f"- `{row.get('artifact_type')}`: `{row.get('source_path')}` -> `{row.get('trash_path')}`"
            )
    else:
        md_lines.append("- No moved entries.")
    manifest_md_path.write_text("\n".join(md_lines), encoding="utf-8")

    rollback_lines: list[str] = []
    rollback_lines.append("#!/usr/bin/env bash")
    rollback_lines.append("set -euo pipefail")
    rollback_lines.append('ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"')
    rollback_lines.append('cd "$ROOT_DIR"')
    rollback_lines.append("")
    rollback_lines.append("# Auto-generated rollback script for cleanup_poc_artifacts.py")
    for row in reversed(entries):
        src = str(row.get("trash_path", "")).replace('"', '\\"')
        dst = str(row.get("source_path", "")).replace('"', '\\"')
        rollback_lines.append(f'mkdir -p "$(dirname \\"{dst}\\")"')
        rollback_lines.append(f'mv "{src}" "{dst}"')
    rollback_lines.append('echo "rollback: completed"')
    rollback_path.write_text("\n".join(rollback_lines) + "\n", encoding="utf-8")
    rollback_path.chmod(0o755)
    return manifest_json_path, manifest_md_path, rollback_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Cleanup Sprint-2 POC artifacts from batch working contour.")
    parser.add_argument(
        "--strict-integrity",
        type=int,
        default=-1,
        choices=[-1, 0, 1],
        help="1 = missing/invalid sidecar is blocking (default from contract), 0 = warn-only.",
    )
    parser.add_argument("--apply", type=int, default=1, choices=[0, 1], help="0 = dry-run; 1 = move files.")
    parser.add_argument("--trash-root", default="_PROJECT_TRASH")
    parser.add_argument("--out-json", default="data/agent_quality/cleanup_poc_artifacts_latest.json")
    args = parser.parse_args()

    spam_contract = _load_contract(SPAM_POLICY_PATH)
    golden_contract = _load_contract(GOLDEN_POLICY_PATH)
    integrity_contract = _load_contract(INTEGRITY_POLICY_PATH)
    cleanup_manifest_contract = _load_contract(CLEANUP_MANIFEST_CONTRACT_PATH)

    spam_policy = spam_contract.get("policy") if isinstance(spam_contract.get("policy"), dict) else {}
    golden_policy = golden_contract.get("policy") if isinstance(golden_contract.get("policy"), dict) else {}
    integrity_policy = integrity_contract.get("policy") if isinstance(integrity_contract.get("policy"), dict) else {}

    forbidden_globs = [str(x) for x in spam_policy.get("forbidden_globs", []) if str(x).strip()]
    excluded_globs = [str(x) for x in spam_policy.get("excluded_globs", []) if str(x).strip()]
    strict_default = bool(integrity_policy.get("strict_integrity_default", True))
    strict_integrity = strict_default if int(args.strict_integrity) < 0 else bool(int(args.strict_integrity))

    golden_card_glob = str(golden_policy.get("allowed_card_glob", "")).strip()
    golden_json_glob = str(golden_policy.get("allowed_json_glob", "")).strip()
    golden_max_json = int(golden_policy.get("max_allowed_json_files", 1) or 1)
    if golden_card_glob:
        excluded_globs.append(golden_card_glob)
    if golden_json_glob:
        excluded_globs.append(golden_json_glob)
        excluded_globs.append(f"{golden_json_glob}.sha256")

    golden_json_paths = [p for p in Path().glob(golden_json_glob) if p.is_file()] if golden_json_glob else []
    golden_policy_errors: list[dict[str, Any]] = []
    if len(golden_json_paths) > golden_max_json:
        golden_policy_errors.append(
            {
                "path": golden_json_glob,
                "reason": f"golden_pair_policy_violation:allowed={golden_max_json},found={len(golden_json_paths)}",
            }
        )

    candidates = _collect_candidates(forbidden_globs, excluded_globs)
    integrity_errors = _validate_integrity(candidates, strict_integrity=strict_integrity)
    blocking_integrity_errors = [
        e for e in integrity_errors if strict_integrity or str(e.get("severity", "")).upper() != "WARN"
    ]

    moved: list[dict[str, Any]] = []
    trash_root = Path(args.trash_root)
    if int(args.apply) == 1 and (blocking_integrity_errors or golden_policy_errors):
        # Fail-closed: do not mutate files if integrity/policy checks fail.
        pass
    elif int(args.apply) == 1:
        for rel in candidates:
            src_abs = ROOT / rel
            if not src_abs.exists():
                continue
            src, dst = _move_to_trash(rel, trash_root=trash_root)
            moved.append({"source_path": src, "trash_path": dst, "artifact_type": "artifact"})

            sidecar_rel = _sidecar_of(rel)
            sidecar_abs = ROOT / sidecar_rel
            if sidecar_abs.exists():
                s_src, s_dst = _move_to_trash(sidecar_rel, trash_root=trash_root)
                moved.append({"source_path": s_src, "trash_path": s_dst, "artifact_type": "sidecar"})

    passed = not blocking_integrity_errors and not golden_policy_errors
    if int(args.apply) == 0:
        passed = passed
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": "cleanup_manifest_v1",
        "strict_integrity": strict_integrity,
        "applied": bool(int(args.apply)),
        "trash_root": str(args.trash_root),
        "contracts": {
            "artifact_spam_prevention_v2": str(SPAM_POLICY_PATH),
            "golden_pair_policy_v2": str(GOLDEN_POLICY_PATH),
            "cleanup_integrity_policy_v2": str(INTEGRITY_POLICY_PATH),
            "cleanup_manifest_v1": str(CLEANUP_MANIFEST_CONTRACT_PATH),
        },
        "summary": {
            "candidate_count": len(candidates),
            "moved_count": len(moved),
            "integrity_error_count": len(integrity_errors),
            "golden_policy_error_count": len(golden_policy_errors),
            "passed": passed,
        },
        "forbidden_globs": forbidden_globs,
        "excluded_globs": excluded_globs,
        "entries": moved,
        "integrity_errors": integrity_errors[:100],
        "golden_policy_errors": golden_policy_errors[:100],
        "rollback_script": f"{args.trash_root}/rollback.sh",
        "notes": {
            "strict_integrity_default": strict_default,
            "apply_mode": int(args.apply),
            "candidates": [str(p) for p in candidates],
        },
    }
    _validate_cleanup_manifest(payload, cleanup_manifest_contract)

    manifest_json_path, manifest_md_path, rollback_path = _write_migration_artifacts(
        trash_root=trash_root,
        manifest_payload=payload,
        entries=moved,
    )

    out_path = Path(args.out_json)
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out_path)
    print(f"ok: cleanup_poc_artifacts passed={passed} candidates={len(candidates)} moved={len(moved)}")
    print(f"report_json={out_path}")
    print(f"report_sidecar={out_path}.sha256")
    print(f"migration_manifest_json={manifest_json_path}")
    print(f"migration_manifest_md={manifest_md_path}")
    print(f"rollback_script={rollback_path}")

    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
