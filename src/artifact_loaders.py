from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from src.paths import (
    captain_report_json,
    commander_report_json,
    doctor_report_json,
    evaluator_report_json,
    narrative_report_json,
    ops_report_dir,
)
from src.security_utils import resolve_manifest_entry_path, verify_json_manifest, verify_sha256_sidecar


class ArtifactIntegrityError(RuntimeError):
    pass


def _integrity_mode() -> str:
    mode = str(os.getenv("DS_INTEGRITY_MODE", "")).strip().lower()
    if mode in {"required", "best_effort"}:
        return mode
    return "best_effort"


def _load_manifest_entries(manifest_path: Path) -> set[str]:
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ArtifactIntegrityError(f"invalid_json_manifest:{manifest_path}") from exc
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise ArtifactIntegrityError(f"invalid_json_manifest:{manifest_path}")
    entries: set[str] = set()
    for row in artifacts:
        if not isinstance(row, dict):
            continue
        raw_path = str(row.get("path", "")).strip()
        if not raw_path:
            continue
        entries.add(str(resolve_manifest_entry_path(manifest_path, raw_path).resolve()))
    return entries


def _verify_run_manifest(run_id: str, *, require_manifest: bool) -> set[str] | None:
    manifest_path = ops_report_dir(run_id) / "artifact_manifest.json"
    ok, reasons = verify_json_manifest(
        manifest_path,
        require_manifest=require_manifest,
        verify_manifest_sidecar=True,
    )
    if not ok:
        raise ArtifactIntegrityError(";".join(reasons[:3]) or "json_manifest_invalid")
    if not manifest_path.exists():
        return None
    entries = _load_manifest_entries(manifest_path)
    return entries


def load_json_optional(
    path: Path,
    *,
    require_integrity: bool = False,
    manifest_entries: set[str] | None = None,
    require_manifest_entry: bool = False,
) -> dict[str, Any] | None:
    if not path.exists():
        if require_integrity:
            raise ArtifactIntegrityError(f"missing_artifact:{path}")
        return None
    resolved = str(path.resolve())
    if require_manifest_entry and manifest_entries is not None and resolved not in manifest_entries:
        raise ArtifactIntegrityError(f"missing_manifest_entry:{path}")
    ok, reason = verify_sha256_sidecar(path, required=require_integrity)
    if not ok:
        raise ArtifactIntegrityError(reason)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        if require_integrity:
            raise ArtifactIntegrityError(f"invalid_json_payload:{path}") from exc
        return None


def load_core_agent_artifacts(run_id: str) -> dict[str, dict[str, Any]]:
    required_mode = _integrity_mode() == "required"
    manifest_entries = _verify_run_manifest(run_id, require_manifest=required_mode)
    return {
        "captain": load_json_optional(
            captain_report_json(run_id),
            require_integrity=True,
            manifest_entries=manifest_entries,
            require_manifest_entry=manifest_entries is not None,
        )
        or {},
        "doctor": load_json_optional(
            doctor_report_json(run_id),
            require_integrity=True,
            manifest_entries=manifest_entries,
            require_manifest_entry=manifest_entries is not None,
        )
        or {},
        "evaluator": load_json_optional(
            evaluator_report_json(run_id),
            require_integrity=True,
            manifest_entries=manifest_entries,
            require_manifest_entry=manifest_entries is not None,
        )
        or {},
        "commander": load_json_optional(
            commander_report_json(run_id),
            require_integrity=True,
            manifest_entries=manifest_entries,
            require_manifest_entry=manifest_entries is not None,
        )
        or {},
    }


def load_agent_artifacts_with_narrative(run_id: str) -> dict[str, dict[str, Any]]:
    out = load_core_agent_artifacts(run_id)
    out["narrative"] = load_json_optional(narrative_report_json(run_id), require_integrity=False) or {}
    return out
