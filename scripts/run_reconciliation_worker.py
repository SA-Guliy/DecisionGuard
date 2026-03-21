#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.architecture_v3 import (
    RECONCILIATION_POLICY_PATH,
    captain_artifact_path,
    context_frame_path,
    decision_outcomes_ledger_path,
    load_json_with_integrity,
)
from src.security_utils import write_sha256_sidecar


def _write_json_with_sidecar(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(path)


def _append_audit_event(payload: dict[str, Any]) -> None:
    audit_path = Path("data/security/obfuscation_maps/audit_log.jsonl")
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _find_pending_runs(*, run_id: str, batch_id: str, max_pending_hours: int) -> list[Path]:
    now = datetime.now(timezone.utc)
    reconciliation_root = Path("data/reconciliation")
    if not reconciliation_root.exists():
        return []
    candidates: list[Path] = []
    if run_id:
        candidates = [reconciliation_root / f"{run_id}_reconciliation_job.json"]
    elif batch_id:
        candidates = sorted(reconciliation_root.glob(f"{batch_id}*_reconciliation_job.json"))
    else:
        candidates = sorted(reconciliation_root.glob("*_reconciliation_job.json"))

    out: list[Path] = []
    for path in candidates:
        if not path.exists():
            continue
        job = load_json_with_integrity(path)
        if str(job.get("status", "")).upper() != "PENDING":
            continue
        generated_at = _parse_ts(job.get("generated_at"))
        if generated_at is None:
            continue
        age_hours = max(0.0, (now - generated_at).total_seconds() / 3600.0)
        if age_hours > float(max_pending_hours):
            continue
        out.append(path)
    return out


def _load_run_context(run_id: str, job_path: Path) -> dict[str, Any]:
    job = load_json_with_integrity(job_path)
    if bool(job.get("needs_cloud_reconciliation", False)) is not True:
        raise RuntimeError("reconciliation_job_invalid:needs_cloud_reconciliation_false")

    context = load_json_with_integrity(context_frame_path(run_id))
    captain = load_json_with_integrity(captain_artifact_path(run_id))
    doctor = load_json_with_integrity(Path(f"data/agent_reports/{run_id}_doctor_variance.json"))
    commander = load_json_with_integrity(Path(f"data/agent_reports/{run_id}_commander_priority.json"))

    # Integrity + scope lock for reconciliation ledger source.
    ledger = load_json_with_integrity(decision_outcomes_ledger_path(run_id))

    return {
        "job": job,
        "context_frame": context,
        "captain": captain,
        "doctor": doctor,
        "commander": commander,
        "decision_outcomes_ledger": ledger,
    }


def _run_cloud_reconciliation(*, run_id: str, backend: str, dry_run: bool) -> dict[str, Any]:
    backend_norm = str(backend or "").strip().lower()
    if backend_norm != "groq":
        raise RuntimeError("reconciliation_backend_not_allowed")

    commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
    provisional = load_json_with_integrity(commander_path)
    provisional_decision = str(
        provisional.get("normalized_decision", provisional.get("decision", "HOLD_NEED_DATA"))
    ).upper()

    if dry_run:
        return {
            "mode": "dry_run",
            "cloud_decision": provisional_decision,
            "doctor_ref": f"artifact:data/agent_reports/{run_id}_doctor_variance.json#",
            "commander_ref": f"artifact:{commander_path}#",
        }

    env = dict(os.environ)
    env["LLM_ALLOW_REMOTE"] = "1"
    env["DS_FORCE_NO_LOCAL_MOCK"] = "1"

    doctor_cmd = [
        "python3",
        "scripts/run_doctor_variance.py",
        "--run-id",
        run_id,
        "--backend",
        "groq",
    ]
    commander_cmd = [
        "python3",
        "scripts/run_commander_priority.py",
        "--run-id",
        run_id,
        "--backend",
        "groq",
        "--enable-hypothesis-review-v1",
        "1",
    ]

    for cmd in (doctor_cmd, commander_cmd):
        proc = subprocess.run(cmd, text=True, capture_output=True, env=env)
        if proc.returncode != 0:
            raise RuntimeError(
                f"reconciliation_cloud_step_failed:{' '.join(cmd)}:{proc.stderr.strip()[:180]}"
            )

    doctor = load_json_with_integrity(Path(f"data/agent_reports/{run_id}_doctor_variance.json"))
    commander = load_json_with_integrity(commander_path)

    if bool(doctor.get("provisional_local_fallback", False)) or bool(doctor.get("needs_cloud_reconciliation", False)):
        raise RuntimeError("reconciliation_cloud_fallback_forbidden:doctor")
    if bool(commander.get("provisional_local_fallback", False)) or bool(commander.get("needs_cloud_reconciliation", False)):
        raise RuntimeError("reconciliation_cloud_fallback_forbidden:commander")

    cloud_decision = str(commander.get("normalized_decision", commander.get("decision", "HOLD_NEED_DATA"))).upper()
    return {
        "mode": "cloud_replay",
        "cloud_decision": cloud_decision,
        "doctor_ref": f"artifact:data/agent_reports/{run_id}_doctor_variance.json#",
        "commander_ref": f"artifact:{commander_path}#",
    }


def _compare_and_seal(
    *,
    run_id: str,
    job_path: Path,
    job_payload: dict[str, Any],
    provisional_decision: str,
    cloud_result: dict[str, Any],
) -> dict[str, Any]:
    cloud_decision = str(cloud_result.get("cloud_decision", "HOLD_NEED_DATA")).upper()
    changed = provisional_decision != cloud_decision
    status = "updated" if changed else "accepted"
    sealed_at = datetime.now(timezone.utc).isoformat()

    result_payload: dict[str, Any] = {
        "version": "reconciliation_worker_result_v2",
        "run_id": run_id,
        "batch_id": str(job_payload.get("batch_id", "") or ""),
        "processed_at": sealed_at,
        "status": status,
        "decision_ceiling_applied": "HOLD_NEED_DATA",
        "auto_decision_change_applied": False,
        "human_approval_required": True,
        "job_ref": f"artifact:{job_path}#",
        "reconciliation": {
            "status": status,
            "provisional_decision": provisional_decision,
            "cloud_decision": cloud_decision,
            "delta": {
                "decision_changed": changed,
                "from": provisional_decision,
                "to": cloud_decision,
            },
        },
        "cloud_result_ref": {
            "mode": str(cloud_result.get("mode", "")),
            "doctor_ref": str(cloud_result.get("doctor_ref", "")),
            "commander_ref": str(cloud_result.get("commander_ref", "")),
        },
    }
    result_path = Path(f"data/reconciliation/{run_id}_reconciliation_result.json")
    _write_json_with_sidecar(result_path, result_payload)

    job_payload["status"] = "PROCESSED"
    job_payload["processed_at"] = sealed_at
    job_payload["result_ref"] = f"artifact:{result_path}#"
    _write_json_with_sidecar(job_path, job_payload)

    _append_audit_event(
        {
            "event": "reconciliation_worker_seal",
            "run_id": run_id,
            "status": status,
            "decision_changed": changed,
            "generated_at": sealed_at,
            "job_ref": f"artifact:{job_path}#",
            "result_ref": f"artifact:{result_path}#",
        }
    )

    return {
        "run_id": run_id,
        "status": status,
        "provisional_decision": provisional_decision,
        "cloud_decision": cloud_decision,
        "result_path": str(result_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Process provisional reconciliation jobs (strict fail-closed)")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--batch-id", default="")
    parser.add_argument("--backend", default="groq")
    parser.add_argument("--dry-run", type=int, default=0, choices=(0, 1))
    parser.add_argument("--max-pending-hours", type=int, default=24)
    parser.add_argument("--out-json", default="")
    args = parser.parse_args()

    run_id = str(args.run_id or "").strip()
    batch_id = str(args.batch_id or "").strip()
    if not run_id and not batch_id:
        raise SystemExit("missing selector: provide --run-id or --batch-id")

    policy = load_json_with_integrity(RECONCILIATION_POLICY_PATH)
    if bool(policy.get("provisional_requires_reconciliation", False)) is not True:
        raise SystemExit("invalid reconciliation policy: provisional_requires_reconciliation=false")

    pending = _find_pending_runs(
        run_id=run_id,
        batch_id=batch_id,
        max_pending_hours=int(args.max_pending_hours),
    )
    if not pending:
        raise SystemExit("no_pending_reconciliation_jobs")

    results: list[dict[str, Any]] = []
    for job_path in pending:
        job_payload = load_json_with_integrity(job_path)
        rid = str(job_payload.get("run_id", "")).strip()
        if not rid:
            raise SystemExit(f"invalid_reconciliation_job_missing_run_id:{job_path}")

        context = _load_run_context(rid, job_path)
        provisional_decision = str(
            (context.get("commander") or {}).get(
                "normalized_decision",
                (context.get("commander") or {}).get("decision", "HOLD_NEED_DATA"),
            )
        ).upper()

        cloud_result = _run_cloud_reconciliation(
            run_id=rid,
            backend=str(args.backend),
            dry_run=bool(int(args.dry_run)),
        )
        sealed = _compare_and_seal(
            run_id=rid,
            job_path=job_path,
            job_payload=job_payload,
            provisional_decision=provisional_decision,
            cloud_result=cloud_result,
        )
        results.append(sealed)

    out_json = Path(str(args.out_json).strip()) if str(args.out_json).strip() else Path(
        f"data/reconciliation/{run_id or batch_id}_reconciliation_worker.json"
    )
    summary = {
        "version": "reconciliation_worker_summary_v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "selector": {"run_id": run_id, "batch_id": batch_id},
        "backend": str(args.backend),
        "dry_run": bool(int(args.dry_run)),
        "max_pending_hours": int(args.max_pending_hours),
        "processed_jobs": len(results),
        "results": results,
    }
    _write_json_with_sidecar(out_json, summary)
    print(f"ok: reconciliation_worker processed={len(results)} summary={out_json}")


if __name__ == "__main__":
    main()
