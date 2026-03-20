#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.architecture_v3 import RECONCILIATION_POLICY_PATH, load_json_with_integrity
from src.runtime_controls import load_feature_state_contract
from src.security_utils import write_sha256_sidecar


def _write_json_with_sidecar(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Process provisional reconciliation job")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = str(args.run_id).strip()
    if not run_id:
        raise SystemExit("missing run_id")

    policy = load_json_with_integrity(RECONCILIATION_POLICY_PATH)
    if bool(policy.get("provisional_requires_reconciliation", False)) is not True:
        raise SystemExit("invalid reconciliation policy: provisional_requires_reconciliation=false")

    feature_state = load_feature_state_contract()
    reconciliation_runtime = str(feature_state.get("reconciliation_runtime", "NOT_IMPLEMENTED")).upper()

    job_path = Path(f"data/reconciliation/{run_id}_reconciliation_job.json")
    job = load_json_with_integrity(job_path)
    if bool(job.get("needs_cloud_reconciliation", False)) is not True:
        raise SystemExit("reconciliation job invalid: needs_cloud_reconciliation must be true")

    if reconciliation_runtime == "NOT_IMPLEMENTED":
        result_status = "DEFERRED_NOT_IMPLEMENTED"
        notes = [
            "Feature state keeps reconciliation runtime disabled.",
            "Cloud replay is deferred; keep decision ceiling at HOLD_NEED_DATA.",
        ]
    else:
        result_status = "QUEUED_FOR_CLOUD_REPLAY"
        notes = [
            "Cloud replay queue created.",
            "Auto decision mutation is forbidden until explicit human approval.",
        ]

    result_payload = {
        "version": "reconciliation_worker_result_v1",
        "run_id": run_id,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "status": result_status,
        "job_ref": f"artifact:{job_path}",
        "reconciliation_runtime": reconciliation_runtime,
        "needs_cloud_reconciliation": True,
        "fallback_agents": [str(x) for x in job.get("fallback_agents", []) if str(x).strip()],
        "decision_ceiling_applied": "HOLD_NEED_DATA",
        "auto_decision_change_applied": False,
        "human_approval_required": True,
        "notes": notes,
    }
    result_path = Path(f"data/reconciliation/{run_id}_reconciliation_result.json")
    _write_json_with_sidecar(result_path, result_payload)

    job["status"] = "PROCESSED"
    job["processed_at"] = result_payload["processed_at"]
    job["result_ref"] = f"artifact:{result_path}"
    _write_json_with_sidecar(job_path, job)

    print(
        "ok: reconciliation_worker "
        f"run_id={run_id} status={result_status} result={result_path}"
    )


if __name__ == "__main__":
    main()
