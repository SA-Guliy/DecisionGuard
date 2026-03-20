#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.architecture_v3 import (
    context_frame_path,
    load_json_optional_with_integrity,
    save_json_with_sidecar,
    write_gate_result,
)


def _pick_current_experiment_id(run_id: str, metrics_snapshot: dict[str, Any]) -> str:
    run_cfg = metrics_snapshot.get("run_config", {}) if isinstance(metrics_snapshot.get("run_config"), dict) else {}
    exp_id = str(run_cfg.get("experiment_id", "") or "").strip()
    if exp_id:
        return exp_id
    candidates = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab.json"))
    if candidates:
        return candidates[0].stem.replace(f"{run_id}_", "").replace("_ab", "")
    return ""


def _pick_next_experiment_id(doctor: dict[str, Any], commander: dict[str, Any]) -> str:
    next_exp = commander.get("next_experiment") if isinstance(commander.get("next_experiment"), dict) else {}
    for key in ("name", "experiment_id"):
        val = str(next_exp.get(key, "") or "").strip()
        if val:
            return val
    ab_plan = doctor.get("ab_plan") if isinstance(doctor.get("ab_plan"), list) else []
    if ab_plan and isinstance(ab_plan[0], dict):
        first = ab_plan[0]
        for key in ("name", "experiment_id"):
            val = str(first.get(key, "") or "").strip()
            if val:
                return val
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Build context_frame_v1 artifact")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    status = "PASS"
    error_code = "NONE"
    blocked_by: list[str] = []
    required_actions: list[str] = []
    load_errors: dict[str, str] = {}
    metrics_snapshot: dict[str, Any] = {}
    doctor: dict[str, Any] = {}
    commander: dict[str, Any] = {}

    try:
        metrics_snapshot = load_json_optional_with_integrity(
            Path(f"data/metrics_snapshots/{run_id}.json"),
            required=True,
        ) or {}
    except Exception as exc:
        status = "FAIL"
        error_code = "CONTEXT_CONFLICT"
        blocked_by.append("missing_or_invalid_metrics_snapshot")
        required_actions.append("generate_metrics_snapshot_with_integrity")
        load_errors["metrics_snapshot"] = str(exc)
    try:
        doctor = load_json_optional_with_integrity(
            Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
            required=False,
        ) or {}
    except Exception as exc:
        status = "FAIL"
        error_code = "CONTEXT_CONFLICT"
        blocked_by.append("invalid_optional_doctor_artifact")
        required_actions.append("remove_or_regenerate_doctor_artifact_with_integrity")
        load_errors["doctor"] = str(exc)
    try:
        # Commander is optional at this point of pipeline by design.
        commander = load_json_optional_with_integrity(
            Path(f"data/agent_reports/{run_id}_commander_priority.json"),
            required=False,
        ) or {}
    except Exception as exc:
        status = "FAIL"
        error_code = "CONTEXT_CONFLICT"
        blocked_by.append("invalid_optional_commander_artifact")
        required_actions.append("remove_or_regenerate_commander_artifact_with_integrity")
        load_errors["commander"] = str(exc)

    current_exp_id = _pick_current_experiment_id(run_id, metrics_snapshot)
    next_exp_id = _pick_next_experiment_id(doctor, commander)
    if current_exp_id and next_exp_id and current_exp_id == next_exp_id:
        status = "FAIL"
        error_code = "CONTEXT_CONFLICT"
        blocked_by.append("current_ab_and_next_experiment_reused_same_experiment_id")
        required_actions.append("assign_distinct_experiment_id_for_next_experiment")

    payload = {
        "version": "context_frame_v1",
        "run_id": run_id,
        "current_ab": {
            "experiment_id": current_exp_id,
            "source": "metrics_snapshot.run_config.experiment_id",
            "status": "KNOWN" if current_exp_id else "MISSING",
        },
        "next_experiment": {
            "experiment_id": next_exp_id,
            "source": "commander.next_experiment or doctor.ab_plan",
            "status": "KNOWN" if next_exp_id else "MISSING",
        },
        "status": status,
        "error_code": error_code,
        "blocked_by": blocked_by,
        "required_actions": required_actions,
        "load_errors": load_errors,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json_with_sidecar(context_frame_path(run_id), payload)
    write_gate_result(
        run_id,
        gate_name="context_frame",
        status=status,
        error_code=error_code,
        blocked_by=blocked_by,
        required_actions=required_actions,
        details={
            "current_experiment_id": current_exp_id,
            "next_experiment_id": next_exp_id,
        },
    )

    if status != "PASS":
        raise SystemExit(1)
    print(f"ok: context frame built for run_id={run_id}")


if __name__ == "__main__":
    main()
