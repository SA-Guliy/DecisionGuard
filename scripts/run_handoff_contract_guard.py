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
    handoff_guard_path,
    load_json_with_integrity,
    load_json_optional_with_integrity,
    save_json_with_sidecar,
    write_gate_result,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Doctor->Evaluator handoff contract")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    doctor_load_error = ""
    try:
        doctor = load_json_optional_with_integrity(
            Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
            required=False,
        )
    except Exception as exc:
        doctor = None
        doctor_load_error = str(exc)
    status = "PASS"
    error_code = "NONE"
    blocked_by: list[str] = []
    required_actions: list[str] = []
    details: dict[str, Any] = {}

    try:
        context_frame = load_json_with_integrity(context_frame_path(run_id))
    except Exception as exc:
        context_frame = {}
        status = "FAIL"
        error_code = "CONTEXT_CONFLICT"
        blocked_by.append("missing_or_invalid_context_frame")
        required_actions.append("run_context_frame_before_handoff_guard")
        details["context_frame_error"] = str(exc)

    if doctor_load_error:
        status = "FAIL"
        error_code = "CONTEXT_CONFLICT"
        blocked_by.append("invalid_optional_doctor_artifact")
        required_actions.append("remove_or_regenerate_doctor_artifact_with_integrity")
        details["doctor_load_error"] = doctor_load_error

    if isinstance(context_frame, dict):
        if str(context_frame.get("status", "PASS")).upper() != "PASS":
            status = "FAIL"
            error_code = "CONTEXT_CONFLICT"
            blocked_by.append("context_frame_status_fail")
            required_actions.append("resolve_context_conflict")
        current_id = str(((context_frame.get("current_ab") or {}) if isinstance(context_frame.get("current_ab"), dict) else {}).get("experiment_id", "")).strip()
        next_id = str(((context_frame.get("next_experiment") or {}) if isinstance(context_frame.get("next_experiment"), dict) else {}).get("experiment_id", "")).strip()
        details["current_experiment_id"] = current_id
        details["next_experiment_id"] = next_id
        if current_id and next_id and current_id == next_id:
            status = "FAIL"
            error_code = "CONTEXT_CONFLICT"
            blocked_by.append("same_experiment_id_across_contours")
            required_actions.append("assign_distinct_experiment_id_for_next_experiment")

    if isinstance(doctor, dict):
        doctor_decision = str(doctor.get("normalized_decision", doctor.get("decision", ""))).upper().strip()
        if doctor_decision not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}:
            status = "FAIL"
            error_code = "CONTEXT_CONFLICT"
            blocked_by.append("doctor_decision_invalid")
            required_actions.append("repair_doctor_contract_output")
        details["doctor_decision"] = doctor_decision
    else:
        details["doctor_artifact_present"] = False
        details["doctor_artifact_optional_before_doctor_gate"] = True

    payload = {
        "version": "handoff_contract_guard_v1",
        "run_id": run_id,
        "from_agent": "doctor",
        "to_agent": "evaluator",
        "status": status,
        "error_code": error_code,
        "blocked_by": sorted({x for x in blocked_by if x})[:20],
        "required_actions": sorted({x for x in required_actions if x})[:20],
        "context_frame_ref": str(context_frame_path(run_id)),
        "details": details,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json_with_sidecar(handoff_guard_path(run_id), payload)
    write_gate_result(
        run_id,
        gate_name="handoff_contract_guard",
        status=status,
        error_code=error_code,
        blocked_by=payload["blocked_by"],
        required_actions=payload["required_actions"],
        details=details,
    )

    if status != "PASS":
        raise SystemExit(1)
    print(f"ok: handoff contract guard PASS for run_id={run_id}")


if __name__ == "__main__":
    main()
