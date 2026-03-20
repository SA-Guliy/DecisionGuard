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
    load_json_optional_with_integrity,
    quality_invariants_path,
    save_json_with_sidecar,
    write_gate_result,
)


def _ab_v2(run_id: str) -> dict[str, Any] | None:
    files = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab_v2.json"))
    if not files:
        return None
    return load_json_optional_with_integrity(files[0], required=True)


def _find_methodology_mismatch_status(adversarial: dict[str, Any]) -> str:
    scenarios = adversarial.get("scenarios", []) if isinstance(adversarial.get("scenarios"), list) else []
    for row in scenarios:
        if isinstance(row, dict) and str(row.get("scenario", "")).strip().lower() == "methodology_mismatch":
            return str(row.get("status", "")).upper().strip()
    return "UNKNOWN"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run quality invariants gate")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    status = "PASS"
    error_code = "NONE"
    blocked_by: list[str] = []
    required_actions: list[str] = []
    load_errors: dict[str, str] = {}
    agent_eval: dict[str, Any] = {}
    adversarial: dict[str, Any] = {}
    ab_v2: dict[str, Any] = {}

    try:
        agent_eval = load_json_optional_with_integrity(
            Path(f"data/agent_eval/{run_id}_agent_value_eval.json"),
            required=True,
        ) or {}
    except Exception as exc:
        status = "FAIL"
        error_code = "METHODOLOGY_INVARIANT_BROKEN"
        blocked_by.append("missing_or_invalid_agent_value_eval")
        required_actions.append("run_agent_value_eval_with_integrity")
        load_errors["agent_value_eval"] = str(exc)
    try:
        adversarial = load_json_optional_with_integrity(
            Path(f"data/eval/adversarial_suite_{run_id}.json"),
            required=True,
        ) or {}
    except Exception as exc:
        status = "FAIL"
        error_code = "METHODOLOGY_INVARIANT_BROKEN"
        blocked_by.append("missing_or_invalid_adversarial_suite")
        required_actions.append("run_adversarial_eval_suite_with_integrity")
        load_errors["adversarial_suite"] = str(exc)
    try:
        ab_v2 = _ab_v2(run_id) or {}
    except Exception as exc:
        status = "FAIL"
        error_code = "METHODOLOGY_INVARIANT_BROKEN"
        blocked_by.append("missing_or_invalid_ab_v2")
        required_actions.append("run_ab_analysis_to_generate_ab_v2")
        load_errors["ab_v2"] = str(exc)

    alignment_status = str(ab_v2.get("alignment_status", "")).upper().strip()
    unit_alignment_status = str((((ab_v2.get("sampling") or {}) if isinstance(ab_v2.get("sampling"), dict) else {}).get("unit_alignment_status", "")).upper()).strip()
    conformance_fail = alignment_status in {"MISMATCH", "FAIL"} or unit_alignment_status in {"FAIL", "MISMATCH"}
    methodology_mismatch_status = _find_methodology_mismatch_status(adversarial)

    checks: list[dict[str, Any]] = []
    checks.append(
        {
            "name": "conformance_goal_metric_unit_vs_methodology_mismatch",
            "status": "PASS",
            "details": {
                "conformance_fail": conformance_fail,
                "alignment_status": alignment_status,
                "unit_alignment_status": unit_alignment_status,
                "methodology_mismatch_status": methodology_mismatch_status,
            },
        }
    )

    if conformance_fail and methodology_mismatch_status == "PASS":
        status = "FAIL"
        error_code = "METHODOLOGY_INVARIANT_BROKEN"
        blocked_by.append("conformance_fail_while_methodology_mismatch_pass")
        required_actions.append("set_methodology_mismatch_to_fail_when_goal_metric_unit_conformance_fails")
        checks[0]["status"] = "FAIL"

    payload = {
        "version": "quality_invariants_v1",
        "run_id": run_id,
        "status": status,
        "error_code": error_code,
        "checks": checks,
        "blocked_by": blocked_by,
        "required_actions": required_actions,
        "load_errors": load_errors,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json_with_sidecar(quality_invariants_path(run_id), payload)
    write_gate_result(
        run_id,
        gate_name="quality_invariants",
        status=status,
        error_code=error_code,
        blocked_by=blocked_by,
        required_actions=required_actions,
        details={
            "alignment_status": alignment_status,
            "unit_alignment_status": unit_alignment_status,
            "methodology_mismatch_status": methodology_mismatch_status,
            "has_agent_eval": bool(agent_eval),
        },
    )

    if status != "PASS":
        raise SystemExit(1)
    print(f"ok: quality invariants PASS for run_id={run_id}")


if __name__ == "__main__":
    main()
