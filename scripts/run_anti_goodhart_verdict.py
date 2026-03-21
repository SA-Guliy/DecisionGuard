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
    anti_goodhart_verdict_path,
    load_json_optional_with_integrity,
    save_json_with_sidecar,
    write_gate_result,
)
from src.status_taxonomy import goal_from_metric


def _load_ab_report(run_id: str, experiment_id: str = "") -> tuple[dict[str, Any] | None, str]:
    if experiment_id.strip():
        path = Path(f"data/ab_reports/{run_id}_{experiment_id.strip()}_ab.json")
        if not path.exists():
            return None, "missing_ab"
        try:
            payload = load_json_optional_with_integrity(path, required=True)
        except Exception:
            return None, "invalid_ab_integrity"
        if not isinstance(payload, dict):
            return None, "invalid_ab"
        return payload, str(path)
    files = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab.json"))
    if not files:
        return None, "missing_ab"
    try:
        payload = load_json_optional_with_integrity(files[0], required=True)
    except Exception:
        return None, "invalid_ab_integrity"
    if not isinstance(payload, dict):
        return None, "invalid_ab"
    return payload, str(files[0])


def _load_ab_v2(run_id: str, experiment_id: str = "") -> tuple[dict[str, Any] | None, str]:
    if experiment_id.strip():
        path = Path(f"data/ab_reports/{run_id}_{experiment_id.strip()}_ab_v2.json")
        if not path.exists():
            return None, "missing_ab_v2"
        try:
            payload = load_json_optional_with_integrity(path, required=True)
        except Exception:
            return None, "invalid_ab_v2_integrity"
        if not isinstance(payload, dict):
            return None, "invalid_ab_v2"
        return payload, str(path)
    files = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab_v2.json"))
    if not files:
        return None, "missing_ab_v2"
    try:
        payload = load_json_optional_with_integrity(files[0], required=True)
    except Exception:
        return None, "invalid_ab_v2_integrity"
    if not isinstance(payload, dict):
        return None, "invalid_ab_v2"
    return payload, str(files[0])


def _as_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _derive_anti_goodhart_from_ab(ab: dict[str, Any]) -> bool:
    summary = ab.get("summary", {}) if isinstance(ab.get("summary"), dict) else {}
    primary_metric = str(summary.get("primary_metric", "")).strip()
    goal = goal_from_metric(primary_metric)

    primary_uplift = _as_float(summary.get("primary_metric_uplift"))
    fill_rate_uplift = _as_float(summary.get("fill_rate_uplift"))
    guardrails = summary.get("guardrail_checks", {}) if isinstance(summary.get("guardrail_checks"), dict) else {}
    guardrail_failed = any(v is False for v in guardrails.values() if isinstance(v, bool))

    if goal == "goal1":
        improvement = primary_uplift is not None and primary_uplift < 0.0
        fill_drop = fill_rate_uplift is not None and fill_rate_uplift < -0.005
        return bool(improvement and (guardrail_failed or fill_drop))

    return bool(guardrail_failed and primary_uplift is not None and primary_uplift > 0.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build anti-goodhart single source of truth verdict")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--experiment-id", default="")
    args = parser.parse_args()

    run_id = args.run_id
    experiment_id = str(args.experiment_id or "").strip()
    ab, ab_source = _load_ab_report(run_id, experiment_id)
    ab_v2, ab_v2_source = _load_ab_v2(run_id, experiment_id)

    status = "PASS"
    error_code = "NONE"
    blocked_by: list[str] = []
    required_actions: list[str] = []
    anti_triggered = False

    if ab is None:
        status = "FAIL"
        error_code = "AB_ARTIFACT_REQUIRED"
        blocked_by.append("missing_or_invalid_ab_artifact")
        required_actions.append("generate_ab_before_anti_goodhart_verdict")
    else:
        anti_triggered = _derive_anti_goodhart_from_ab(ab)
        if isinstance(ab_v2, dict) and "anti_goodhart_triggered" in ab_v2:
            ab_v2_flag = bool(ab_v2.get("anti_goodhart_triggered", False))
            if ab_v2_flag != anti_triggered:
                status = "FAIL"
                error_code = "ANTI_GOODHART_MISMATCH"
                blocked_by.append("ab_v2_anti_goodhart_mismatch_with_sot")
                required_actions.append("rebuild_ab_v2_from_anti_goodhart_sot")

    payload = {
        "version": "anti_goodhart_verdict_v1",
        "run_id": run_id,
        "status": status,
        "error_code": error_code,
        "anti_goodhart_triggered": anti_triggered,
        "source_of_truth": "anti_goodhart_verdict_v1",
        "blocked_by": blocked_by,
        "required_actions": required_actions,
        "evidence": {
            "ab_ref": ab_source if isinstance(ab, dict) else "",
            "ab_status": (str(ab.get("status", "")) if isinstance(ab, dict) else ""),
            "ab_v2_ref": ab_v2_source if isinstance(ab_v2, dict) else "",
            "ab_v2_status": (str(ab_v2.get("status", "")) if isinstance(ab_v2, dict) else ""),
            "ab_v2_anti_goodhart_triggered": (
                bool(ab_v2.get("anti_goodhart_triggered", False)) if isinstance(ab_v2, dict) else None
            ),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json_with_sidecar(anti_goodhart_verdict_path(run_id), payload)
    write_gate_result(
        run_id,
        gate_name="anti_goodhart_sot",
        status=status,
        error_code=error_code,
        blocked_by=blocked_by,
        required_actions=required_actions,
        details={
            "anti_goodhart_triggered": anti_triggered,
            "ab_ref": ab_source if isinstance(ab, dict) else "",
            "ab_v2_ref": ab_v2_source if isinstance(ab_v2, dict) else "",
        },
    )

    if status != "PASS":
        raise SystemExit(1)
    print(f"ok: anti_goodhart SoT written for run_id={run_id}")


if __name__ == "__main__":
    main()
