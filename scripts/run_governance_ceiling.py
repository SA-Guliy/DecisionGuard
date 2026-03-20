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
    governance_ceiling_path,
    load_json_optional_with_integrity,
    save_json_with_sidecar,
    write_gate_result,
)


def _norm_decision(raw: Any) -> str:
    value = str(raw or "").strip().upper()
    if value in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}:
        return value
    return "HOLD_NEED_DATA"


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply governance_ceiling_v1 policy")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    status = "PASS"
    error_code = "NONE"
    blocked_by: list[str] = []
    required_actions: list[str] = []
    load_errors: dict[str, str] = {}
    try:
        governance = load_json_optional_with_integrity(
            Path(f"data/agent_governance/{run_id}_agent_approvals.json"),
            required=True,
        )
    except Exception as exc:
        governance = None
        status = "FAIL"
        error_code = "GOVERNANCE_REVIEW_REQUIRED"
        blocked_by.append("missing_or_invalid_governance_artifact")
        required_actions.append("run_agent_governance_with_integrity")
        load_errors["governance"] = str(exc)
    try:
        commander = load_json_optional_with_integrity(
            Path(f"data/agent_reports/{run_id}_commander_priority.json"),
            required=True,
        ) or {}
    except Exception as exc:
        commander = {}
        status = "FAIL"
        error_code = "CONTEXT_CONFLICT"
        blocked_by.append("missing_or_invalid_commander_artifact")
        required_actions.append("run_commander_priority_before_governance_ceiling")
        load_errors["commander"] = str(exc)

    commander_decision = _norm_decision(commander.get("normalized_decision", commander.get("decision")))
    governance_status = str((governance or {}).get("governance_status", "")).strip().lower()
    decision_ceiling = commander_decision

    if governance is None:
        status = "FAIL"
        error_code = "GOVERNANCE_REVIEW_REQUIRED"
        decision_ceiling = "HOLD_NEED_DATA"
        blocked_by.append("missing_governance_artifact")
        required_actions.append("run_agent_governance_before_publish")
    elif governance_status == "missing_review":
        status = "FAIL"
        error_code = "GOVERNANCE_REVIEW_REQUIRED"
        decision_ceiling = "HOLD_NEED_DATA"
        blocked_by.append("governance_status_missing_review")
        req_raw = governance.get("rejection_reasons")
        if isinstance(req_raw, list):
            required_actions.extend([str(x) for x in req_raw if str(x).strip()])
        if not required_actions:
            required_actions.append("collect_human_review_for_open_proposals")
    elif governance_status and governance_status not in {"ok", "pass", "approved"}:
        status = "FAIL"
        error_code = "GOVERNANCE_REVIEW_REQUIRED"
        decision_ceiling = "HOLD_NEED_DATA"
        blocked_by.append(f"governance_status_{governance_status}")
        required_actions.append("resolve_governance_status_before_publish")

    if status == "FAIL" and not required_actions:
        required_actions.append("provide_governance_required_actions")
    if status == "FAIL" and decision_ceiling != "HOLD_NEED_DATA":
        decision_ceiling = "HOLD_NEED_DATA"

    payload = {
        "version": "governance_ceiling_v1",
        "run_id": run_id,
        "governance_status": governance_status or "missing",
        "status": status,
        "error_code": error_code,
        "decision_ceiling": decision_ceiling,
        "required_actions": sorted({x for x in required_actions if x})[:20],
        "blocked_by": sorted({x for x in blocked_by if x})[:20],
        "load_errors": load_errors,
        "observed": {
            "commander_decision": commander_decision,
            "proposal_rows_count": (
                len(governance.get("proposal_rows", []))
                if isinstance(governance, dict) and isinstance(governance.get("proposal_rows"), list)
                else 0
            ),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json_with_sidecar(governance_ceiling_path(run_id), payload)
    write_gate_result(
        run_id,
        gate_name="governance_ceiling",
        status=status,
        error_code=error_code,
        blocked_by=payload["blocked_by"],
        required_actions=payload["required_actions"],
        details={
            "governance_status": payload["governance_status"],
            "decision_ceiling": decision_ceiling,
            "commander_decision": commander_decision,
        },
    )

    if status != "PASS":
        raise SystemExit(1)
    print(f"ok: governance ceiling PASS for run_id={run_id}")


if __name__ == "__main__":
    main()
