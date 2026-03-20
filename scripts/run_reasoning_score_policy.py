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

from src.agent_llm_auth import core_agent_llm_authenticity
from src.architecture_v3 import (
    load_json_optional_with_integrity,
    reasoning_policy_path,
    save_json_with_sidecar,
    write_gate_result,
)


def _norm_decision(raw: Any) -> str:
    value = str(raw or "").strip().upper()
    if value in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}:
        return value
    return "HOLD_NEED_DATA"


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate reasoning_score_policy_v2")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    status = "PASS"
    error_code = "NONE"
    blocked_by: list[str] = []
    required_actions: list[str] = []
    load_errors: dict[str, str] = {}

    try:
        commander = load_json_optional_with_integrity(
            Path(f"data/agent_reports/{run_id}_commander_priority.json"),
            required=True,
        ) or {}
    except Exception as exc:
        commander = {}
        status = "FAIL"
        error_code = "METHODOLOGY_INVARIANT_BROKEN"
        blocked_by.append("missing_or_invalid_commander_artifact")
        required_actions.append("run_commander_priority_with_integrity")
        load_errors["commander"] = str(exc)
    try:
        agent_eval = load_json_optional_with_integrity(
            Path(f"data/agent_eval/{run_id}_agent_value_eval.json"),
            required=True,
        ) or {}
    except Exception as exc:
        agent_eval = {}
        status = "FAIL"
        error_code = "METHODOLOGY_INVARIANT_BROKEN"
        blocked_by.append("missing_or_invalid_agent_value_eval")
        required_actions.append("run_agent_value_eval_with_integrity")
        load_errors["agent_value_eval"] = str(exc)
    try:
        llm_auth = core_agent_llm_authenticity(run_id)
    except Exception as exc:
        llm_auth = {"real_llm_agents_count": 0}
        status = "FAIL"
        error_code = "METHODOLOGY_INVARIANT_BROKEN"
        blocked_by.append("missing_or_invalid_core_agent_artifacts")
        required_actions.append("generate_core_agent_artifacts_with_manifest_integrity")
        load_errors["core_agent_artifacts"] = str(exc)

    effective_real_llm_agents_count = int(llm_auth.get("real_llm_agents_count", 0) or 0)
    commander_decision = _norm_decision(commander.get("normalized_decision", commander.get("decision")))
    decision_ceiling = commander_decision

    reasoning_layer = agent_eval.get("system", {}) if isinstance(agent_eval.get("system"), dict) else {}
    reasoning_layer_status = str(reasoning_layer.get("reasoning_layer_status", "")).upper().strip()
    reasoning_layer_score = reasoning_layer.get("reasoning_layer_score")

    if effective_real_llm_agents_count == 0:
        decision_ceiling = "HOLD_NEED_DATA"
        if commander_decision not in {"STOP", "HOLD_NEED_DATA"}:
            status = "FAIL"
            error_code = "METHODOLOGY_INVARIANT_BROKEN"
            blocked_by.append("decision_ceiling_violated_when_no_real_llm_agents")
            required_actions.append("force_commander_decision_to_hold_need_data_when_fallback_only")
        try:
            score_val = float(reasoning_layer_score)
        except Exception:
            score_val = None
        if reasoning_layer_status == "PASS" and score_val is not None and score_val >= 0.90:
            status = "FAIL"
            error_code = "METHODOLOGY_INVARIANT_BROKEN"
            blocked_by.append("fallback_only_run_cannot_be_near_pass")
            required_actions.append("downgrade_reasoning_layer_status_for_full_fallback_runs")

    payload = {
        "version": "reasoning_score_policy_v2",
        "run_id": run_id,
        "status": status,
        "error_code": error_code,
        "effective_real_llm_agents_count": effective_real_llm_agents_count,
        "decision_ceiling": decision_ceiling,
        "blocked_by": sorted({x for x in blocked_by if x})[:20],
        "required_actions": sorted({x for x in required_actions if x})[:20],
        "load_errors": load_errors,
        "observed": {
            "commander_decision": commander_decision,
            "reasoning_layer_status": reasoning_layer_status or "MISSING",
            "reasoning_layer_score": reasoning_layer_score,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    save_json_with_sidecar(reasoning_policy_path(run_id), payload)
    write_gate_result(
        run_id,
        gate_name="reasoning_score_policy",
        status=status,
        error_code=error_code,
        blocked_by=payload["blocked_by"],
        required_actions=payload["required_actions"],
        details={
            "effective_real_llm_agents_count": effective_real_llm_agents_count,
            "decision_ceiling": decision_ceiling,
            "commander_decision": commander_decision,
        },
    )

    if status != "PASS":
        raise SystemExit(1)
    print(f"ok: reasoning score policy PASS for run_id={run_id}")


if __name__ == "__main__":
    main()
