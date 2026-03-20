#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _add(out: list[dict[str, Any]], level: str, code: str, message: str) -> None:
    out.append({"level": level, "code": code, "message": message})


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Captain/Doctor/Commander contract consistency")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    captain = _load(Path(f"data/llm_reports/{run_id}_captain.json")) or {}
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
    commander = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}
    snapshot = _load(Path(f"data/metrics_snapshots/{run_id}.json")) or {}

    findings: list[dict[str, Any]] = []

    cap_result = captain.get("result", {}) if isinstance(captain.get("result"), dict) else {}
    if cap_result.get("verdict") not in {"PASS", "WARN", "FAIL"}:
        _add(findings, "ERROR", "captain_verdict_invalid", "Captain verdict missing or invalid")

    doctor_decision = str(doctor.get("normalized_decision", doctor.get("decision", ""))).strip()
    if doctor_decision not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}:
        _add(findings, "ERROR", "doctor_decision_invalid", "Doctor normalized_decision is invalid")

    assignment_status = str(doctor.get("assignment_status", "missing")).strip().lower()
    if assignment_status not in {"ready", "present", "missing"}:
        _add(findings, "WARN", "doctor_assignment_status_unexpected", f"Unexpected assignment_status={assignment_status}")

    doctor_quality = doctor.get("quality", {}) if isinstance(doctor.get("quality"), dict) else {}
    if not isinstance(doctor_quality.get("hypothesis_valid"), bool):
        _add(findings, "WARN", "doctor_hypothesis_flag_missing", "Doctor quality.hypothesis_valid missing")
    if not isinstance(doctor_quality.get("methodology_present"), bool):
        _add(findings, "WARN", "doctor_methodology_flag_missing", "Doctor quality.methodology_present missing")

    ab_plan = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
    first_exp = ab_plan[0] if ab_plan and isinstance(ab_plan[0], dict) else {}

    if doctor_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
        if assignment_status not in {"ready", "present"}:
            _add(findings, "ERROR", "assignment_missing_for_run_ab", "Doctor allows AB but assignment is not ready")
        required_exp_keys = [
            "hypotheses",
            "methodology",
            "sample_size_gate",
            "min_sample_size",
            "mde",
            "confidence_level",
            "goal",
            "north_star_metric",
            "dod",
        ]
        for key in required_exp_keys:
            if key not in first_exp:
                _add(findings, "ERROR", "doctor_experiment_contract_missing", f"Doctor experiment missing key={key}")
        if not first_exp.get("methodology_detail"):
            _add(findings, "ERROR", "doctor_methodology_detail_missing", "Doctor experiment missing methodology_detail")
        try:
            if float(first_exp.get("mde", 0) or 0) <= 0:
                _add(findings, "ERROR", "doctor_mde_missing", "Doctor experiment has invalid mde")
        except Exception:
            _add(findings, "ERROR", "doctor_mde_missing", "Doctor experiment has invalid mde")
        try:
            cl = float(first_exp.get("confidence_level", 0) or 0)
            if cl <= 0 or cl >= 1:
                _add(findings, "ERROR", "doctor_confidence_level_missing", "Doctor experiment has invalid confidence_level")
        except Exception:
            _add(findings, "ERROR", "doctor_confidence_level_missing", "Doctor experiment has invalid confidence_level")

    commander_decision = str(commander.get("normalized_decision", commander.get("decision", ""))).strip()
    if commander_decision not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}:
        _add(findings, "ERROR", "commander_decision_invalid", "Commander normalized_decision is invalid")

    if doctor_decision in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"} and commander_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
        _add(findings, "ERROR", "commander_overrides_doctor", "Commander escalated decision above Doctor gate")

    run_cfg = snapshot.get("run_config", {}) if isinstance(snapshot.get("run_config"), dict) else {}
    experiment_id = str(run_cfg.get("experiment_id", "") or "").strip()
    if experiment_id:
        ab_report = _load(Path(f"data/ab_reports/{run_id}_{experiment_id}_ab.json"))
        if ab_report is None:
            _add(findings, "WARN", "ab_report_missing", "AB report missing for experiment_id from run_config")
        else:
            ab_status = str(ab_report.get("status", "")).upper()
            if ab_status in {"MISSING_ASSIGNMENT", "UNDERPOWERED", "INCONCLUSIVE"} and commander_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                _add(findings, "ERROR", "commander_ignores_ab_status", f"Commander decision conflicts with ab_status={ab_status}")

    errors = [x for x in findings if x["level"] == "ERROR"]
    warnings = [x for x in findings if x["level"] == "WARN"]
    passed = len(errors) == 0

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "findings": findings,
        "version": "contracts.v1",
    }

    out_json = Path(f"data/agent_quality/{run_id}_contracts.json")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        f"# Contract Check — {run_id}",
        "",
        f"- passed: `{passed}`",
        f"- errors: `{len(errors)}`",
        f"- warnings: `{len(warnings)}`",
        "",
        "| level | code | message |",
        "|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f['level']} | {f['code']} | {f['message']} |")
    if not findings:
        lines.append("| INFO | none | all contract checks passed |")

    out_md = Path(f"reports/L1_ops/{run_id}/contract_check.md")
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"ok: contract check written for run_id={run_id}")


if __name__ == "__main__":
    main()
