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


def _float_or_zero(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Build agent quality report for one run")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    captain = _load(Path(f"data/llm_reports/{run_id}_captain.json")) or {}
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
    evaluator = _load(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")) or {}
    commander = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}
    eval_v2 = _load(Path(f"reports/L1_ops/{run_id}/agent_effectiveness.json")) or {}

    cap_eval = captain.get("eval_metrics", {}) if isinstance(captain.get("eval_metrics"), dict) else {}
    doctor_ab = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
    doctor_first = doctor_ab[0] if doctor_ab and isinstance(doctor_ab[0], dict) else {}
    hypotheses = doctor_first.get("hypotheses", []) if isinstance(doctor_first.get("hypotheses"), list) else []

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "captain": {
            "issue_coverage": cap_eval.get("issue_coverage"),
            "no_extra_issues": cap_eval.get("no_extra_issues"),
            "actionability": cap_eval.get("actionability"),
            "safety": cap_eval.get("safety"),
            "semantic_score": cap_eval.get("semantic_score"),
            "fallback_used": captain.get("fallback_used"),
            "pass": bool(cap_eval.get("safety", False)) and bool(cap_eval.get("no_extra_issues", False)),
        },
        "doctor": {
            "hypothesis_valid": bool(hypotheses and isinstance(hypotheses[0], dict) and str(hypotheses[0].get("hypothesis_statement", "")).strip()),
            "methodology_present": bool(str(doctor_first.get("methodology", "")).strip()) or bool((doctor.get("quality") or {}).get("methodology_present")),
            "assignment_status": doctor.get("assignment_status"),
            "required_sample_size_present": bool((doctor.get("quality") or {}).get("required_sample_size_present") or doctor_first.get("methodology_detail")),
            "mde_present": _float_or_zero(doctor_first.get("mde", 0) or 0) > 0,
            "confidence_level_present": 0 < _float_or_zero(doctor_first.get("confidence_level", 0) or 0) < 1,
            "assignment_gate_ok": str(doctor.get("assignment_status", "")).strip().lower() in {"ready", "present"},
            "normalized_decision": doctor.get("normalized_decision", doctor.get("decision")),
            "guardrails_listed": bool(doctor_first.get("guardrails")),
            "dod_present": bool(doctor_first.get("dod")),
            "decision_contract_valid": bool(str(doctor.get("decision_contract_version", "")).strip()),
            "semantic_score": (doctor.get("quality") or {}).get("semantic_score") if isinstance(doctor.get("quality"), dict) else None,
        },
        "evaluator": {
            "decision": evaluator.get("decision"),
            "evidence_present": bool(str((doctor.get("evidence") or {}).get("ab_report", "")).strip()) if isinstance(doctor.get("evidence"), dict) else False,
            "underpowered_flag": str(evaluator.get("ab_status", "")).upper() == "UNDERPOWERED",
            "inconclusive_flag": str(evaluator.get("ab_status", "")).upper() == "INCONCLUSIVE",
            "blocked_by_count": len(evaluator.get("blocked_by", []) if isinstance(evaluator.get("blocked_by"), list) else []),
        },
        "commander": {
            "normalized_decision": commander.get("normalized_decision", commander.get("decision")),
            "blocked_by_count": len(commander.get("blocked_by", []) if isinstance(commander.get("blocked_by"), list) else []),
            "go_requires_methodology": not (
                str(commander.get("normalized_decision", commander.get("decision", ""))).upper() in {"RUN_AB", "ROLLOUT_CANDIDATE"}
                and not (
                    (bool(str(doctor_first.get("methodology", "")).strip()) or bool((doctor.get("quality") or {}).get("methodology_present")))
                    and (_float_or_zero(doctor_first.get("mde", 0) or 0) > 0)
                    and (0 < _float_or_zero(doctor_first.get("confidence_level", 0) or 0) < 1)
                )
            ),
            "interference_blocked": bool(
                isinstance(commander.get("next_experiment"), dict)
                and isinstance((commander.get("next_experiment") or {}).get("interference"), dict)
                and str(((commander.get("next_experiment") or {}).get("interference") or {}).get("risk_level", "")).lower() == "high"
            ),
            "priority_score_selected": ((commander.get("next_experiment") or {}).get("priority_score") if isinstance(commander.get("next_experiment"), dict) else None),
        },
        "v2": eval_v2 if isinstance(eval_v2, dict) else {},
    }
    payload["system_safe"] = bool(
        payload["captain"]["pass"]
        and str(payload["commander"]["normalized_decision"]).upper() != "STOP"
        and not payload["evaluator"]["underpowered_flag"]
        and not bool(captain.get("fallback_used"))
    )
    payload["business_value_produced"] = bool(
        str(payload["commander"]["normalized_decision"]).upper() in {"RUN_AB", "ROLLOUT_CANDIDATE"}
        and payload["doctor"]["hypothesis_valid"]
        and payload["doctor"]["methodology_present"]
    )

    lines = [
        f"# Agent Quality — {run_id}",
        "",
        "| Agent | Check | Value |",
        "|---|---|---|",
        f"| Captain | issue_coverage | {payload['captain']['issue_coverage']} |",
        f"| Captain | no_extra_issues | {payload['captain']['no_extra_issues']} |",
        f"| Captain | actionability | {payload['captain']['actionability']} |",
        f"| Captain | safety | {payload['captain']['safety']} |",
        f"| Captain | semantic_score | {payload['captain']['semantic_score']} |",
        f"| Captain | fallback_used | {payload['captain']['fallback_used']} |",
        f"| Doctor | hypothesis_valid | {payload['doctor']['hypothesis_valid']} |",
        f"| Doctor | methodology_present | {payload['doctor']['methodology_present']} |",
        f"| Doctor | assignment_status | {payload['doctor']['assignment_status']} |",
        f"| Doctor | required_sample_size_present | {payload['doctor']['required_sample_size_present']} |",
        f"| Doctor | mde_present | {payload['doctor']['mde_present']} |",
        f"| Doctor | confidence_level_present | {payload['doctor']['confidence_level_present']} |",
        f"| Doctor | assignment_gate_ok | {payload['doctor']['assignment_gate_ok']} |",
        f"| Doctor | normalized_decision | {payload['doctor']['normalized_decision']} |",
        f"| Doctor | guardrails_listed | {payload['doctor']['guardrails_listed']} |",
        f"| Doctor | DoD_present | {payload['doctor']['dod_present']} |",
        f"| Doctor | decision_contract_valid | {payload['doctor']['decision_contract_valid']} |",
        f"| Doctor | semantic_score | {payload['doctor']['semantic_score']} |",
        f"| Evaluator | decision | {payload['evaluator']['decision']} |",
        f"| Evaluator | evidence_present | {payload['evaluator']['evidence_present']} |",
        f"| Evaluator | underpowered_flag | {payload['evaluator']['underpowered_flag']} |",
        f"| Evaluator | inconclusive_flag | {payload['evaluator']['inconclusive_flag']} |",
        f"| Evaluator | blocked_by_count | {payload['evaluator']['blocked_by_count']} |",
        f"| Commander | normalized_decision | {payload['commander']['normalized_decision']} |",
        f"| Commander | blocked_by_count | {payload['commander']['blocked_by_count']} |",
        f"| Commander | go_requires_methodology | {payload['commander']['go_requires_methodology']} |",
        f"| Commander | interference_blocked | {payload['commander']['interference_blocked']} |",
        f"| Commander | priority_score_selected | {payload['commander']['priority_score_selected']} |",
        (
            f"| V2 | narrative_grounded_rate | "
            f"{((payload['v2'].get('narrative') or {}).get('grounded_rate') if isinstance(payload.get('v2'), dict) else 'missing')} |"
        ),
        (
            f"| V2 | narrative_uniqueness_rate | "
            f"{((payload['v2'].get('narrative') or {}).get('uniqueness_rate') if isinstance(payload.get('v2'), dict) else 'missing')} |"
        ),
        (
            f"| V2 | doctor_go_without_evidence_penalty | "
            f"{((payload['v2'].get('doctor') or {}).get('go_without_evidence_penalty') if isinstance(payload.get('v2'), dict) else 'missing')} |"
        ),
        (
            f"| V2 | captain_fallback_penalty_applied | "
            f"{((payload['v2'].get('captain') or {}).get('fallback_penalty_applied') if isinstance(payload.get('v2'), dict) else 'missing')} |"
        ),
        "",
        f"- System safe?: `{payload['system_safe']}`",
        f"- Business value produced?: `{payload['business_value_produced']}`",
        "",
    ]

    out_md = Path(f"reports/L1_ops/{run_id}/agent_quality.md")
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines), encoding="utf-8")

    print(f"ok: agent quality report (md-only legacy v1) written for run_id={run_id}")


if __name__ == "__main__":
    main()
