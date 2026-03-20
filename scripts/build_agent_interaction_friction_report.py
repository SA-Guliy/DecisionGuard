#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.artifact_loaders import load_agent_artifacts_with_narrative, load_json_optional
from src.agent_llm_auth import captain_llm_auth, commander_llm_auth, doctor_llm_auth
from src.paths import (
    agent_interaction_friction_registry_json,
    agent_interaction_friction_report_md,
)
from src.status_taxonomy import AB_DECISION_INVALID_STATUSES, goal_from_metric, is_measurement_blocked


def _load(path: Path) -> dict[str, Any] | None:
    return load_json_optional(path)


def _extract_doctor_top_target_goal(doctor: dict[str, Any]) -> str:
    portfolio = doctor.get("hypothesis_portfolio", []) if isinstance(doctor.get("hypothesis_portfolio"), list) else []
    rows = [x for x in portfolio if isinstance(x, dict)]
    rows.sort(key=lambda h: (int(h.get("rank", 9999)) if str(h.get("rank", "")).isdigit() else 9999, -float(h.get("ice_score", 0) or 0)))
    top = rows[0] if rows else {}
    return goal_from_metric(str(top.get("target_metric", "")).strip())


def _fmt_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    out = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for r in rows:
        out.append("| " + " | ".join(r) + " |")
    return out


def _bool(v: Any) -> bool:
    return bool(v)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build agent interaction friction report")
    parser.add_argument("--top-n", type=int, default=15)
    args = parser.parse_args()

    doctor_paths = sorted(Path("data/agent_reports").glob("*_doctor_variance.json"))
    runs = [p.name[: -len("_doctor_variance.json")] for p in doctor_paths]

    friction_counts: Counter[str] = Counter()
    blocked_reason_counts: Counter[str] = Counter()
    decision_pair_counts: Counter[str] = Counter()
    evaluator_pair_counts: Counter[str] = Counter()
    captain_model_counts: Counter[str] = Counter()
    doctor_model_counts: Counter[str] = Counter()
    doctor_method_sel_counts: Counter[str] = Counter()
    commander_model_counts: Counter[str] = Counter()
    commander_llm_fallback_counts: Counter[str] = Counter()
    commander_remote_allowed_counts: Counter[str] = Counter()
    commander_validation_issue_counts: Counter[str] = Counter()
    commander_repair_action_counts: Counter[str] = Counter()
    doctor_method_validation_issue_counts: Counter[str] = Counter()
    captain_repair_action_counts: Counter[str] = Counter()
    core_real_llm_agents_count_dist: Counter[str] = Counter()
    core_llm_path_reached_agents_count_dist: Counter[str] = Counter()
    ab_status_counts: Counter[str] = Counter()
    cohort_status_counts: Counter[str] = Counter()
    narrative_status_counts: Counter[str] = Counter()
    per_run_rows: list[dict[str, Any]] = []

    memory_registry_exists = any(Path("data").glob("**/*memory*")) or Path("memory").exists()

    for run_id in runs:
        arts = load_agent_artifacts_with_narrative(run_id)
        captain = arts["captain"]
        doctor = arts["doctor"]
        evaluator = arts["evaluator"]
        commander = arts["commander"]
        narrative = arts["narrative"]
        ab_v2 = None
        cmd_e = commander.get("evidence_refs", {}) if isinstance(commander.get("evidence_refs"), dict) else {}
        ab_v2_path = cmd_e.get("ab_report_v2")
        if isinstance(ab_v2_path, str) and ab_v2_path:
            ab_v2 = _load(Path(ab_v2_path))

        cap_auth = captain_llm_auth(captain)
        captain_model = str(cap_auth["model"])
        captain_fallback = bool(cap_auth["fallback"])
        captain_model_counts[captain_model] += 1
        cap_prov = captain.get("llm_provenance", {}) if isinstance(captain.get("llm_provenance"), dict) else {}
        for action in (cap_prov.get("repair_actions", []) if isinstance(cap_prov.get("repair_actions"), list) else []):
            captain_repair_action_counts[str(action)] += 1

        doctor_dec = str(doctor.get("normalized_decision", doctor.get("decision", "missing")) or "missing").upper()
        doctor_measurement_state = str(doctor.get("measurement_state", "missing") or "missing").upper()
        doc_auth = doctor_llm_auth(doctor)
        doctor_model = str(doc_auth["model_used"])
        doctor_model_counts[doctor_model] += 1
        doctor_react = bool(((doctor.get("react_config") or {}).get("enabled")) if isinstance(doctor.get("react_config"), dict) else False)
        doctor_protocol_ok = bool(doctor.get("protocol_checks_passed")) if "protocol_checks_passed" in doctor else None
        doc_method = doc_auth["method"] if isinstance(doc_auth.get("method"), dict) else {}
        doc_method_sel = str(doc_auth["method_selected_by"])
        doctor_method_sel_counts[doc_method_sel] += 1
        doc_method_validation = doc_method.get("validation", {}) if isinstance(doc_method.get("validation"), dict) else {}
        for issue in (doc_method_validation.get("issues", []) if isinstance(doc_method_validation.get("issues"), list) else []):
            doctor_method_validation_issue_counts[str(issue)] += 1

        eval_dec = str(evaluator.get("decision", "missing") or "missing").upper()
        eval_ab_status = str(evaluator.get("ab_status", "missing") or "missing").upper()
        ab_status_counts[eval_ab_status] += 1

        cmd_dec = str(commander.get("normalized_decision", commander.get("decision", "missing")) or "missing").upper()
        cmd_react_cfg = commander.get("react_config", {}) if isinstance(commander.get("react_config"), dict) else {}
        cmd_react_enabled = bool(cmd_react_cfg.get("enabled"))
        cmd_model = str(commander.get("commander_model", "missing") or "missing")
        commander_model_counts[cmd_model] += 1
        cmd_llm_prov = commander.get("llm_decision_provenance", {}) if isinstance(commander.get("llm_decision_provenance"), dict) else {}
        commander_llm_fallback_counts[str(cmd_llm_prov.get("fallback_reason", "none") or "none")] += 1
        commander_remote_allowed_counts[str(cmd_llm_prov.get("remote_allowed", "missing"))] += 1
        for issue in (cmd_llm_prov.get("validation_issues", []) if isinstance(cmd_llm_prov.get("validation_issues"), list) else []):
            commander_validation_issue_counts[str(issue)] += 1
        for action in (cmd_llm_prov.get("repair_actions", []) if isinstance(cmd_llm_prov.get("repair_actions"), list) else []):
            commander_repair_action_counts[str(action)] += 1
        captain_real_llm = bool(cap_auth["real_llm"])
        captain_llm_path_reached = bool(cap_auth["llm_path_reached"])
        doctor_method_model = str(doc_auth["method_model"])
        doc_method_prov = doc_auth["method_provenance"] if isinstance(doc_auth.get("method_provenance"), dict) else {}
        doctor_real_llm = bool(doc_auth["real_llm"])
        doctor_llm_path_reached = bool(doc_auth["llm_path_reached"])
        cmd_auth = commander_llm_auth(commander)
        commander_real_llm = bool(cmd_auth["real_llm"])
        commander_llm_path_reached = bool(cmd_auth["llm_path_reached"])
        core_real_llm_agents = int(captain_real_llm) + int(doctor_real_llm) + int(commander_real_llm)
        core_llm_path_reached_agents = int(captain_llm_path_reached) + int(doctor_llm_path_reached) + int(commander_llm_path_reached)
        core_real_llm_agents_count_dist[str(core_real_llm_agents)] += 1
        core_llm_path_reached_agents_count_dist[str(core_llm_path_reached_agents)] += 1
        cmd_method = commander.get("methodology_check", {}) if isinstance(commander.get("methodology_check"), dict) else {}
        cmd_goal_metric_ok = cmd_method.get("goal_metric_alignment_ok")
        cmd_ab_status = str(cmd_method.get("ab_status", "missing") or "missing").upper()
        cmd_cohort_status = str(((commander.get("cohort_analysis") or {}).get("status")) if isinstance(commander.get("cohort_analysis"), dict) else "missing")
        cohort_status_counts[cmd_cohort_status] += 1
        narrative_status = str(narrative.get("status", "missing") or "missing")
        narrative_status_counts[narrative_status] += 1
        narrative_blocked = bool(narrative.get("blocked_by_data")) if "blocked_by_data" in narrative else False

        blocked_by = commander.get("blocked_by", []) if isinstance(commander.get("blocked_by"), list) else []
        for b in blocked_by:
            blocked_reason_counts[str(b)] += 1

        decision_pair_counts[f"{doctor_dec}->{cmd_dec}"] += 1
        evaluator_pair_counts[f"{eval_dec}->{cmd_dec}"] += 1

        frictions: list[str] = []
        if captain_fallback:
            frictions.append("captain_llm_fallback_local_mock")
        if core_real_llm_agents < 3:
            frictions.append("core_agents_not_all_real_llm")
        if core_llm_path_reached_agents > core_real_llm_agents:
            frictions.append("llm_path_reached_but_contract_fallback")
        if doc_method_sel != "doctor_llm_validated":
            frictions.append("doctor_methodology_not_llm_validated")
        if doctor_dec != "missing" and cmd_dec != "missing" and doctor_dec != cmd_dec:
            frictions.append("doctor_commander_decision_disagreement")
        if eval_dec != "missing" and cmd_dec != "missing" and eval_dec != cmd_dec:
            frictions.append("evaluator_commander_decision_disagreement")
        if cmd_goal_metric_ok is False:
            frictions.append("goal_metric_misalignment_at_commander")
        if cmd_cohort_status == "BLOCKED_BY_DATA":
            frictions.append("cohort_evidence_blocked")
        if cmd_react_enabled and "llm_decision_provenance" not in commander:
            frictions.append("commander_react_declared_no_decision_trace")
        if is_measurement_blocked(doctor_measurement_state):
            frictions.append("doctor_measurement_unobservable")
        if eval_ab_status in AB_DECISION_INVALID_STATUSES:
            frictions.append("ab_not_decision_valid")
        if narrative_blocked:
            frictions.append("narrative_blocked_by_data")
        if not doctor.get("ab_interpretation_methodology"):
            frictions.append("doctor_missing_ab_interpretation_methodology")

        for f in frictions:
            friction_counts[f] += 1

        ab_v2_method = {}
        if isinstance(ab_v2, dict):
            ab_v2_method = ab_v2.get("methodology", {}) if isinstance(ab_v2.get("methodology"), dict) else {}
        per_run_rows.append(
            {
                "run_id": run_id,
                "captain_model": captain_model,
                "captain_fallback": captain_fallback,
                "captain_real_llm": captain_real_llm,
                "captain_llm_path_reached": captain_llm_path_reached,
                "doctor_decision": doctor_dec,
                "doctor_measurement_state": doctor_measurement_state,
                "doctor_method_selected_by": doc_method_sel,
                "doctor_real_llm": doctor_real_llm,
                "doctor_llm_path_reached": doctor_llm_path_reached,
                "doctor_react_enabled": doctor_react,
                "doctor_protocol_checks_passed": doctor_protocol_ok,
                "evaluator_decision": eval_dec,
                "evaluator_ab_status": eval_ab_status,
                "commander_decision": cmd_dec,
                "commander_real_llm": commander_real_llm,
                "commander_llm_path_reached": commander_llm_path_reached,
                "commander_ab_status": cmd_ab_status,
                "commander_goal_metric_alignment_ok": cmd_goal_metric_ok,
                "commander_cohort_status": cmd_cohort_status,
                "commander_react_enabled": cmd_react_enabled,
                "core_real_llm_agents_count": core_real_llm_agents,
                "core_llm_path_reached_agents_count": core_llm_path_reached_agents,
                "ab_v2_method_selected_by": str(ab_v2_method.get("selected_by", "missing") or "missing"),
                "frictions": frictions,
            }
        )

    out_json = agent_interaction_friction_registry_json()
    out_md = agent_interaction_friction_report_md()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runs_analyzed": len(runs),
        "summary": {
            "captain_local_mock_fallback_runs": friction_counts.get("captain_llm_fallback_local_mock", 0),
            "core_agents_not_all_real_llm_runs": friction_counts.get("core_agents_not_all_real_llm", 0),
            "llm_path_reached_but_contract_fallback_runs": friction_counts.get("llm_path_reached_but_contract_fallback", 0),
            "runs_with_all_3_core_agents_real_llm": core_real_llm_agents_count_dist.get("3", 0),
            "runs_with_all_3_core_agents_llm_path_reached": core_llm_path_reached_agents_count_dist.get("3", 0),
            "doctor_methodology_not_llm_validated_runs": friction_counts.get("doctor_methodology_not_llm_validated", 0),
            "doctor_commander_decision_disagreement_runs": friction_counts.get("doctor_commander_decision_disagreement", 0),
            "evaluator_commander_decision_disagreement_runs": friction_counts.get("evaluator_commander_decision_disagreement", 0),
            "goal_metric_misalignment_at_commander_runs": friction_counts.get("goal_metric_misalignment_at_commander", 0),
            "cohort_evidence_blocked_runs": friction_counts.get("cohort_evidence_blocked", 0),
            "commander_react_declared_no_decision_trace_runs": friction_counts.get("commander_react_declared_no_decision_trace", 0),
            "memory_registry_detected": bool(memory_registry_exists),
        },
        "friction_counts": [{"friction": k, "count": v} for k, v in friction_counts.most_common()],
        "captain_model_counts": [{"model": k, "count": v} for k, v in captain_model_counts.most_common()],
        "doctor_model_counts": [{"model": k, "count": v} for k, v in doctor_model_counts.most_common()],
        "doctor_methodology_selection_counts": [{"selected_by": k, "count": v} for k, v in doctor_method_sel_counts.most_common()],
        "commander_model_counts": [{"model": k, "count": v} for k, v in commander_model_counts.most_common()],
        "commander_llm_fallback_counts": [{"fallback_reason": k, "count": v} for k, v in commander_llm_fallback_counts.most_common()],
        "commander_remote_allowed_counts": [{"remote_allowed": k, "count": v} for k, v in commander_remote_allowed_counts.most_common()],
        "commander_validation_issue_counts": [{"issue": k, "count": v} for k, v in commander_validation_issue_counts.most_common()],
        "commander_repair_action_counts": [{"action": k, "count": v} for k, v in commander_repair_action_counts.most_common()],
        "doctor_method_validation_issue_counts": [{"issue": k, "count": v} for k, v in doctor_method_validation_issue_counts.most_common()],
        "captain_repair_action_counts": [{"action": k, "count": v} for k, v in captain_repair_action_counts.most_common()],
        "core_real_llm_agents_count_distribution": [{"real_llm_agents": k, "count": v} for k, v in core_real_llm_agents_count_dist.most_common()],
        "core_llm_path_reached_agents_count_distribution": [{"llm_path_agents": k, "count": v} for k, v in core_llm_path_reached_agents_count_dist.most_common()],
        "evaluator_ab_status_counts": [{"ab_status": k, "count": v} for k, v in ab_status_counts.most_common()],
        "cohort_status_counts": [{"status": k, "count": v} for k, v in cohort_status_counts.most_common()],
        "narrative_status_counts": [{"status": k, "count": v} for k, v in narrative_status_counts.most_common()],
        "doctor_to_commander_decision_pairs": [{"pair": k, "count": v} for k, v in decision_pair_counts.most_common()],
        "evaluator_to_commander_decision_pairs": [{"pair": k, "count": v} for k, v in evaluator_pair_counts.most_common()],
        "top_blocked_reasons": [{"reason": k, "count": v} for k, v in blocked_reason_counts.most_common(args.top_n)],
        "runs": per_run_rows,
        "version": "agent_interaction_friction_registry.v1",
    }
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    md: list[str] = []
    md.append("# Agent Interaction Friction Report")
    md.append("")
    md.append(f"- generated_at: `{payload['generated_at']}`")
    md.append(f"- runs_analyzed: `{payload['runs_analyzed']}`")
    md.append(f"- memory_registry_detected: `{payload['summary']['memory_registry_detected']}`")
    md.append(f"- runs_with_all_3_core_agents_real_llm: `{payload['summary']['runs_with_all_3_core_agents_real_llm']}`")
    md.append(f"- runs_with_all_3_core_agents_llm_path_reached: `{payload['summary']['runs_with_all_3_core_agents_llm_path_reached']}`")
    md.append(f"- core_agents_not_all_real_llm_runs: `{payload['summary']['core_agents_not_all_real_llm_runs']}`")
    md.append(f"- llm_path_reached_but_contract_fallback_runs: `{payload['summary']['llm_path_reached_but_contract_fallback_runs']}`")
    md.append("")
    md.append("## Friction Summary")
    md.extend(
        _fmt_table(
            ["Friction", "Count"],
            [[x["friction"], str(x["count"])] for x in payload["friction_counts"][: args.top_n]],
        )
    )
    md.append("")
    md.append("## LLM / Methodology Provenance")
    md.extend(_fmt_table(["Captain model", "Count"], [[x["model"], str(x["count"])] for x in payload["captain_model_counts"]]))
    md.append("")
    md.extend(_fmt_table(["Doctor model_used", "Count"], [[x["model"], str(x["count"])] for x in payload["doctor_model_counts"]]))
    md.append("")
    md.extend(
        _fmt_table(
            ["Doctor methodology selected_by", "Count"],
            [[x["selected_by"], str(x["count"])] for x in payload["doctor_methodology_selection_counts"]],
        )
    )
    md.append("")
    md.extend(_fmt_table(["Commander model", "Count"], [[x["model"], str(x["count"])] for x in payload["commander_model_counts"]]))
    md.append("")
    md.extend(_fmt_table(["Commander remote_allowed", "Count"], [[x["remote_allowed"], str(x["count"])] for x in payload["commander_remote_allowed_counts"]]))
    md.append("")
    md.extend(_fmt_table(["Commander LLM fallback", "Count"], [[x["fallback_reason"], str(x["count"])] for x in payload["commander_llm_fallback_counts"][: args.top_n]]))
    md.append("")
    if payload["commander_validation_issue_counts"]:
        md.extend(_fmt_table(["Commander validation issue", "Count"], [[x["issue"], str(x["count"])] for x in payload["commander_validation_issue_counts"][: args.top_n]]))
        md.append("")
    if payload["commander_repair_action_counts"]:
        md.extend(_fmt_table(["Commander repair action", "Count"], [[x["action"], str(x["count"])] for x in payload["commander_repair_action_counts"][: args.top_n]]))
        md.append("")
    if payload["doctor_method_validation_issue_counts"]:
        md.extend(_fmt_table(["Doctor methodology validator note", "Count"], [[x["issue"], str(x["count"])] for x in payload["doctor_method_validation_issue_counts"][: args.top_n]]))
        md.append("")
    if payload["captain_repair_action_counts"]:
        md.extend(_fmt_table(["Captain repair action", "Count"], [[x["action"], str(x["count"])] for x in payload["captain_repair_action_counts"][: args.top_n]]))
        md.append("")
    md.extend(_fmt_table(["Core real LLM agents (0-3)", "Count"], [[x["real_llm_agents"], str(x["count"])] for x in payload["core_real_llm_agents_count_distribution"]]))
    md.append("")
    md.extend(_fmt_table(["Core LLM path reached agents (0-3)", "Count"], [[x["llm_path_agents"], str(x["count"])] for x in payload["core_llm_path_reached_agents_count_distribution"]]))
    md.append("")
    md.append("## Decision Handoff Pairs")
    md.extend(_fmt_table(["Doctor -> Commander", "Count"], [[x["pair"], str(x["count"])] for x in payload["doctor_to_commander_decision_pairs"][: args.top_n]]))
    md.append("")
    md.extend(_fmt_table(["Evaluator -> Commander", "Count"], [[x["pair"], str(x["count"])] for x in payload["evaluator_to_commander_decision_pairs"][: args.top_n]]))
    md.append("")
    md.append("## Top Commander Blocked Reasons")
    md.extend(_fmt_table(["Reason", "Count"], [[x["reason"], str(x["count"])] for x in payload["top_blocked_reasons"]]))
    md.append("")
    md.append("## Per-Run Snapshot (latest 20)")
    latest_rows = sorted(per_run_rows, key=lambda r: r["run_id"], reverse=True)[:20]
    md.extend(
        _fmt_table(
            ["run_id", "llm_path_core", "real_llm_core", "captain", "doctor", "eval_ab", "commander", "goal_align", "cohort", "frictions"],
            [
                [
                    r["run_id"],
                    str(r.get("core_llm_path_reached_agents_count", 0)),
                    str(r.get("core_real_llm_agents_count", 0)),
                    ("local_mock" if r["captain_fallback"] else r["captain_model"]),
                    f"{r['doctor_decision']} ({r['doctor_method_selected_by']})",
                    f"{r['evaluator_decision']}/{r['evaluator_ab_status']}",
                    r["commander_decision"],
                    str(r["commander_goal_metric_alignment_ok"]),
                    r["commander_cohort_status"],
                    ", ".join(r["frictions"][:3]) + ("..." if len(r["frictions"]) > 3 else ""),
                ]
                for r in latest_rows
            ],
        )
    )
    md.append("")
    md.append("## Notes")
    md.append("- This report is artifact-based and highlights handoff frictions; it does not replace code-level architecture audit.")
    md.append("- `commander_react_declared_no_decision_trace` means ReAct is declared in payload config but no explicit LLM decision trace/provenance field is present.")
    md.append("- `doctor_methodology_not_llm_validated` includes deterministic fallback cases (for example local_mock backend or invalid LLM JSON).")
    md.append("")

    out_md.write_text("\n".join(md), encoding="utf-8")
    print("ok: agent interaction friction report written")


if __name__ == "__main__":
    main()
