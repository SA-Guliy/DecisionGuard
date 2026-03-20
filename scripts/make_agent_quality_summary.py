#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent_llm_auth import captain_llm_auth, commander_llm_auth, doctor_llm_auth


def _load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _week_id() -> str:
    now = datetime.now(timezone.utc)
    year, week, _ = now.isocalendar()
    return f"{year}-W{week:02d}"


def _weekly_dir_name(week_id: str) -> str:
    return f"weekly_{week_id.replace('-', '_')}"


def _run_id_from_suffix(path: Path, suffix: str) -> str:
    name = path.name
    return name[: -len(suffix)] if name.endswith(suffix) else name


def _avg(vals: list[float]) -> float | None:
    return (sum(vals) / len(vals)) if vals else None


def _is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        s = value.strip().lower()
        return bool(s and s not in {"missing", "none", "null", "nan", "n/a", "unknown"})
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def _norm_blocker_code(value: Any) -> str:
    s = str(value or "").strip()
    if not s:
        return "missing"
    # Keep stable prefix before verbose explanation/details.
    if ":" in s:
        s = s.split(":", 1)[0].strip()
    if "|" in s:
        s = s.split("|", 1)[0].strip()
    return s or "missing"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build agent quality summary")
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--week-id", default="", help="Override ISO week id (YYYY-Www)")
    args = parser.parse_args()

    reports_dir = Path("data")
    captain_files = sorted((reports_dir / "llm_reports").glob("*_captain.json"), key=lambda p: p.stat().st_mtime, reverse=True)[: args.limit]
    doctor_files = sorted((reports_dir / "agent_reports").glob("*_doctor_variance.json"), key=lambda p: p.stat().st_mtime, reverse=True)[: args.limit]
    commander_files = sorted((reports_dir / "agent_reports").glob("*_commander_priority.json"), key=lambda p: p.stat().st_mtime, reverse=True)[: args.limit]
    evaluator_files = sorted((reports_dir / "agent_reports").glob("*_experiment_evaluator.json"), key=lambda p: p.stat().st_mtime, reverse=True)[: args.limit]

    captain_vals = {"issue_coverage": [], "actionability": [], "semantic_score": [], "safety_true": 0, "fallback_true": 0, "total": 0, "no_extra_true": 0}
    captain_auth_by_run: dict[str, dict[str, Any]] = {}
    for p in captain_files:
        data = _load(p)
        if not data:
            continue
        rid = _run_id_from_suffix(p, "_captain.json")
        ev = data.get("eval_metrics", {}) if isinstance(data.get("eval_metrics"), dict) else {}
        captain_vals["total"] += 1
        if ev.get("issue_coverage") is not None:
            captain_vals["issue_coverage"].append(float(ev.get("issue_coverage") or 0.0))
        if ev.get("actionability") is not None:
            captain_vals["actionability"].append(float(ev.get("actionability") or 0.0))
        if ev.get("semantic_score") is not None:
            captain_vals["semantic_score"].append(float(ev.get("semantic_score") or 0.0))
        if bool(ev.get("safety")):
            captain_vals["safety_true"] += 1
        if bool(ev.get("no_extra_issues")):
            captain_vals["no_extra_true"] += 1
        if bool(data.get("fallback_used")):
            captain_vals["fallback_true"] += 1
        captain_auth_by_run[rid] = captain_llm_auth(data)

    doctor_decisions = Counter()
    doctor_hyp_valid = 0
    doctor_assignment_gate = 0
    doctor_total = 0
    doctor_auth_by_run: dict[str, dict[str, Any]] = {}
    doctor_method_selection = Counter()
    doctor_design_coverage: list[float] = []
    doctor_design_complete = 0
    doctor_design_gap_codes = Counter()
    for p in doctor_files:
        data = _load(p)
        if not data:
            continue
        rid = _run_id_from_suffix(p, "_doctor_variance.json")
        doctor_total += 1
        doctor_decisions[str(data.get("decision", "unknown"))] += 1
        if str(data.get("assignment_status", "")).lower() in {"present", "ready"}:
            doctor_assignment_gate += 1
        ab_plan = data.get("ab_plan", []) if isinstance(data.get("ab_plan"), list) else []
        recommended_experiment = data.get("recommended_experiment", {}) if isinstance(data.get("recommended_experiment"), dict) else {}
        first_exp = ab_plan[0] if ab_plan and isinstance(ab_plan[0], dict) else (recommended_experiment if isinstance(recommended_experiment, dict) else {})
        if first_exp:
            h = first_exp.get("hypotheses") if isinstance(first_exp.get("hypotheses"), list) else None
            if isinstance(h, list) and h and isinstance(h[0], dict) and str(h[0].get("hypothesis_statement", "")).strip():
                doctor_hyp_valid += 1
        measurement_fix_plan = data.get("measurement_fix_plan", {}) if isinstance(data.get("measurement_fix_plan"), dict) else {}
        required_raw = measurement_fix_plan.get("required_design_fields")
        required_fields = [str(x).strip() for x in required_raw] if isinstance(required_raw, list) else []
        if not required_fields:
            required_fields = [
                "pre_period_weeks",
                "test_period_weeks",
                "wash_in_days",
                "attribution_window_rule",
                "test_side",
                "randomization_unit",
                "analysis_unit",
            ]
        required_fields = [x for x in required_fields if x]
        aliases = {
            "randomization_unit": "randomization_unit_cfg",
            "analysis_unit": "analysis_unit_realized",
            "randomization_unit_cfg": "randomization_unit",
            "analysis_unit_realized": "analysis_unit",
        }
        missing_fields: list[str] = []
        if required_fields:
            present = 0
            for key in required_fields:
                value = first_exp.get(key) if isinstance(first_exp, dict) else None
                if value is None and key in aliases and isinstance(first_exp, dict):
                    value = first_exp.get(aliases[key])
                if _is_present(value):
                    present += 1
                else:
                    missing_fields.append(key)
                    doctor_design_gap_codes[key] += 1
            coverage = present / len(required_fields)
            doctor_design_coverage.append(float(coverage))
            if not missing_fields:
                doctor_design_complete += 1
        auth = doctor_llm_auth(data)
        doctor_auth_by_run[rid] = auth
        doctor_method_selection[str(auth.get("method_selected_by", "missing"))] += 1

    commander_hold_reasons = Counter()
    commander_hold_reason_codes = Counter()
    commander_interference_blocks = 0
    commander_total = 0
    commander_auth_by_run: dict[str, dict[str, Any]] = {}
    for p in commander_files:
        data = _load(p)
        if not data:
            continue
        rid = _run_id_from_suffix(p, "_commander_priority.json")
        commander_total += 1
        for b in (data.get("blocked_by") or []):
            commander_hold_reasons[str(b)] += 1
            commander_hold_reason_codes[_norm_blocker_code(b)] += 1
        nxt = data.get("next_experiment")
        if isinstance(nxt, dict):
            inter = nxt.get("interference", {}) if isinstance(nxt.get("interference"), dict) else {}
            if str(inter.get("risk_level", "")).lower() == "high":
                commander_interference_blocks += 1
        commander_auth_by_run[rid] = commander_llm_auth(data)

    evaluator_ab_status = Counter()
    evaluator_measurement_state = Counter()
    evaluator_total = 0
    for p in evaluator_files:
        data = _load(p)
        if not data:
            continue
        evaluator_total += 1
        evaluator_ab_status[str(data.get("ab_status", "missing"))] += 1
        evaluator_measurement_state[str(data.get("measurement_state", "missing"))] += 1

    common_runs = sorted(set(captain_auth_by_run) & set(doctor_auth_by_run) & set(commander_auth_by_run))
    real_llm_counts: list[int] = []
    llm_path_counts: list[int] = []
    all_3_real = 0
    for rid in common_runs:
        c = captain_auth_by_run[rid]
        d = doctor_auth_by_run[rid]
        m = commander_auth_by_run[rid]
        real_cnt = int(bool(c.get("real_llm"))) + int(bool(d.get("real_llm"))) + int(bool(m.get("real_llm")))
        path_cnt = int(bool(c.get("llm_path_reached"))) + int(bool(d.get("llm_path_reached"))) + int(bool(m.get("llm_path_reached")))
        real_llm_counts.append(float(real_cnt))
        llm_path_counts.append(float(path_cnt))
        if real_cnt == 3:
            all_3_real += 1

    summary = {
        "version": "agent_quality_summary.v2",
        "scope": "L2_weekly_rollup",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_limit": args.limit,
        "run_window": {
            "common_core_agent_runs_n": len(common_runs),
            "captain_runs_n": len(captain_auth_by_run),
            "doctor_runs_n": len(doctor_auth_by_run),
            "commander_runs_n": len(commander_auth_by_run),
            "sample_run_ids": common_runs[:10],
        },
        "llm_authenticity": {
            "all_3_core_agents_real_llm_pct": (all_3_real / len(common_runs)) if common_runs else None,
            "avg_real_llm_agents_per_run": _avg(real_llm_counts),
            "avg_llm_path_reached_agents_per_run": _avg(llm_path_counts),
            "captain_real_llm_pct": (_avg([1.0 if bool(v.get("real_llm")) else 0.0 for v in captain_auth_by_run.values()])),
            "doctor_real_llm_pct": (_avg([1.0 if bool(v.get("real_llm")) else 0.0 for v in doctor_auth_by_run.values()])),
            "commander_real_llm_pct": (_avg([1.0 if bool(v.get("real_llm")) else 0.0 for v in commander_auth_by_run.values()])),
            "captain_llm_path_reached_pct": (_avg([1.0 if bool(v.get("llm_path_reached")) else 0.0 for v in captain_auth_by_run.values()])),
            "doctor_llm_path_reached_pct": (_avg([1.0 if bool(v.get("llm_path_reached")) else 0.0 for v in doctor_auth_by_run.values()])),
            "commander_llm_path_reached_pct": (_avg([1.0 if bool(v.get("llm_path_reached")) else 0.0 for v in commander_auth_by_run.values()])),
        },
        "captain": {
            "issue_coverage_avg": _avg(captain_vals["issue_coverage"]),
            "actionability_avg": _avg(captain_vals["actionability"]),
            "semantic_score_avg": _avg(captain_vals["semantic_score"]),
            "safety_true_pct": (captain_vals["safety_true"] / captain_vals["total"]) if captain_vals["total"] else None,
            "no_extra_true_pct": (captain_vals["no_extra_true"] / captain_vals["total"]) if captain_vals["total"] else None,
            "fallback_used_pct": (captain_vals["fallback_true"] / captain_vals["total"]) if captain_vals["total"] else None,
            "n": captain_vals["total"],
        },
        "doctor": {
            "hypothesis_valid_pct": (doctor_hyp_valid / doctor_total) if doctor_total else None,
            "assignment_gate_applied_pct": (doctor_assignment_gate / doctor_total) if doctor_total else None,
            "decision_distribution": dict(doctor_decisions),
            "methodology_selection_distribution": dict(doctor_method_selection),
            "design_contract_complete_pct": (doctor_design_complete / doctor_total) if doctor_total else None,
            "avg_design_field_coverage": _avg(doctor_design_coverage),
            "top_design_gap_codes": doctor_design_gap_codes.most_common(10),
            "n": doctor_total,
        },
        "commander": {
            "hold_reasons_top": commander_hold_reasons.most_common(10),
            "hold_reason_codes_top": commander_hold_reason_codes.most_common(10),
            "interference_blocks_count": commander_interference_blocks,
            "n": commander_total,
        },
        "ab_observability": {
            "ab_status_distribution": dict(evaluator_ab_status),
            "measurement_state_distribution": dict(evaluator_measurement_state),
            "n": evaluator_total,
        },
    }

    week = args.week_id.strip() or _week_id()
    canonical_out_dir = Path("reports/L2_mgmt") / _weekly_dir_name(week)
    legacy_out_dir = Path("reports/L2_mgmt") / week
    canonical_out_dir.mkdir(parents=True, exist_ok=True)
    legacy_out_dir.mkdir(parents=True, exist_ok=True)

    payload_json = json.dumps(summary, ensure_ascii=False, indent=2)
    out_json = canonical_out_dir / "agent_quality_summary.json"
    out_md = canonical_out_dir / "agent_quality_summary.md"
    # Backward-compat aliases (temporary): some local workflows still expect these paths.
    legacy_json = legacy_out_dir / "agent_quality.json"
    legacy_md = legacy_out_dir / "agent_quality.md"
    out_json.write_text(payload_json, encoding="utf-8")
    legacy_json.write_text(payload_json, encoding="utf-8")

    lines = [
        f"# Agent Quality — {week}",
        "",
        "## Captain",
        f"- issue_coverage_avg: `{summary['captain']['issue_coverage_avg']}`",
        f"- actionability_avg: `{summary['captain']['actionability_avg']}`",
        f"- semantic_score_avg: `{summary['captain']['semantic_score_avg']}`",
        f"- safety_true_pct: `{summary['captain']['safety_true_pct']}`",
        f"- fallback_used_pct: `{summary['captain']['fallback_used_pct']}`",
        "",
        "## LLM Authenticity (Core 3 Agents)",
        f"- all_3_core_agents_real_llm_pct: `{summary['llm_authenticity']['all_3_core_agents_real_llm_pct']}`",
        f"- avg_real_llm_agents_per_run: `{summary['llm_authenticity']['avg_real_llm_agents_per_run']}`",
        f"- avg_llm_path_reached_agents_per_run: `{summary['llm_authenticity']['avg_llm_path_reached_agents_per_run']}`",
        "",
        "## Doctor",
        f"- hypothesis_valid_pct: `{summary['doctor']['hypothesis_valid_pct']}`",
        f"- assignment_gate_applied_pct: `{summary['doctor']['assignment_gate_applied_pct']}`",
        f"- decision_distribution: `{summary['doctor']['decision_distribution']}`",
        f"- methodology_selection_distribution: `{summary['doctor']['methodology_selection_distribution']}`",
        f"- design_contract_complete_pct: `{summary['doctor']['design_contract_complete_pct']}`",
        f"- avg_design_field_coverage: `{summary['doctor']['avg_design_field_coverage']}`",
        f"- top_design_gap_codes: `{summary['doctor']['top_design_gap_codes']}`",
        "",
        "## Commander",
        f"- interference_blocks_count: `{summary['commander']['interference_blocks_count']}`",
        f"- hold_reason_codes_top: `{summary['commander']['hold_reason_codes_top']}`",
        "",
        "## AB Observability (from Evaluator)",
        f"- ab_status_distribution: `{summary['ab_observability']['ab_status_distribution']}`",
        f"- measurement_state_distribution: `{summary['ab_observability']['measurement_state_distribution']}`",
        "",
    ]
    md_text = "\n".join(lines)
    out_md.write_text(md_text, encoding="utf-8")
    legacy_md.write_text(md_text, encoding="utf-8")
    print(
        "ok: agent quality summary written "
        f"canonical={canonical_out_dir} legacy_alias={legacy_out_dir}"
    )


if __name__ == "__main__":
    main()
