#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.artifact_loaders import load_core_agent_artifacts, load_json_optional
from src.agent_llm_auth import (
    captain_llm_auth,
    commander_llm_auth,
    core_agent_llm_authenticity_from_artifacts,
    doctor_llm_auth,
)
from src.paths import (
    ab_preflight_json,
    agent_reasoning_trace_md,
)
from src.status_taxonomy import goal_from_metric


def _load(path: Path) -> dict[str, Any] | None:
    return load_json_optional(path)


def _top_doctor_hypothesis(doctor: dict[str, Any]) -> dict[str, Any]:
    portfolio = doctor.get("hypothesis_portfolio", []) if isinstance(doctor.get("hypothesis_portfolio"), list) else []
    rows = [x for x in portfolio if isinstance(x, dict)]
    rows.sort(key=lambda h: (int(h.get("rank", 9999)) if str(h.get("rank", "")).isdigit() else 9999, -float(h.get("ice_score", 0.0) or 0.0)))
    return rows[0] if rows else {}


def _fmt_list(items: list[str], max_n: int = 5) -> list[str]:
    out = []
    for x in items[:max_n]:
        out.append(f"- {x}")
    if len(items) > max_n:
        out.append(f"- ... (+{len(items)-max_n})")
    return out


def _safe_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _safe_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def build_trace(run_id: str) -> str:
    arts = load_core_agent_artifacts(run_id)
    captain = arts["captain"]
    doctor = arts["doctor"]
    evaluator = arts["evaluator"]
    commander = arts["commander"]
    ab_v2 = None
    exp_id = None
    e_refs = _safe_dict(commander.get("evidence_refs"))
    ab_v2_ref = e_refs.get("ab_report_v2")
    if isinstance(ab_v2_ref, str) and ab_v2_ref:
        ab_v2 = _load(Path(ab_v2_ref))
        if isinstance(ab_v2, dict):
            exp_id = str(ab_v2.get("experiment_id", "") or "").strip() or None
    preflight = None
    if exp_id:
        preflight = _load(ab_preflight_json(run_id, exp_id))

    lines: list[str] = []
    lines.append(f"# Agent Reasoning Trace — {run_id}")
    lines.append("")

    cap_auth = captain_llm_auth(captain)
    cap_model = str(cap_auth["model"])
    cap_fallback = bool(cap_auth["fallback"])
    cap_prov = _safe_dict(cap_auth["provenance"])
    cap_result = _safe_dict(captain.get("result"))
    doc_auth = doctor_llm_auth(doctor)
    doc_model = str(doc_auth["model_used"])
    doc_method_obj = _safe_dict(doc_auth["method"])
    doc_method_prov = _safe_dict(doc_auth["method_provenance"])
    doc_method_selected_by = str(doc_auth["method_selected_by"])
    doc_method_model = str(doc_auth["method_model"])
    doc_method_fallback_reason = str(doc_auth["method_fallback_reason"])
    doc_method_remote_allowed = doc_auth.get("method_remote_allowed")
    doc_summary_local_mock = bool(doc_auth["human_summary_local_mock"])
    doc_dec = str(doctor.get("normalized_decision", doctor.get("decision", "missing")) or "missing").upper()
    doc_ms = str(doctor.get("measurement_state", "missing") or "missing").upper()
    eval_dec = str(evaluator.get("decision", "missing") or "missing").upper()
    eval_ab_status = str(evaluator.get("ab_status", "missing") or "missing").upper()
    cmd_dec = str(commander.get("normalized_decision", commander.get("decision", "missing")) or "missing").upper()
    cmd_auth = commander_llm_auth(commander)
    cmd_model = str(cmd_auth["commander_model"])
    cmd_prov = _safe_dict(cmd_auth["provenance"])
    cmd_align = _safe_dict(commander.get("llm_decision_alignment"))
    cmd_merge = _safe_dict(commander.get("decision_merge_provenance"))
    cap_real_llm = bool(cap_auth["real_llm"])
    cap_llm_path_reached = bool(cap_auth["llm_path_reached"])
    doc_real_llm_core = bool(doc_auth["real_llm"])
    doc_llm_path_reached = bool(doc_auth["llm_path_reached"])
    cmd_real_llm = bool(cmd_auth["real_llm"])
    cmd_llm_path_reached = bool(cmd_auth["llm_path_reached"])
    core_auth = core_agent_llm_authenticity_from_artifacts(run_id, captain, doctor, commander)
    real_llm_agents_count = int(core_auth.get("real_llm_agents_count", 0))
    llm_path_reached_agents_count = int(core_auth.get("llm_path_reached_agents_count", 0))
    simulated_agents_count = 3 - real_llm_agents_count

    lines.append("## Overview")
    lines.append(f"- Captain: model=`{cap_model}`, fallback=`{cap_fallback}`, verdict=`{cap_result.get('verdict')}`")
    lines.append(
        f"- Doctor: model_used=`{doc_model}`, method_selected_by=`{doc_method_selected_by}`, "
        f"decision=`{doc_dec}`, measurement_state=`{doc_ms}`"
    )
    lines.append(f"- Evaluator: decision=`{eval_dec}`, ab_status=`{eval_ab_status}`")
    lines.append(f"- Commander: model=`{cmd_model}`, final_decision=`{cmd_dec}`, remote_allowed=`{cmd_prov.get('remote_allowed')}`, fallback=`{cmd_prov.get('used_fallback')}`")
    if cmd_prov.get("fallback_reason"):
        lines.append(f"- Commander fallback_reason: `{cmd_prov.get('fallback_reason')}`")
    lines.append("")

    lines.append("## LLM Reality Check (Core 3 Agents)")
    lines.append("- Purpose: distinguish (1) LLM/API path was reached vs (2) core LLM output was accepted after schema/validator checks.")
    lines.append("- `LLM Path Reached`: the agent called a real LLM backend (e.g., Groq) and received a response.")
    lines.append("- `Core LLM Accepted`: the response passed JSON/schema/contract validators and was used as the agent's authoritative core output (not fallback).")
    lines.append(f"- llm_path_reached_agents_count: `{llm_path_reached_agents_count}` / `3`")
    lines.append(f"- effective_real_llm_agents_count: `{real_llm_agents_count}` / `3`")
    lines.append(f"- simulated_or_fallback_agents_count: `{simulated_agents_count}` / `3`")
    if simulated_agents_count > 0:
        lines.append("- interpretation: This run is not a full proof run yet; at least one core agent used local fallback or deterministic fallback path.")
    lines.append("")
    lines.append("| Agent | LLM Path Reached | Core LLM Accepted | Model (Actual/Intent) | Remote Allowed | Fallback | Notes |")
    lines.append("|---|---|---|---|---|---|---|")
    lines.append(
        f"| Captain | {'YES' if cap_llm_path_reached else 'NO'} | {'YES' if cap_real_llm else 'NO'} | `{cap_prov.get('selected_model_before_fallback') or cap_prov.get('model') or cap_model}` | `{cap_prov.get('remote_allowed', 'unknown')}` | `{cap_fallback}` | "
        f"{'local_mock or runtime fallback' if not cap_real_llm else 'core sanity output from LLM'} |"
    )
    doc_notes = []
    if doc_method_selected_by != "doctor_llm_validated":
        doc_notes.append(f"methodology via {doc_method_selected_by}")
    if doc_method_fallback_reason:
        doc_notes.append(f"fallback_reason={doc_method_fallback_reason}")
    if doc_summary_local_mock:
        doc_notes.append("human_summary local_mock")
    if not doc_notes:
        doc_notes.append("Doctor methodology validated by LLM")
    lines.append(
        f"| Doctor | {'YES' if doc_llm_path_reached else 'NO'} | {'YES' if doc_real_llm_core else 'NO'} | `{doc_method_prov.get('actual_model') or doc_method_model}` (method), intent=`{doc_model}` | "
        f"`{doc_method_remote_allowed if doc_method_remote_allowed is not None else 'unknown'}` | `{doc_method_selected_by != 'doctor_llm_validated'}` | {'; '.join(doc_notes)} |"
    )
    lines.append(
        f"| Commander | {'YES' if cmd_llm_path_reached else 'NO'} | {'YES' if cmd_real_llm else 'NO'} | `{cmd_prov.get('model') or cmd_model}` | "
        f"`{cmd_prov.get('remote_allowed')}` | `{cmd_prov.get('used_fallback')}` | "
        f"{str(cmd_prov.get('fallback_reason') or 'decision proposal LLM path active')} |"
    )
    lines.append("")

    lines.append("## Captain (Agent 1)")
    cap_issues = _safe_list(cap_result.get("issues"))
    cap_recs = _safe_list(cap_result.get("recommendations"))
    lines.append(f"- verdict: `{cap_result.get('verdict')}`")
    lines.append(f"- issue_count: `{len(cap_issues)}`")
    if cap_prov:
        lines.append(f"- llm_remote_allowed: `{cap_prov.get('remote_allowed')}`")
        lines.append(f"- llm_fallback_reason: `{cap_prov.get('fallback_reason')}`")
        cap_repairs = [str(x) for x in _safe_list(cap_prov.get("repair_actions")) if str(x).strip()]
        if cap_repairs:
            lines.append("- llm_repair_actions:")
            for r in cap_repairs[:8]:
                lines.append(f"  - {r}")
    if cap_issues:
        lines.append("- top_issues:")
        for issue in cap_issues[:5]:
            if isinstance(issue, dict):
                lines.append(f"  - `{issue.get('check_name')}` [{issue.get('severity')}]: {issue.get('message')}")
            else:
                lines.append(f"  - {issue}")
    if cap_recs:
        lines.append("- recommendations:")
        for rec in cap_recs[:5]:
            lines.append(f"  - {rec}")
    lines.append("")

    lines.append("## Doctor (Agent 2)")
    lines.append(f"- decision: `{doc_dec}`")
    lines.append(f"- measurement_state: `{doc_ms}`")
    top_h = _top_doctor_hypothesis(doctor)
    if top_h:
        top_goal = goal_from_metric(str(top_h.get("target_metric")))
        lines.append(f"- top_hypothesis_goal: `{top_goal}`")
        lines.append(f"- top_hypothesis_metric: `{top_h.get('target_metric')}`")
        lines.append(f"- top_hypothesis_statement: {top_h.get('hypothesis_statement')}")
        mech = _safe_list(top_h.get("mechanism"))
        if mech:
            lines.append("- top_hypothesis_mechanism:")
            for m in mech[:4]:
                lines.append(f"  - {m}")
    doc_reasons = _safe_list(doctor.get("reasons"))
    if doc_reasons:
        lines.append("- reasons:")
        for r in doc_reasons[:6]:
            if isinstance(r, dict):
                lines.append(f"  - `{r.get('code')}` [{r.get('severity')}]: {r.get('message')}")
            else:
                lines.append(f"  - {r}")
    doc_method = _safe_dict(doctor.get("ab_interpretation_methodology"))
    doc_method_sum = _safe_dict(doctor.get("statistical_methodology_summary"))
    if doc_method or doc_method_sum:
        m = doc_method or doc_method_sum
        prov = _safe_dict(m.get("selection_provenance")) if doc_method else {}
        lines.append("- methodology (current AB interpretation):")
        lines.append(f"  - selected_by: `{prov.get('selected_by') or m.get('selected_by')}`")
        lines.append(f"  - test_family: `{m.get('test_family')}`")
        lines.append(f"  - principle: `{m.get('statistical_principle')}`")
        lines.append(f"  - reason: {m.get('reason_selected')}")
        if (prov.get("fallback_reason") or m.get("fallback_reason")):
            lines.append(f"  - fallback_reason: `{prov.get('fallback_reason') or m.get('fallback_reason')}`")
        vobj = _safe_dict(m.get("validation"))
        vissues = [str(x) for x in _safe_list(vobj.get("issues")) if str(x).strip()]
        if vissues:
            lines.append("  - validator_notes:")
            for v in vissues[:8]:
                lines.append(f"    - {v}")
    fix = _safe_dict(doctor.get("measurement_fix_plan"))
    if fix:
        lines.append("- measurement_fix_plan:")
        for step in _safe_list(fix.get("minimal_steps"))[:4]:
            lines.append(f"  - {step}")
    lines.append("")

    lines.append("## Commander (Agent 3)")
    lines.append(f"- final_decision: `{cmd_dec}`")
    lines.append(f"- llm_model: `{cmd_model}`")
    lines.append(f"- llm_remote_allowed: `{cmd_prov.get('remote_allowed')}`")
    lines.append(f"- llm_used_fallback: `{cmd_prov.get('used_fallback')}`")
    if cmd_prov.get("fallback_reason"):
        lines.append(f"- llm_fallback_reason: `{cmd_prov.get('fallback_reason')}`")
    cmd_vissues = [str(x) for x in _safe_list(cmd_prov.get("validation_issues")) if str(x).strip()]
    if cmd_vissues:
        lines.append("- llm_validation_issues:")
        for v in cmd_vissues[:8]:
            lines.append(f"  - {v}")
    cmd_repairs = [str(x) for x in _safe_list(cmd_prov.get("repair_actions")) if str(x).strip()]
    if cmd_repairs:
        lines.append("- llm_repair_actions:")
        for r in cmd_repairs[:8]:
            lines.append(f"  - {r}")
    llm_prop = _safe_dict(commander.get("llm_decision_proposal"))
    if llm_prop:
        lines.append(f"- llm_proposed_decision: `{llm_prop.get('proposed_decision')}` (confidence=`{llm_prop.get('confidence')}`)")
        lines.append(f"- llm_rationale: {llm_prop.get('decision_rationale')}")
        for sec_name, key in [
            ("causal_chain_summary", "causal_chain_summary"),
            ("human_loop_checks", "human_loop_checks"),
            ("what_would_change_my_mind", "what_would_change_my_mind"),
            ("requested_data", "requested_data"),
        ]:
            vals = [str(x) for x in _safe_list(llm_prop.get(key)) if str(x).strip()]
            if vals:
                lines.append(f"- {sec_name}:")
                for v in vals[:5]:
                    lines.append(f"  - {v}")
    else:
        lines.append("- llm_proposed_decision: `none` (fallback path)")
    if cmd_align:
        lines.append(f"- llm_vs_final_match: `{cmd_align.get('matches_final')}`")
    if cmd_merge:
        lines.append(f"- decision_merge_source: `{cmd_merge.get('merge_source')}`")
        for n in _safe_list(cmd_merge.get("notes"))[:4]:
            lines.append(f"  - merge_note: {n}")
    cmd_method = _safe_dict(commander.get("methodology_check"))
    if cmd_method:
        lines.append("- methodology_check:")
        lines.append(f"  - ab_status=`{cmd_method.get('ab_status')}` measurement_state=`{cmd_method.get('measurement_state')}`")
        lines.append(f"  - goal_metric_alignment_ok=`{cmd_method.get('goal_metric_alignment_ok')}` unit_alignment_ok=`{cmd_method.get('unit_alignment_ok')}`")
        lines.append(f"  - stats_consistent=`{cmd_method.get('stats_consistent')}` decision_rule_result=`{cmd_method.get('decision_rule_result')}`")
        errs = [str(x) for x in _safe_list(cmd_method.get("errors")) if str(x).strip()]
        if errs:
            lines.append("  - errors:")
            for e in errs[:6]:
                lines.append(f"    - {e}")
    drs = _safe_list(commander.get("data_requests"))
    cohort_info = _safe_dict(commander.get("cohort_analysis"))
    if cohort_info:
        lines.append("- cohort_analysis:")
        lines.append(f"  - status: `{cohort_info.get('status')}`")
        notes = [str(x) for x in _safe_list(cohort_info.get("notes")) if str(x).strip()]
        if notes:
            lines.append("  - notes:")
            for n in notes[:4]:
                lines.append(f"    - {n}")
        cuts = _safe_list(cohort_info.get("cuts"))
        if cuts:
            lines.append("  - cuts:")
            for cut in cuts[:4]:
                if not isinstance(cut, dict):
                    continue
                summ = _safe_dict(cut.get("summary"))
                lines.append(
                    f"    - `{cut.get('cut_name')}` rows=`{cut.get('row_count', len(_safe_list(cut.get('rows'))))}` "
                    f"buckets_with_both_arms=`{summ.get('buckets_with_both_arms')}` "
                    f"max_abs_delta_pct_on_mean_gmv=`{summ.get('max_abs_delta_pct_on_mean_gmv')}`"
                )
                sample_rows = _safe_list(cut.get("sample_rows"))
                for sr in sample_rows[:2]:
                    if isinstance(sr, dict):
                        lines.append(
                            "      - sample: bucket={bucket}, arm={arm}, n={n}, mean_gmv={gmv}, mean_orders={ord}".format(
                                bucket=sr.get("bucket"),
                                arm=sr.get("arm"),
                                n=sr.get("n_customers"),
                                gmv=sr.get("mean_gmv"),
                                ord=sr.get("mean_orders_cnt"),
                            )
                        )
    if drs:
        lines.append("- data_requests:")
        for r in drs[:6]:
            if isinstance(r, dict):
                lines.append(f"  - `{r.get('request_id')}` ({r.get('priority')}): {r.get('why')}")
    lines.append("")

    lines.append("## Inter-Agent Deliberation (Reconstructed Visible Dialogue)")
    lines.append("- This is a reconstructed handoff dialogue from visible artifact outputs (not hidden chain-of-thought).")
    lines.append("")
    lines.append("### Turn 1 — Captain -> Doctor")
    lines.append(f"- Captain verdict: `{cap_result.get('verdict')}`")
    if cap_fallback:
        lines.append("- Captain note: local fallback was used, so DQ reasoning depth is reduced for this run.")
    if cap_issues:
        lines.append("- Captain to Doctor (top signals):")
        for issue in cap_issues[:3]:
            if isinstance(issue, dict):
                lines.append(
                    f"  - `{issue.get('check_name')}` [{issue.get('severity')}]: {issue.get('message')}"
                )
    if cap_recs:
        lines.append("- Captain asks Doctor to preserve safety constraints while evaluating hypotheses:")
        for rec in cap_recs[:3]:
            lines.append(f"  - {rec}")
    lines.append("")
    lines.append("### Turn 2 — Doctor -> Commander")
    lines.append(f"- Doctor decision: `{doc_dec}` (measurement_state=`{doc_ms}`)")
    if top_h:
        lines.append(
            f"- Doctor hypothesis proposal: metric=`{top_h.get('target_metric')}`, goal=`{goal_from_metric(str(top_h.get('target_metric')) )}`, "
            f"statement={top_h.get('hypothesis_statement')}"
        )
    if doc_method or doc_method_sum:
        m = doc_method or doc_method_sum
        lines.append(
            f"- Doctor methodology choice: `{(m.get('test_family') or 'missing')}` / "
            f"`{(m.get('statistical_principle') or 'missing')}` via `{doc_method_selected_by}`"
        )
        if doc_method_fallback_reason:
            lines.append(f"- Doctor methodology caution: fallback reason=`{doc_method_fallback_reason}`")
    if doc_reasons:
        lines.append("- Doctor rationale to Commander (top reasons):")
        for r in doc_reasons[:4]:
            if isinstance(r, dict):
                lines.append(f"  - `{r.get('code')}` [{r.get('severity')}]: {r.get('message')}")
            else:
                lines.append(f"  - {r}")
    lines.append("")
    lines.append("### Turn 3 — Commander -> Human (HITL)")
    lines.append(f"- Commander final decision: `{cmd_dec}`")
    if llm_prop:
        lines.append(
            f"- Commander LLM proposal: `{llm_prop.get('proposed_decision')}` "
            f"(confidence=`{llm_prop.get('confidence')}`)"
        )
        if llm_prop.get("decision_rationale"):
            lines.append(f"- Commander reasoning summary: {llm_prop.get('decision_rationale')}")
    else:
        lines.append("- Commander LLM proposal unavailable (fallback or older artifact path).")
    if cmd_align:
        lines.append(f"- LLM vs final alignment: `{cmd_align.get('matches_final')}`")
    if drs:
        lines.append("- Commander requests before decision upgrade:")
        for r in drs[:4]:
            if isinstance(r, dict):
                lines.append(f"  - `{r.get('request_id')}` ({r.get('priority')}): {r.get('why')}")
            else:
                lines.append(f"  - {r}")
    elif cmd_method and _safe_list(cmd_method.get("errors")):
        lines.append("- Commander blockers (methodology/data):")
        for e in [str(x) for x in _safe_list(cmd_method.get("errors"))[:4]]:
            lines.append(f"  - {e}")
    lines.append("")

    lines.append("## AB / Preflight")
    if isinstance(preflight, dict):
        lines.append(f"- preflight_status: `{preflight.get('status')}` error_code=`{preflight.get('error_code')}` error_family=`{preflight.get('error_family')}`")
        if preflight.get("error_detail"):
            lines.append(f"- preflight_error_detail: {preflight.get('error_detail')}")
    else:
        lines.append("- preflight: missing")
    if isinstance(ab_v2, dict):
        m = _safe_dict(ab_v2.get("methodology"))
        lines.append(f"- ab_v2_status: `{ab_v2.get('status')}`")
        lines.append(f"- ab_v2_method_selected_by: `{m.get('selected_by')}`")
        if m.get("fallback_reason"):
            lines.append(f"- ab_v2_method_fallback_reason: `{m.get('fallback_reason')}`")
    else:
        lines.append("- ab_v2: missing")
    lines.append("")

    lines.append("## Handoff Frictions (This Run)")
    frictions: list[str] = []
    if cap_fallback:
        frictions.append("Captain used local fallback (`local_mock`).")
    if not doc_real_llm_core:
        frictions.append("Doctor core methodology path was not LLM-validated for this run.")
    if not cmd_real_llm:
        frictions.append("Commander decision proposal path used local fallback / non-LLM path.")
    if doc_dec != cmd_dec:
        frictions.append(f"Doctor decision `{doc_dec}` differs from Commander final `{cmd_dec}`.")
    if eval_dec != cmd_dec:
        frictions.append(f"Evaluator decision `{eval_dec}` differs from Commander final `{cmd_dec}`.")
    if cmd_method.get("goal_metric_alignment_ok") is False:
        frictions.append("Commander flagged goal/metric misalignment (hard stop path).")
    cohort = _safe_dict(commander.get("cohort_analysis"))
    if str(cohort.get("status", "")).upper() == "BLOCKED_BY_DATA":
        frictions.append("Cohort analysis blocked (missing cohort evidence tables).")
    if not doctor.get("ab_interpretation_methodology"):
        frictions.append("Doctor missing current-AB methodology artifact (older run or pre-patch artifact).")
    if preflight and str(preflight.get("status", "")).upper() == "FAIL":
        frictions.append(f"AB preflight failed with `{preflight.get('error_code')}`.")
    if frictions:
        lines.extend(_fmt_list(frictions, max_n=10))
    else:
        lines.append("- none detected by artifact checks")
    lines.append("")

    lines.append("## Paths")
    lines.append(f"- Captain JSON: `data/llm_reports/{run_id}_captain.json`")
    lines.append(f"- Doctor JSON: `data/agent_reports/{run_id}_doctor_variance.json`")
    lines.append(f"- Evaluator JSON: `data/agent_reports/{run_id}_experiment_evaluator.json`")
    lines.append(f"- Commander JSON: `data/agent_reports/{run_id}_commander_priority.json`")
    if exp_id:
        lines.append(f"- AB Preflight JSON: `data/ab_preflight/{run_id}_{exp_id}_preflight.json`")
        lines.append(f"- AB v2 JSON: `data/ab_reports/{run_id}_{exp_id}_ab_v2.json`")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build per-run agent reasoning trace (Captain/Doctor/Commander)")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    out = agent_reasoning_trace_md(args.run_id)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_trace(args.run_id) + "\n", encoding="utf-8")
    print(f"ok: agent reasoning trace written for run_id={args.run_id}")


if __name__ == "__main__":
    main()
