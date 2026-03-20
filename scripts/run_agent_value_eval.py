#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]


def _redact(text: str) -> str:
    out = text
    for p, repl in REDACTION_PATTERNS:
        out = p.sub(repl, out)
    return out


def _safe_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(json.dumps(payload, ensure_ascii=False, indent=2)), encoding="utf-8")
    write_sha256_sidecar(path)


def _safe_write_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(text), encoding="utf-8")


def _load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _f(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _ratio(num: float, den: float) -> float:
    if den <= 0:
        return 0.0
    return max(0.0, min(1.0, num / den))


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def _i(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except Exception:
        return int(default)


def _collect_real_outcomes_from_history(run_id: str) -> tuple[list[dict[str, Any]], list[str], int]:
    rows: list[dict[str, Any]] = []
    refs: list[str] = []
    label_window_days_max = 0
    seen_ids: set[str] = set()
    run_tokens = [t for t in str(run_id).split("_") if t]
    scope_prefix = "_".join(run_tokens[:3]) if len(run_tokens) >= 3 else (run_tokens[0] if run_tokens else str(run_id))
    allowed_decisions = {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}

    for path in sorted(Path("data/agent_eval").glob("*_decision_outcomes_ledger.json")):
        if path.name == f"{run_id}_decision_outcomes_ledger.json":
            continue
        ok, _ = verify_sha256_sidecar(path, required=True)
        if not ok:
            continue
        payload = _load(path)
        if not isinstance(payload, dict):
            continue
        payload_run_id = str(payload.get("run_id", "")).strip()
        if payload_run_id and scope_prefix and not payload_run_id.startswith(scope_prefix):
            # Anti-dirty policy: keep only historical outcomes from same run family.
            continue
        source_outcomes = payload.get("outcomes", []) if isinstance(payload.get("outcomes"), list) else []
        if not source_outcomes:
            continue
        label_window_days_max = max(label_window_days_max, _i(payload.get("label_window_days"), 0))
        refs.append(f"artifact:{path}")
        for row in source_outcomes:
            if not isinstance(row, dict):
                continue
            decision_id = str(row.get("decision_id", "")).strip()
            if not decision_id:
                continue
            decision = str(row.get("decision", "")).strip().upper()
            if decision not in allowed_decisions:
                continue
            if decision_id in seen_ids:
                continue
            seen_ids.add(decision_id)
            rows.append(
                {
                    "decision_id": decision_id,
                    "decision": decision,
                    "actual_outcome": str(row.get("actual_outcome", "")).strip(),
                    "prevented_loss": bool(row.get("prevented_loss", False)),
                    "regret": bool(row.get("regret", False)),
                }
            )
    return rows, sorted(set(refs)), int(label_window_days_max)


def _refs_have_numeric_values(refs: Any) -> bool:
    if not isinstance(refs, list):
        return False
    for ref in refs:
        if isinstance(ref, dict):
            for key in ("value", "fact", "baseline", "control", "treatment", "delta", "delta_pct"):
                val = ref.get(key)
                if isinstance(val, (int, float)):
                    return True
                try:
                    if val is not None and str(val).strip() != "":
                        float(val)
                        return True
                except Exception:
                    pass
        else:
            txt = str(ref)
            if re.search(r"-?\d+(\.\d+)?", txt):
                return True
    return False


def _goal_from_metric(metric: str) -> str:
    m = (metric or "").strip().lower()
    if m in {"aov", "goal2_aov"}:
        return "goal2"
    if m in {"writeoff_rate_adj", "goal1_writeoff", "writeoff_units", "writeoff_cogs"}:
        return "goal1"
    if m in {"buyers", "goal3_buyers", "new_buyers_7d", "active_buyers_avg"}:
        return "goal3"
    return "unknown"


def _extract_flagged_metrics(captain: dict[str, Any], synthetic_bias: dict[str, Any]) -> set[str]:
    metric_candidates = {
        "fill_rate_units",
        "oos_lost_gmv_rate",
        "lost_gmv_oos",
        "writeoff_cogs",
        "writeoff_rate_vs_requested_units",
        "writeoff_units",
        "gp_margin",
        "gmv",
        "aov",
        "active_buyers_avg",
        "new_buyers_7d",
        "churn_rate",
    }
    hits: set[str] = set()
    issues = ((captain.get("result") or {}).get("issues") if isinstance(captain.get("result"), dict) else []) or []
    if isinstance(issues, list):
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            blob = f"{issue.get('check_name', '')} {issue.get('message', '')}".lower()
            for metric in metric_candidates:
                if metric in blob:
                    hits.add(metric)
    findings = synthetic_bias.get("findings", []) if isinstance(synthetic_bias.get("findings"), list) else []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        blob = f"{finding.get('type', '')} {finding.get('message', '')} {finding.get('path', '')}".lower()
        for metric in metric_candidates:
            if metric in blob:
                hits.add(metric)
    signals = synthetic_bias.get("signals", []) if isinstance(synthetic_bias.get("signals"), list) else []
    for sig in signals:
        if not isinstance(sig, dict):
            continue
        blob = f"{sig.get('check_name', '')} {sig.get('message', '')}".lower()
        for metric in metric_candidates:
            if metric in blob:
                hits.add(metric)
    return hits


def _collect_visible_trace_claims(payload: dict[str, Any]) -> list[dict[str, Any]]:
    trace = payload.get("visible_reasoning_trace", {}) if isinstance(payload.get("visible_reasoning_trace"), dict) else {}
    claims = trace.get("claims", []) if isinstance(trace.get("claims"), list) else []
    return [c for c in claims if isinstance(c, dict)]


def _claim_trace_complete(claim: dict[str, Any]) -> bool:
    statement = str(claim.get("statement", "")).strip()
    refs = claim.get("evidence_refs", [])
    alternatives = claim.get("alternatives_considered", [])
    falsifiability = str(claim.get("falsifiability_test", "")).strip()
    return bool(
        statement
        and isinstance(refs, list)
        and len(refs) >= 1
        and isinstance(alternatives, list)
        and len(alternatives) >= 1
        and falsifiability
    )


def _falsifiability_is_specific(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    has_number = bool(re.search(r"-?\d+(?:\.\d+)?%?", text))
    has_threshold = bool(re.search(r"(>=|<=|>|<|\bbetween\b|\bat least\b|\bno more than\b)", text))
    has_test_hint = any(k in text for k in ("select ", " where ", "metric", "p_value", "ci", "threshold", "delta", "compare"))
    return has_number and has_threshold and has_test_hint


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent value eval scoring")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    captain = _load(Path(f"data/llm_reports/{run_id}_captain.json")) or {}
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
    evaluator = _load(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")) or {}
    commander = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}
    narrative = _load(Path(f"data/agent_reports/{run_id}_narrative_claims.json")) or _load(Path(f"reports/L1_ops/{run_id}/causal_claims.json")) or {}
    validation = _load(Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json")) or {}
    synthetic_bias = _load(Path(f"data/realism_reports/{run_id}_synthetic_bias.json")) or {}
    approvals = _load(Path(f"data/agent_governance/{run_id}_agent_approvals.json")) or _load(Path(f"data/governance/approvals_{run_id}.json")) or {}
    adversarial = _load(Path(f"data/eval/adversarial_suite_{run_id}.json")) or {}
    vector_quality = _load(Path(f"data/agent_reports/{run_id}_vector_quality.json")) or {}
    ab_v2 = {}
    ab_v2_candidates = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab_v2.json"))
    if ab_v2_candidates:
        ab_v2 = _load(ab_v2_candidates[0]) or {}
    ab_v1 = {}
    ab_v1_candidates = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab.json"))
    if ab_v1_candidates:
        ab_v1 = _load(ab_v1_candidates[0]) or {}
    ab_stat_report_path = Path(f"reports/L1_ops/{run_id}/AB_STAT_REPORT.md")
    ab_stat_report_text = ab_stat_report_path.read_text(encoding="utf-8") if ab_stat_report_path.exists() else ""
    decision_card_path = Path(f"reports/L1_ops/{run_id}/decision_card.md")
    decision_card_text = decision_card_path.read_text(encoding="utf-8") if decision_card_path.exists() else ""
    metrics = ((_load(Path(f"data/metrics_snapshots/{run_id}.json")) or {}).get("metrics", {}) if isinstance((_load(Path(f"data/metrics_snapshots/{run_id}.json")) or {}).get("metrics"), dict) else {})
    action_trace = Path(f"data/decision_traces/{run_id}_actions.jsonl")
    ab = {}
    ab_candidates = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab.json"))
    if ab_candidates:
        ab = _load(ab_candidates[0]) or {}

    appr_rows = approvals.get("proposal_rows", approvals.get("approvals", []))
    if not isinstance(appr_rows, list):
        appr_rows = []
    governance_status = str(approvals.get("governance_status", "")).strip().lower()
    ab_stat_report_text_l = ab_stat_report_text.lower()
    decision_card_text_l = decision_card_text.lower()

    cap_eval = captain.get("eval_metrics", {}) if isinstance(captain.get("eval_metrics"), dict) else {}
    cap_cov = _f(cap_eval.get("issue_coverage"))
    cap_issues = ((captain.get("result") or {}).get("issues", []) if isinstance(captain.get("result"), dict) else [])
    cap_issues = cap_issues if isinstance(cap_issues, list) else []
    cap_total = max(1, len(cap_issues))
    cap_extra = sum(1 for i in cap_issues if isinstance(i, dict) and str(i.get("severity", "")).upper() == "INFO")
    cap_fp = _ratio(cap_extra, cap_total)
    cap_realism_fixes = sum(1 for r in appr_rows if isinstance(r, dict) and str(r.get("agent")) == "captain" and str(r.get("decision", "")).upper() == "APPROVE")
    cap_evidence_density = _ratio(sum(1 for i in cap_issues if isinstance(i, dict) and str(i.get("message", "")).strip()), cap_total)
    cap_safety = 1.0 if bool(cap_eval.get("safety", False)) else 0.0
    captain_score = _clamp(0.35*cap_cov + 0.20*cap_evidence_density + 0.20*_ratio(cap_realism_fixes,3) + 0.15*cap_safety - 0.10*cap_fp)

    ab_plan = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
    hypothesis_portfolio = doctor.get("hypothesis_portfolio", []) if isinstance(doctor.get("hypothesis_portfolio"), list) else []
    hyps = [h for h in hypothesis_portfolio if isinstance(h, dict)]
    hyp_generated = len(hyps)
    hyp_approved = sum(
        1
        for r in appr_rows
        if isinstance(r, dict)
        and str(r.get("agent")) == "doctor"
        and str(r.get("proposal_type")) == "hypothesis"
        and str(r.get("decision", "")).upper() == "APPROVE"
    )
    hyp_review_rows = [
        r
        for r in appr_rows
        if isinstance(r, dict) and str(r.get("agent")) == "doctor" and str(r.get("proposal_type")) == "hypothesis"
    ]
    review_pending_count = 1 if (governance_status == "missing_review" and len(hyp_review_rows) == 0) else 0
    uniq_h = len({str(h.get("hypothesis_id", "")).strip() for h in hyps if str(h.get("hypothesis_id", "")).strip()})
    lever_types = {str(h.get("lever_type", "")).strip().lower() for h in hyps if str(h.get("lever_type", "")).strip()}
    target_metrics = {str(h.get("target_metric", "")).strip().lower() for h in hyps if str(h.get("target_metric", "")).strip()}
    diversity_levers = min(1.0, _ratio(len(lever_types), 2))
    diversity_targets = min(1.0, _ratio(len(target_metrics), 2))
    portfolio_diversity = 0.5 * diversity_levers + 0.5 * diversity_targets
    methodology_complete = _ratio(
        sum(
            1
            for h in hyps
            if str(h.get("hypothesis_statement", "")).strip()
            and isinstance(h.get("evidence_refs"), list)
            and len(h.get("evidence_refs", [])) >= 2
            and str(h.get("falsifiability_condition", "")).strip()
        ),
        max(1, len(hyps)),
    )
    measurement_fix_plan_present = 1.0 if isinstance(doctor.get("measurement_fix_plan"), dict) else 0.0
    flagged_metrics = _extract_flagged_metrics(captain, synthetic_bias)
    aligned_hypotheses = 0
    for h in hyps:
        if not isinstance(h, dict):
            continue
        refs = h.get("evidence_refs", [])
        if not isinstance(refs, list):
            continue
        ref_blob_parts: list[str] = []
        for ref in refs:
            if isinstance(ref, dict):
                ref_blob_parts.append(str(ref.get("metric", "")))
                ref_blob_parts.append(str(ref.get("value", "")))
                ref_blob_parts.append(str(ref.get("field", "")))
            else:
                ref_blob_parts.append(str(ref))
        blob = " ".join(ref_blob_parts).lower()
        if any(m in blob for m in flagged_metrics):
            aligned_hypotheses += 1
    if not flagged_metrics:
        flagged_metric_alignment_status = "N/A"
        flagged_metric_alignment_rate = None
    else:
        flagged_metric_alignment_rate = _ratio(aligned_hypotheses, max(1, len(hyps)))
        flagged_metric_alignment_status = "PASS" if aligned_hypotheses >= 1 else "FAIL"
    ab_status = str((ab_v2.get("status") if isinstance(ab_v2, dict) and ab_v2.get("status") else evaluator.get("ab_status", ""))).upper()
    ab_observable = 0.0 if ab_status in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "INVALID", "INVALID_METHODS", ""} else 1.0
    eval_dec = str(evaluator.get("decision", "")).upper()
    ab_success = 1.0 if (ab_observable > 0 and eval_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"}) else 0.0
    underpowered = 1.0 if ab_status == "UNDERPOWERED" else 0.0
    mismatch = 1.0 if ab_status == "METHODOLOGY_MISMATCH" else 0.0
    guardrail_awareness = 1.0 if (_f(metrics.get("fill_rate_units")) >= 0.90 or _f(metrics.get("writeoff_rate_vs_requested_units")) >= 0.02) else 0.4
    blocked_statuses = {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "ASSIGNMENT_RECOVERED", "INVALID_METHODS"}
    ratio_metrics = {"gp_margin", "fill_rate_units", "oos_lost_gmv_rate", "writeoff_rate_vs_requested_units"}
    alpha = 0.05
    ab_summary = ab_v1.get("summary", {}) if isinstance(ab_v1.get("summary"), dict) else {}
    ab_v2_primary = ab_v2.get("primary_metric", {}) if isinstance(ab_v2.get("primary_metric"), dict) else {}
    ab_primary_metric_name = str(
        (ab_v2_primary.get("name") if isinstance(ab_v2_primary, dict) else None)
        or ab_summary.get("primary_metric")
        or ""
    ).strip()
    ab_method_name = str(ab_v2.get("method_name", "")).strip().lower()
    p_value_val = ab_v2_primary.get("p_value", ab_summary.get("primary_metric_p_value"))
    ci_val = ab_v2_primary.get("ci95", ab_summary.get("primary_metric_uplift_ci95"))
    ci_contains_zero = None
    try:
        if isinstance(ci_val, list) and len(ci_val) == 2:
            lo = float(ci_val[0])
            hi = float(ci_val[1])
            ci_contains_zero = lo <= 0.0 <= hi
    except Exception:
        ci_contains_zero = None
    try:
        p_float = float(p_value_val)
    except Exception:
        p_float = None

    reject_h0_in_ab_report = bool(re.search(r"(?i)\\breject h0\\b", ab_stat_report_text)) and not bool(
        re.search(r"(?i)\\bfail to reject h0\\b", ab_stat_report_text)
    )
    reject_h0_in_decision_card = bool(re.search(r"(?i)\\breject h0\\b", decision_card_text)) and not bool(
        re.search(r"(?i)\\bfail to reject h0\\b", decision_card_text)
    )

    # Fatal checks
    math_contradiction = False
    if p_float is not None and ci_contains_zero is not None:
        math_contradiction = ((p_float > alpha) and (ci_contains_zero is False)) or ((p_float <= alpha) and (ci_contains_zero is True))
    # Text-level contradiction guard: report language must match computed p-value/CI.
    if p_float is not None and reject_h0_in_ab_report and p_float > alpha:
        math_contradiction = True
    if p_float is not None and reject_h0_in_decision_card and p_float > alpha:
        math_contradiction = True
    if ci_contains_zero is not None and ("ci excludes 0" in ab_stat_report_text_l) and ci_contains_zero and reject_h0_in_ab_report:
        math_contradiction = True
    wrong_method_for_ratio = bool(ab_primary_metric_name in ratio_metrics and ("bootstrap" not in ab_method_name and "delta" not in ab_method_name))
    reject_h0_with_p_gt_alpha = bool(p_float is not None and p_float > alpha and (reject_h0_in_ab_report or reject_h0_in_decision_card))
    uplift_claimed_while_unobservable = False
    if ab_status in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "ASSIGNMENT_RECOVERED"}:
        primary_u = ab_v2_primary.get("uplift", ab_summary.get("primary_metric_uplift"))
        if primary_u is not None:
            uplift_claimed_while_unobservable = True
    rec_exp = doctor.get("recommended_experiment", {}) if isinstance(doctor.get("recommended_experiment"), dict) else {}
    rec_goal = _goal_from_metric(str(rec_exp.get("primary_metric", "")))
    ab_goal = _goal_from_metric(str(ab_primary_metric_name))
    mismatch_exists = bool(rec_goal != "unknown" and ab_goal != "unknown" and rec_goal != ab_goal)
    mismatch_flagged_fatal = ("fatal" in ab_stat_report_text_l and "misalignment" in ab_stat_report_text_l) or ("fatal" in decision_card_text_l and "misalignment" in decision_card_text_l) or str(ab_status).upper() == "INVALID_METHODS"
    misalignment_ignored = bool(mismatch_exists and str(doctor.get("normalized_decision", doctor.get("decision", ""))).upper() not in {"STOP", "HOLD_RISK", "HOLD_NEED_DATA"})
    goal_metric_misalignment_not_flagged_fatal = bool(mismatch_exists and not mismatch_flagged_fatal)
    valid_ab_numbers_when_invalid_methods = bool(
        str(ab_status).upper() == "INVALID_METHODS"
        and (
            ab_v2_primary.get("uplift") is not None
            or ab_v2_primary.get("p_value") is not None
            or ab_v2_primary.get("ci95") is not None
        )
        and ("diagnostic-only" not in decision_card_text_l and "diagnostic" not in ab_stat_report_text_l)
    )
    fatal_doctor = any([
        math_contradiction,
        reject_h0_with_p_gt_alpha,
        wrong_method_for_ratio,
        uplift_claimed_while_unobservable,
        misalignment_ignored,
        goal_metric_misalignment_not_flagged_fatal,
        valid_ab_numbers_when_invalid_methods,
    ])

    # Major penalties
    doc_dec = str(doctor.get("normalized_decision", doctor.get("decision", ""))).upper()
    eval_dec = str(evaluator.get("decision", "")).upper()
    cmd_dec_for_pen = str(commander.get("normalized_decision", commander.get("decision", ""))).upper()
    underpowered_overconfidence = bool(ab_status == "UNDERPOWERED" and ({doc_dec, eval_dec, cmd_dec_for_pen} & {"RUN_AB", "ROLLOUT_CANDIDATE"}))
    has_abs_numbers = (
        (ab_v2_primary.get("control") is not None and ab_v2_primary.get("treatment") is not None)
        or (ab_summary.get("primary_metric_control") is not None and ab_summary.get("primary_metric_treatment") is not None)
    )
    no_absolute_numbers = bool((ab_status not in blocked_statuses) and not has_abs_numbers)
    primary_uplift = ab_v2_primary.get("uplift", ab_summary.get("primary_metric_uplift"))
    guardrail_breach = bool(
        _f(metrics.get("fill_rate_units")) < 0.90
        or _f(metrics.get("oos_lost_gmv_rate")) > 0.10
        or _f(metrics.get("gp_margin")) < 0.0
    )
    guardrail_blindness = bool(
        isinstance(primary_uplift, (int, float))
        and float(primary_uplift) > 0
        and guardrail_breach
        and doc_dec not in {"STOP", "HOLD_RISK", "HOLD_NEED_DATA"}
    )

    major_penalty = 0.0
    major_penalty += 0.30 if underpowered_overconfidence else 0.0
    major_penalty += 0.20 if no_absolute_numbers else 0.0
    major_penalty += 0.50 if guardrail_blindness else 0.0

    doctor_numeric_evidence_rate = _ratio(
        sum(1 for h in hyps if isinstance(h, dict) and _refs_have_numeric_values(h.get("evidence_refs"))),
        max(1, len(hyps)),
    )
    no_numeric_evidence_refs_doctor = bool(hyp_generated > 0 and doctor_numeric_evidence_rate <= 0.0)
    template_explanation_reuse_doctor = False  # doctor is portfolio-structured; dedupe handled via hypothesis hashes.

    # Rewards
    method_justification_excellent = 1.0 if ("statistical method" in ab_stat_report_text.lower() and "assumptions checks" in ab_stat_report_text.lower()) else 0.0
    no_method_justification = bool(method_justification_excellent == 0.0 and ab_primary_metric_name)
    expected_vs_actual_rigor = 1.0 if ("SECTION 4: Expected vs Actual Impact" in ab_stat_report_text and "Actual delta" in ab_stat_report_text) else 0.0
    tradeoff_analysis = 1.0 if ("SECTION 3: Cross-goal Tradeoffs" in ab_stat_report_text and "Anti-Goodhart" in ab_stat_report_text) else 0.0
    design_clarity = 1.0 if ("analysis population: `ITT`" in ab_stat_report_text and "multiple testing" in ab_stat_report_text and "assignment: `deterministic hash + salt + unit_id`" in ab_stat_report_text) else 0.0
    method_correct_for_metric_type = 1.0 if not wrong_method_for_ratio else 0.0
    expected_vs_actual_checked_explicitly = expected_vs_actual_rigor
    tradeoff_analysis_across_goals = tradeoff_analysis

    reward_bonus = (
        0.20 * method_justification_excellent
        + 0.10 * method_correct_for_metric_type
        + 0.20 * expected_vs_actual_rigor
        + 0.30 * tradeoff_analysis
        + 0.20 * design_clarity
    )
    rec_exp = doctor.get("recommended_experiment", {}) if isinstance(doctor.get("recommended_experiment"), dict) else {}
    rec_goal = _goal_from_metric(str(rec_exp.get("primary_metric", "")))
    ab_summary = ab_v1.get("summary", {}) if isinstance(ab_v1.get("summary"), dict) else {}
    ab_goal = _goal_from_metric(str(ab_summary.get("primary_metric", "")))
    metric_alignment_penalty = 0.0
    metric_alignment_status = "N/A"
    if rec_goal != "unknown" and ab_goal != "unknown":
        metric_alignment_status = "PASS" if rec_goal == ab_goal else "FAIL"
        if rec_goal != ab_goal:
            metric_alignment_penalty = 0.15
    n_c = _f(ab_summary.get("n_orders_control"))
    n_t = _f(ab_summary.get("n_orders_treatment"))
    imbalance = abs(n_c - n_t) / max(1.0, (n_c + n_t) / 2.0) if (n_c > 0 and n_t > 0) else 0.0
    has_ci = isinstance(ab_summary.get("primary_metric_uplift_ci95"), list) and len(ab_summary.get("primary_metric_uplift_ci95")) == 2
    has_p = ab_summary.get("primary_metric_p_value") is not None
    has_srm = str(ab_summary.get("srm_status", "")).strip() != ""
    significance_discipline_penalty = 0.0
    significance_check_status = "N/A"
    if (n_c > 0 and n_t > 0):
        significance_check_status = "PASS"
        if imbalance > 0.15 and not (has_ci and has_p and has_srm):
            significance_check_status = "FAIL"
            significance_discipline_penalty = 0.10
    approval_ratio = _ratio(hyp_approved, max(1, hyp_generated))
    if review_pending_count:
        # Neutral while governance review is pending; do not penalize Doctor for missing review.
        approval_ratio = 0.5
    doctor_score = _clamp(
        0.50 * ab_success
        + 0.15 * methodology_complete
        + 0.10 * approval_ratio
        + 0.10 * guardrail_awareness
        + 0.10 * portfolio_diversity
        + 0.05 * _ratio(uniq_h, max(1, hyp_generated))
        + 0.05 * measurement_fix_plan_present
        - 0.10 * underpowered
        - 0.20 * mismatch
        - metric_alignment_penalty
        - significance_discipline_penalty
        - major_penalty
        - (0.25 if no_method_justification else 0.0)
        - (0.25 if no_numeric_evidence_refs_doctor else 0.0)
        + reward_bonus
    )
    if fatal_doctor:
        doctor_score = 0.0
    doctor_score_cap_reason = None
    if not fatal_doctor and ab_status == "INVALID_METHODS":
        doctor_score = min(doctor_score, 0.30)
        doctor_score_cap_reason = "ab_status_invalid_methods"

    cmd_dec = str(commander.get("normalized_decision", commander.get("decision", ""))).upper()
    decision_alignment = 1.0 if cmd_dec == eval_dec else 0.0
    adv_rows = adversarial.get("scenarios", []) if isinstance(adversarial.get("scenarios"), list) else []
    adv_fail = [s for s in adv_rows if isinstance(s, dict) and str(s.get("status")) == "FAIL"]
    blocked_bad = 1.0 if (len(adv_fail) > 0 and cmd_dec in {"STOP", "HOLD_RISK", "HOLD_NEED_DATA"}) else (1.0 if len(adv_fail)==0 else 0.0)
    portfolio_win = 1.0 if cmd_dec == "ROLLOUT_CANDIDATE" else 0.0
    guardrail_retention = _ratio((1 if _f(metrics.get("fill_rate_units")) >= 0.90 else 0)+(1 if _f(metrics.get("gp_margin")) >= 0 else 0),2)
    commander_score = _clamp(0.35*decision_alignment + 0.25*blocked_bad + 0.20*guardrail_retention + 0.20*portfolio_win)
    commander_claimed_uplift_when_unobservable = bool(ab_status in blocked_statuses and cmd_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"})
    commander_goal_metric_misalignment_not_flagged_fatal = bool(mismatch_exists and cmd_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"} and not mismatch_flagged_fatal)
    commander_valid_ab_numbers_when_invalid_methods = bool(
        str(ab_status).upper() == "INVALID_METHODS"
        and cmd_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"}
    )
    commander_guardrail_blindness = bool(guardrail_breach and cmd_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"})
    commander_methodology = commander.get("methodology_check", {}) if isinstance(commander.get("methodology_check"), dict) else {}
    commander_goals = commander.get("goals", []) if isinstance(commander.get("goals"), list) else []
    commander_data_requests = commander.get("data_requests", []) if isinstance(commander.get("data_requests"), list) else []
    commander_no_method_justification = not isinstance(commander_methodology.get("method_by_metric_policy"), dict)
    commander_cohort_status = str((commander.get("cohort_analysis", {}) or {}).get("status", "")).upper() if isinstance(commander.get("cohort_analysis"), dict) else ""
    commander_cohort_no_fantasy = 1.0 if commander_cohort_status in {"OK", "BLOCKED_BY_DATA"} else 0.0
    commander_expected_vs_actual_checked = 1.0 if any(isinstance(g, dict) and ("expected_impact_accepted" in g and "expected_impact_changed" in g) for g in commander_goals) else 0.0
    commander_missing_data_requests = bool(commander_cohort_status == "BLOCKED_BY_DATA" and len(commander_data_requests) < 3)
    fatal_commander = any(
        [
            commander_claimed_uplift_when_unobservable,
            commander_goal_metric_misalignment_not_flagged_fatal,
            commander_valid_ab_numbers_when_invalid_methods,
        ]
    )
    if commander_guardrail_blindness:
        commander_score = _clamp(commander_score - 0.5)
    if commander_no_method_justification:
        commander_score = _clamp(commander_score - 0.2)
    if commander_missing_data_requests:
        commander_score = _clamp(commander_score - 0.3)
    commander_score = _clamp(commander_score + 0.1 * commander_expected_vs_actual_checked + 0.1 * commander_cohort_no_fantasy)
    commander_score_cap_reason = None
    if not fatal_commander and ab_status in {"INVALID_METHODS", "METHODOLOGY_MISMATCH", "MISSING_ASSIGNMENT", "ASSIGNMENT_RECOVERED"}:
        caught_invalidity_early = bool(cmd_dec in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"} and ("invalid_methods" in str(commander.get("blocked_by", [])).lower() or "goal_metric_misalignment" in str(commander.get("blocked_by", [])).lower()))
        commander_score = min(commander_score + (0.05 if caught_invalidity_early else 0.0), 0.55)
        commander_score_cap_reason = "ab_not_decision_valid"
    if fatal_commander:
        commander_score = 0.0

    chains = narrative.get("causal_chains", []) if isinstance(narrative.get("causal_chains"), list) else []
    if not chains and isinstance(narrative.get("claims"), list):
        chains = narrative.get("claims", [])
    captain_trace_claims = _collect_visible_trace_claims(captain if isinstance(captain, dict) else {})
    doctor_trace_claims = _collect_visible_trace_claims(doctor if isinstance(doctor, dict) else {})
    commander_trace_claims = _collect_visible_trace_claims(commander if isinstance(commander, dict) else {})
    trace_claims = captain_trace_claims + doctor_trace_claims + commander_trace_claims
    trace_completeness_raw = _ratio(
        sum(1 for c in trace_claims if _claim_trace_complete(c)),
        max(1, len(trace_claims)),
    )
    trace_alt_ratio = _ratio(
        sum(
            1
            for c in trace_claims
            if isinstance(c.get("alternatives_considered"), list) and len(c.get("alternatives_considered", [])) >= 2
        ),
        max(1, len(trace_claims)),
    )
    trace_falsifiability_specific = _ratio(
        sum(1 for c in trace_claims if _falsifiability_is_specific(c.get("falsifiability_test"))),
        max(1, len(trace_claims)),
    )
    grounded = bool(validation.get("grounded", False))
    grounded_rate = 1.0 if grounded else 0.0
    top_delta_cov = _ratio(min(len(chains),3),3)
    completeness = _ratio(
        sum(
            1
            for c in chains
            if isinstance(c, dict)
            and str(c.get("observation", "")).strip()
            and str(c.get("root_cause_statement", "")).strip()
            and str(c.get("falsifiability_test", "")).strip()
            and isinstance(c.get("evidence_refs"), list)
            and len(c.get("evidence_refs", [])) >= 2
            and str(c.get("cause_type", "")).strip()
        ),
        max(1, len(chains)),
    )
    uniq_exp = len({str(c.get("evidence_pattern_hash", "")).strip().lower() for c in chains if isinstance(c, dict) and str(c.get("evidence_pattern_hash", "")).strip()})
    unique_cause_types = len({str(c.get("cause_type", "")).strip().lower() for c in chains if isinstance(c, dict) and str(c.get("cause_type", "")).strip()})
    evidence_pattern_uniqueness_rate = _ratio(uniq_exp, max(1, len(chains)))
    sig_hashes = [str(c.get("cause_signature_hash", "")).strip().lower() for c in chains if isinstance(c, dict)]
    sig_hashes = [s for s in sig_hashes if s]
    uniq_sig = len(set(sig_hashes))
    signature_uniqueness_rate = _ratio(uniq_sig, max(1, len(chains)))
    repeated_signature_penalty = 0.0
    max_signature_reuse = 1
    if sig_hashes:
        counts = {}
        for s in sig_hashes:
            counts[s] = counts.get(s, 0) + 1
        max_signature_reuse = max(counts.values())
        repeated_signature_penalty = 0.15 if max_signature_reuse > 2 else 0.0
    explanation_uniqueness = min(evidence_pattern_uniqueness_rate, signature_uniqueness_rate)
    template_explanation_reuse = bool(max_signature_reuse > 2)
    action_ref_count = 0
    for c in chains:
        refs = c.get("evidence_refs", []) if isinstance(c, dict) and isinstance(c.get("evidence_refs"), list) else []
        linked = False
        for ref in refs:
            if isinstance(ref, dict):
                src = str(ref.get("source", "")).strip().lower()
                if src in {"decision_trace", "commander", "doctor", "governance", "approvals"}:
                    linked = True
                    break
            txt = str(ref)
            if (
                "decision_traces" in txt
                or "decision_trace" in txt
                or "commander_priority" in txt
                or "doctor_variance" in txt
                or "agent_approvals" in txt
                or "agent_governance" in txt
            ):
                linked = True
                break
        if linked:
            action_ref_count += 1
    decision_ref = _ratio(action_ref_count, max(1, len(chains)))
    narrative_numeric_evidence_rate = _ratio(
        sum(1 for c in chains if isinstance(c, dict) and _refs_have_numeric_values(c.get("evidence_refs"))),
        max(1, len(chains)),
    )
    no_numeric_evidence_refs_narrative = bool(len(chains) > 0 and narrative_numeric_evidence_rate <= 0.0)
    no_method_justification_narrative = bool("method" not in ab_stat_report_text_l and "welch" not in ab_stat_report_text_l and "bootstrap" not in ab_stat_report_text_l and "delta method" not in ab_stat_report_text_l)
    cohort_heterogeneity_insight = 0.0
    narrative_md_path = Path(f"reports/L1_ops/{run_id}/CAUSAL_EXPLANATION.md")
    narrative_md_text = narrative_md_path.read_text(encoding="utf-8") if narrative_md_path.exists() else ""
    if narrative_md_text:
        txt = narrative_md_text.lower()
        if ("cohort" in txt or "segment" in txt) and ("%" in narrative_md_text or any(ch.isdigit() for ch in narrative_md_text)):
            cohort_heterogeneity_insight = 1.0
    narrative_score = _clamp(
        0.40 * grounded_rate
        + 0.25 * top_delta_cov
        + 0.20 * completeness
        + 0.15 * explanation_uniqueness
        - repeated_signature_penalty
        - (0.25 if template_explanation_reuse else 0.0)
        - (0.25 if no_numeric_evidence_refs_narrative else 0.0)
        - (0.15 if no_method_justification_narrative else 0.0)
        + (0.10 * cohort_heterogeneity_insight)
    )
    narrative_score_cap_reason = None
    if commander_cohort_status == "BLOCKED_BY_DATA":
        narrative_score = min(narrative_score, 0.75)
        narrative_score_cap_reason = "cohort_blocked_by_data"
    # Perfect narrative score requires stronger evidence of real reasoning.
    alternatives_per_claim_ok = _ratio(
        sum(1 for c in chains if isinstance(c, dict) and isinstance(c.get("alternatives_considered"), list) and len(c.get("alternatives_considered", [])) >= 2),
        max(1, len(chains)),
    )
    narrative_falsifiability_specific = _ratio(
        sum(1 for c in chains if isinstance(c, dict) and _falsifiability_is_specific(c.get("falsifiability_test"))),
        max(1, len(chains)),
    )
    counterfactual_present = 1.0 if (
        any(
            isinstance(c, dict)
            and (
                "if " in str(c.get("falsifiability_test", "")).lower()
                or "counterfactual" in str(c.get("root_cause_statement", "")).lower()
            )
            for c in chains
        )
        or ("if this were" in narrative_md_text.lower() if narrative_md_text else False)
    ) else 0.0
    if narrative_score >= 0.999:
        if not (unique_cause_types >= 3 and alternatives_per_claim_ok >= 1.0 and counterfactual_present >= 1.0 and commander_cohort_status == "OK"):
            narrative_score = 0.95 if commander_cohort_status == "OK" else min(narrative_score, 0.75)
            narrative_score_cap_reason = narrative_score_cap_reason or "perfect_score_requirements_not_met"
    narrative_claimed_uplift_when_unobservable = bool(
        ab_status in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "ASSIGNMENT_RECOVERED"}
        and ("uplift" in narrative_md_text.lower() if narrative_md_text else False)
    )
    fatal_narrative = any(
        [
            narrative_claimed_uplift_when_unobservable,
            (math_contradiction and ("reject h0" in (narrative_md_text.lower() if narrative_md_text else ""))),
            (valid_ab_numbers_when_invalid_methods and "diagnostic" not in (narrative_md_text.lower() if narrative_md_text else "")),
            (goal_metric_misalignment_not_flagged_fatal and "misalignment" not in (narrative_md_text.lower() if narrative_md_text else "")),
        ]
    )
    if fatal_narrative:
        narrative_score = 0.0
    vector_quality_score = _f(vector_quality.get("vector_quality_score"))
    vector_quality_status = str(vector_quality.get("status", "")).upper()

    # Reasoning-layer score: quality of structured, grounded, action-linked thinking.
    reasoning_layer_score = _clamp(
        0.30 * grounded_rate
        + 0.20 * completeness
        + 0.20 * decision_ref
        + 0.10 * explanation_uniqueness
        + 0.10 * methodology_complete
        + 0.10 * vector_quality_score
        - repeated_signature_penalty
    )
    reasoning_layer_status = "PASS" if reasoning_layer_score >= 0.70 else "WARN"
    trace_completeness_rate = _clamp(0.7 * trace_completeness_raw + 0.3 * completeness)
    alternative_hypothesis_quality = _clamp(
        0.5 * trace_alt_ratio
        + 0.3 * alternatives_per_claim_ok
        + 0.2 * portfolio_diversity
    )
    falsifiability_specificity = _clamp(
        0.6 * trace_falsifiability_specific + 0.4 * narrative_falsifiability_specific
    )
    adv_warn = [s for s in adv_rows if isinstance(s, dict) and str(s.get("status")) == "WARN"]
    aggressive_decision = bool(cmd_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"} or eval_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"})
    if adv_fail:
        decision_change_sensitivity = 0.0 if aggressive_decision else 1.0
    elif adv_warn:
        decision_change_sensitivity = 0.25 if aggressive_decision else 0.75
    else:
        decision_change_sensitivity = 0.85 if aggressive_decision else 1.0
    reasoning_checks_status = (
        "PASS"
        if min(
            trace_completeness_rate,
            alternative_hypothesis_quality,
            falsifiability_specificity,
            decision_change_sensitivity,
        )
        >= 0.60
        else "WARN"
    )

    fatal_any = bool(fatal_doctor or fatal_commander or fatal_narrative)
    safety_score = _clamp(0.5*captain_score + 0.5*guardrail_retention)
    business_value_score = _clamp(0.6*doctor_score + 0.4*commander_score)
    adv_penalty = min(0.3, 0.1*len(adv_fail))
    reasoning_quality = _clamp((0.34*captain_score + 0.33*doctor_score + 0.33*narrative_score) - adv_penalty)
    reporting_quality = 1.0 if Path(f"reports/L1_ops/{run_id}/DEMO_INDEX.md").exists() else 0.6
    final_score = _clamp(0.40*business_value_score + 0.30*reasoning_quality + 0.20*safety_score + 0.10*reporting_quality)
    if fatal_any:
        final_score = 0.0

    replaceable = fatal_any or (grounded_rate < 0.7) or (uniq_h < 2 and measurement_fix_plan_present <= 0.0)

    stat_correctness_pass = not (math_contradiction or wrong_method_for_ratio or uplift_claimed_while_unobservable)
    methodology_match_score = _clamp(1.0 - (1.0 if wrong_method_for_ratio else 0.0) - metric_alignment_penalty)
    decision_rule_compliance = _clamp(1.0 - (1.0 if (misalignment_ignored or underpowered_overconfidence) else 0.0))
    guardrail_tradeoff_quality = _clamp(1.0 - (1.0 if guardrail_blindness else 0.0) + 0.3 * tradeoff_analysis)
    expected_vs_actual_quality = _clamp(0.4 * expected_vs_actual_rigor + 0.6 * method_justification_excellent)

    # Real KPI layer (ledger-backed): must be based on historical labeled outcomes, no synthetic flooring.
    outcomes, ground_truth_refs, label_window_days = _collect_real_outcomes_from_history(run_id)
    sample_size = len(outcomes)
    ground_truth_source = "decision_outcomes_ledger_history" if sample_size > 0 else ""
    if label_window_days <= 0:
        label_window_days = 0
    prevented_loss_count = sum(1 for row in outcomes if bool(row.get("prevented_loss", False)))
    regret_count = sum(1 for row in outcomes if bool(row.get("regret", False)))
    would_have_prevented_loss_rate = _ratio(prevented_loss_count, sample_size)
    decision_regret_rate = _ratio(regret_count, sample_size)

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "captain": {
            "issue_coverage": round(cap_cov,4),
            "false_positive_rate_est": round(cap_fp,4),
            "approved_realism_fixes_count": cap_realism_fixes,
            "evidence_density": round(cap_evidence_density,4),
            "score": round(captain_score,4),
        },
        "doctor": {
            "hypotheses_generated_count": hyp_generated,
            "hypotheses_approved_count": hyp_approved,
            "unique_hypotheses_count": uniq_h,
            "portfolio_diversity_score": round(portfolio_diversity,4),
            "measurement_fix_plan_present": int(measurement_fix_plan_present),
            "approved_by_commander_count": hyp_approved,
            "review_pending_count": review_pending_count,
            "flagged_metric_alignment_status": flagged_metric_alignment_status,
            "flagged_metric_alignment_rate": (
                round(float(flagged_metric_alignment_rate), 4)
                if isinstance(flagged_metric_alignment_rate, (int, float))
                else None
            ),
            "methodology_completeness": round(methodology_complete,4),
            "ab_observable_rate": round(ab_observable,4),
            "ab_success_rate": round(ab_success,4),
            "underpowered_rate": round(underpowered,4),
            "mismatch_rate": round(mismatch,4),
            "guardrail_awareness": round(guardrail_awareness,4),
            "metric_alignment_status": metric_alignment_status,
            "metric_alignment_penalty": round(metric_alignment_penalty,4),
            "significance_check_status": significance_check_status,
            "significance_discipline_penalty": round(significance_discipline_penalty,4),
            "fatal_penalty_applied": fatal_doctor,
            "fatal_reasons": [
                r
                for r, ok in {
                    "MATH_CONTRADICTION": math_contradiction,
                    "REJECT_H0_WITH_P_GT_ALPHA": reject_h0_with_p_gt_alpha,
                    "WRONG_METHOD_FOR_RATIO": wrong_method_for_ratio,
                    "CLAIMED_UPLIFT_WHEN_UNOBSERVABLE": uplift_claimed_while_unobservable,
                    "VALID_AB_NUMBERS_WHEN_ab_status_INVALID_METHODS": valid_ab_numbers_when_invalid_methods,
                    "GOAL_METRIC_MISALIGNMENT_IGNORED": misalignment_ignored,
                    "GOAL_METRIC_MISALIGNMENT_NOT_FLAGGED_FATAL": goal_metric_misalignment_not_flagged_fatal,
                }.items()
                if ok
            ],
            "major_penalties": {
                "UNDERPOWERED_OVERCONFIDENCE": underpowered_overconfidence,
                "NO_ABSOLUTE_NUMBERS": no_absolute_numbers,
                "GUARDRAIL_BLINDNESS": guardrail_blindness,
                "NO_METHOD_JUSTIFICATION": no_method_justification,
                "NO_NUMERIC_EVIDENCE_REFS": no_numeric_evidence_refs_doctor,
                "penalty_total": round(major_penalty, 4),
            },
            "rewards": {
                "METHOD_CORRECT_FOR_METRIC_TYPE": bool(method_correct_for_metric_type),
                "METHOD_JUSTIFICATION_EXCELLENT": bool(method_justification_excellent),
                "EXPECTED_VS_ACTUAL_CHECKED_EXPLICITLY": bool(expected_vs_actual_checked_explicitly),
                "EXPECTED_VS_ACTUAL_RIGOR": bool(expected_vs_actual_rigor),
                "TRADEOFF_ANALYSIS_ACROSS_GOALS": bool(tradeoff_analysis_across_goals),
                "TRADEOFF_ANALYSIS": bool(tradeoff_analysis),
                "DESIGN_CLARITY": bool(design_clarity),
                "reward_total": round(reward_bonus, 4),
            },
            "numeric_evidence_refs_rate": round(doctor_numeric_evidence_rate, 4),
            "stat_correctness_pass": stat_correctness_pass,
            "methodology_match_score": round(methodology_match_score, 4),
            "decision_rule_compliance": round(decision_rule_compliance, 4),
            "guardrail_tradeoff_quality": round(guardrail_tradeoff_quality, 4),
            "expected_vs_actual_quality": round(expected_vs_actual_quality, 4),
            "replaceable_by_python": replaceable,
            "score": round(doctor_score,4),
            "score_cap_reason": doctor_score_cap_reason,
        },
        "doctor_eval_quality": {
            "stat_correctness_pass": stat_correctness_pass,
            "methodology_match_score": round(methodology_match_score, 4),
            "decision_rule_compliance": round(decision_rule_compliance, 4),
            "guardrail_tradeoff_quality": round(guardrail_tradeoff_quality, 4),
            "expected_vs_actual_quality": round(expected_vs_actual_quality, 4),
            "replaceable_by_python": replaceable,
        },
        "commander": {
            "decision_alignment_with_evaluator": round(decision_alignment,4),
            "blocked_bad_experiments": round(blocked_bad,4),
            "portfolio_win_rate": round(portfolio_win,4),
            "guardrail_retention": round(guardrail_retention,4),
            "fatal_penalty_applied": fatal_commander,
            "fatal_reasons": [
                r
                for r, ok in {
                    "CLAIMED_UPLIFT_WHEN_UNOBSERVABLE": commander_claimed_uplift_when_unobservable,
                    "VALID_AB_NUMBERS_WHEN_ab_status_INVALID_METHODS": commander_valid_ab_numbers_when_invalid_methods,
                    "GOAL_METRIC_MISALIGNMENT_NOT_FLAGGED_FATAL": commander_goal_metric_misalignment_not_flagged_fatal,
                }.items() if ok
            ],
            "strong_penalties": {
                "GUARDRAIL_BLINDNESS": commander_guardrail_blindness,
                "NO_METHOD_JUSTIFICATION": commander_no_method_justification,
                "MISSING_DATA_REQUESTS_WHEN_BLOCKED": commander_missing_data_requests,
            },
            "rewards": {
                "EXPECTED_VS_ACTUAL_CHECKED_EXPLICITLY": bool(commander_expected_vs_actual_checked),
                "COHORT_HETEROGENEITY_INSIGHT": bool(commander_cohort_status == "OK"),
                "COHORT_BLOCKED_NO_FANTASY": bool(commander_cohort_no_fantasy),
                "CAUGHT_INVALIDITY_EARLY": bool(ab_status in {"INVALID_METHODS", "METHODOLOGY_MISMATCH", "MISSING_ASSIGNMENT", "ASSIGNMENT_RECOVERED"} and cmd_dec in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"}),
            },
            "score_cap_reason": commander_score_cap_reason,
            "score": round(commander_score,4),
        },
        "narrative": {
            "grounded_claim_rate": round(grounded_rate,4),
            "top_delta_coverage": round(top_delta_cov,4),
            "causal_chain_completeness": round(completeness,4),
            "explanation_uniqueness": round(explanation_uniqueness,4),
            "evidence_pattern_uniqueness_rate": round(evidence_pattern_uniqueness_rate,4),
            "cause_signature_uniqueness_rate": round(signature_uniqueness_rate,4),
            "decision_reference_rate": round(decision_ref,4),
            "evidence_refs_to_actions_rate": round(decision_ref,4),
            "numeric_evidence_refs_rate": round(narrative_numeric_evidence_rate,4),
            "unique_cause_types_count": unique_cause_types,
            "template_explanation_reuse": template_explanation_reuse,
            "no_method_justification": no_method_justification_narrative,
            "no_numeric_evidence_refs": no_numeric_evidence_refs_narrative,
            "rewards": {
                "METHOD_CORRECT_FOR_METRIC_TYPE": bool(method_correct_for_metric_type),
                "EXPECTED_VS_ACTUAL_CHECKED_EXPLICITLY": bool(expected_vs_actual_checked_explicitly),
                "TRADEOFF_ANALYSIS_ACROSS_GOALS": bool(tradeoff_analysis_across_goals),
                "COHORT_HETEROGENEITY_INSIGHT": bool(cohort_heterogeneity_insight),
            },
            "alternatives_per_claim_rate": round(alternatives_per_claim_ok,4),
            "counterfactual_present": bool(counterfactual_present),
            "score_cap_reason": narrative_score_cap_reason,
            "fatal_penalty_applied": fatal_narrative,
            "fatal_reasons": [
                r for r, ok in {
                    "CLAIMED_UPLIFT_WHEN_UNOBSERVABLE": narrative_claimed_uplift_when_unobservable,
                    "REJECT_H0_WITH_P_GT_ALPHA": bool(math_contradiction and ("reject h0" in (narrative_md_text.lower() if narrative_md_text else ""))),
                    "VALID_AB_NUMBERS_WHEN_ab_status_INVALID_METHODS": bool(valid_ab_numbers_when_invalid_methods and "diagnostic" not in (narrative_md_text.lower() if narrative_md_text else "")),
                    "GOAL_METRIC_MISALIGNMENT_NOT_FLAGGED_FATAL": bool(goal_metric_misalignment_not_flagged_fatal and "misalignment" not in (narrative_md_text.lower() if narrative_md_text else "")),
                }.items() if ok
            ],
            "score": round(narrative_score,4),
        },
        "system": {
            "safety_score": round(safety_score,4),
            "business_value_score": round(business_value_score,4),
            "reasoning_quality_score": round(reasoning_quality,4),
            "reasoning_layer_score": round(reasoning_layer_score,4),
            "reasoning_layer_status": reasoning_layer_status,
            "reasoning_checks_status": reasoning_checks_status,
            "prevented_loss_proxy_rate": round(_clamp(0.5 * blocked_bad + 0.5 * guardrail_retention), 4),
            "unsafe_rollout_block_rate": round(_clamp(blocked_bad), 4),
            "evidence_coverage_rate": round(_clamp(0.5 * grounded_rate + 0.5 * decision_ref), 4),
            "would_have_prevented_loss_rate": round(would_have_prevented_loss_rate, 4),
            "decision_regret_rate": round(decision_regret_rate, 4),
            "sample_size": int(sample_size),
            "label_window_days": int(label_window_days),
            "ground_truth_source": ground_truth_source,
            "ground_truth_refs_count": len(ground_truth_refs),
            "reporting_quality_score": round(reporting_quality,4),
            "final_score": round(final_score,4),
            "replaceable_by_python": replaceable,
            "adversarial_fail_count": len(adv_fail),
            "fatal_penalty_applied": fatal_any,
        },
        "reasoning_layer": {
            "grounded_claim_rate": round(grounded_rate,4),
            "causal_chain_completeness": round(completeness,4),
            "evidence_refs_to_actions_rate": round(decision_ref,4),
            "explanation_uniqueness": round(explanation_uniqueness,4),
            "doctor_methodology_completeness": round(methodology_complete,4),
            "vector_quality_score": round(vector_quality_score,4),
            "vector_quality_status": vector_quality_status,
            "repeated_signature_penalty": round(repeated_signature_penalty,4),
            "score": round(reasoning_layer_score,4),
            "status": reasoning_layer_status,
        },
        "reasoning_checks": {
            "trace_completeness_rate": round(trace_completeness_rate, 4),
            "alternative_hypothesis_quality": round(alternative_hypothesis_quality, 4),
            "falsifiability_specificity": round(falsifiability_specificity, 4),
            "decision_change_sensitivity": round(decision_change_sensitivity, 4),
            "status": reasoning_checks_status,
            "mode": "ADVISORY",
        },
        "real_kpi": {
            "status": ("PASS" if sample_size > 0 else "MISSING"),
            "would_have_prevented_loss_rate": round(would_have_prevented_loss_rate, 4),
            "decision_regret_rate": round(decision_regret_rate, 4),
            "sample_size": int(sample_size),
            "label_window_days": int(label_window_days),
            "ground_truth_source": ground_truth_source,
            "ground_truth_refs_count": len(ground_truth_refs),
            "outcomes_count": int(sample_size),
        },
        "version": "agent_value_eval.v1",
    }

    out_json = Path(f"data/agent_eval/{run_id}_agent_value_eval.json")
    _safe_write(out_json, payload)
    decision_outcomes_ledger = {
        "version": "decision_outcomes_ledger_v1",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ground_truth_source": ground_truth_source,
        "ground_truth_refs": ground_truth_refs,
        "label_window_days": int(label_window_days),
        "sample_size": int(sample_size),
        "would_have_prevented_loss_rate": round(would_have_prevented_loss_rate, 4),
        "decision_regret_rate": round(decision_regret_rate, 4),
        "outcomes": outcomes,
    }
    _safe_write(Path(f"data/agent_eval/{run_id}_decision_outcomes_ledger.json"), decision_outcomes_ledger)
    offline_kpi_backtest = {
        "version": "offline_kpi_backtest_v1",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ground_truth_source": ground_truth_source,
        "ground_truth_refs": ground_truth_refs,
        "label_window_days": int(label_window_days),
        "sample_size": int(sample_size),
        "would_have_prevented_loss_rate": round(would_have_prevented_loss_rate, 4),
        "decision_regret_rate": round(decision_regret_rate, 4),
        "freshness_mode": "run",
    }
    _safe_write(Path(f"data/agent_eval/{run_id}_offline_kpi_backtest.json"), offline_kpi_backtest)

    md = [
        f"# AGENT VALUE SCORECARD — {run_id}",
        "",
        f"- Final score: `{payload['system']['final_score']}`",
        f"- replaceable_by_python: `{payload['system']['replaceable_by_python']}`",
        f"- adversarial_fail_count: `{payload['system']['adversarial_fail_count']}`",
        f"- fatal_penalty_applied: `{payload['system']['fatal_penalty_applied']}`",
        "",
        "## Agent scores",
        f"- Captain: `{payload['captain']['score']}`",
        f"- Doctor: `{payload['doctor']['score']}` (fatal=`{payload['doctor']['fatal_penalty_applied']}`)",
        f"- Doctor flagged-metric alignment: `{payload['doctor']['flagged_metric_alignment_status']}` ({payload['doctor']['flagged_metric_alignment_rate']})",
        f"- Commander: `{payload['commander']['score']}` (fatal=`{payload['commander']['fatal_penalty_applied']}`)",
        f"- Narrative: `{payload['narrative']['score']}` (fatal=`{payload['narrative']['fatal_penalty_applied']}`)",
        "",
        "## System scores",
        f"- safety_score: `{payload['system']['safety_score']}`",
        f"- business_value_score: `{payload['system']['business_value_score']}`",
        f"- reasoning_quality_score: `{payload['system']['reasoning_quality_score']}`",
        f"- reporting_quality_score: `{payload['system']['reporting_quality_score']}`",
        "",
        "## Reasoning layer",
        f"- status: `{payload['reasoning_layer']['status']}`",
        f"- score: `{payload['reasoning_layer']['score']}`",
        f"- grounded_claim_rate: `{payload['reasoning_layer']['grounded_claim_rate']}`",
        f"- evidence_refs_to_actions_rate: `{payload['reasoning_layer']['evidence_refs_to_actions_rate']}`",
        f"- causal_chain_completeness: `{payload['reasoning_layer']['causal_chain_completeness']}`",
        f"- explanation_uniqueness: `{payload['reasoning_layer']['explanation_uniqueness']}`",
        f"- vector_quality_score: `{payload['reasoning_layer']['vector_quality_score']}` (`{payload['reasoning_layer']['vector_quality_status']}`)",
        f"- doctor_methodology_completeness: `{payload['reasoning_layer']['doctor_methodology_completeness']}`",
        "",
        "## Reasoning checks (v2 advisory)",
        f"- status: `{payload['reasoning_checks']['status']}`",
        f"- trace_completeness_rate: `{payload['reasoning_checks']['trace_completeness_rate']}`",
        f"- alternative_hypothesis_quality: `{payload['reasoning_checks']['alternative_hypothesis_quality']}`",
        f"- falsifiability_specificity: `{payload['reasoning_checks']['falsifiability_specificity']}`",
        f"- decision_change_sensitivity: `{payload['reasoning_checks']['decision_change_sensitivity']}`",
        "",
    ]
    _safe_write_md(Path(f"reports/L1_ops/{run_id}/AGENT_VALUE_SCORECARD.md"), "\n".join(md))

    # keep links.json in sync (best effort)
    links_path = Path(f"reports/L1_ops/{run_id}/links.json")
    links = _load(links_path)
    if isinstance(links, dict):
        outputs = links.get("outputs", {})
        if not isinstance(outputs, dict):
            outputs = {}
        outputs["agent_value_scorecard"] = f"reports/L1_ops/{run_id}/AGENT_VALUE_SCORECARD.md"
        outputs["agent_value_eval_json"] = f"data/agent_eval/{run_id}_agent_value_eval.json"
        links["outputs"] = outputs
        _safe_write(links_path, links)

    print(f"ok: agent value eval written for run_id={run_id}")


if __name__ == "__main__":
    main()
