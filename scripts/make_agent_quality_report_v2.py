#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def _safe_write(path: Path, text: str) -> None:
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


def _is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        s = value.strip().lower()
        return bool(s and s not in {"missing", "none", "null", "nan", "n/a", "unknown"})
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def _doctor_design_contract_quality(first_exp: dict[str, Any], measurement_fix_plan: dict[str, Any]) -> tuple[float | None, list[str], bool, list[str]]:
    required_raw = measurement_fix_plan.get("required_design_fields")
    required = [str(x).strip() for x in required_raw] if isinstance(required_raw, list) else []
    if not required:
        required = [
            "pre_period_weeks",
            "test_period_weeks",
            "wash_in_days",
            "attribution_window_rule",
            "test_side",
            "randomization_unit",
            "analysis_unit",
        ]
    required = [x for x in required if x]
    aliases = {
        "randomization_unit": "randomization_unit_cfg",
        "analysis_unit": "analysis_unit_realized",
        "randomization_unit_cfg": "randomization_unit",
        "analysis_unit_realized": "analysis_unit",
    }
    gaps: list[str] = []
    present = 0
    for key in required:
        value = first_exp.get(key)
        if value is None and key in aliases:
            value = first_exp.get(aliases[key])
        if _is_present(value):
            present += 1
        else:
            gaps.append(key)
    coverage = (present / len(required)) if required else None
    return coverage, gaps, len(gaps) == 0, required


def _semantic_hash(text: str) -> str:
    cleaned = re.sub(r"\s+", " ", text.strip().lower())
    return hashlib.sha1(cleaned.encode("utf-8")).hexdigest()[:12]


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent quality report v2 (outcome-based)")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    out_dir = Path(f"reports/L1_ops/{run_id}")
    out_dir.mkdir(parents=True, exist_ok=True)

    approvals = (_load(Path(f"data/governance/approvals_{run_id}.json")) or {}).get("approvals", [])
    if not isinstance(approvals, list):
        approvals = []
    captain = _load(Path(f"data/llm_reports/{run_id}_captain.json")) or {}
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
    evaluator = _load(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")) or {}
    commander = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}
    narrative = _load(Path(f"data/agent_reports/{run_id}_narrative_claims.json")) or _load(out_dir / "causal_claims.json") or {}
    validation = _load(out_dir / "causal_claims_validation.json") or {}
    metrics = (_load(Path(f"data/metrics_snapshots/{run_id}.json")) or {}).get("metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}

    cap_eval = captain.get("eval_metrics", {}) if isinstance(captain.get("eval_metrics"), dict) else {}
    cap_issue_cov = _f(cap_eval.get("issue_coverage"))
    cap_warn_fail = _f(cap_eval.get("target_warn_fail_count"))
    cap_issues = ((captain.get("result") or {}).get("issues", []) if isinstance(captain.get("result"), dict) else [])
    cap_issues = cap_issues if isinstance(cap_issues, list) else []
    realism_critique_count = len([i for i in cap_issues if isinstance(i, dict) and ("realism" in str(i.get("check_name", "")).lower() or "anti_gaming" in str(i.get("check_name", "")).lower())])
    approved_realism_fixes_count = len([a for a in approvals if isinstance(a, dict) and str(a.get("agent")) == "captain" and str(a.get("proposal_type")) == "realism_gap" and str(a.get("decision")).upper() == "APPROVE"])
    evidence_density = _ratio(sum(1 for i in cap_issues if isinstance(i, dict) and str(i.get("message", "")).strip()), len(cap_issues))
    false_positive_rate = _ratio(max(0.0, cap_warn_fail - len(cap_issues)), max(1.0, cap_warn_fail))
    captain_score = _clamp(0.35 * cap_issue_cov + 0.15 * _ratio(realism_critique_count, max(1, len(cap_issues))) + 0.20 * _ratio(approved_realism_fixes_count, max(1, realism_critique_count)) + 0.20 * evidence_density - 0.10 * false_positive_rate)

    ab_plan = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
    recommended_experiment = doctor.get("recommended_experiment", {}) if isinstance(doctor.get("recommended_experiment"), dict) else {}
    first_exp = ab_plan[0] if ab_plan and isinstance(ab_plan[0], dict) else (recommended_experiment if isinstance(recommended_experiment, dict) else {})
    measurement_fix_plan = doctor.get("measurement_fix_plan", {}) if isinstance(doctor.get("measurement_fix_plan"), dict) else {}
    design_cov, design_gaps, design_complete, required_design_fields = _doctor_design_contract_quality(first_exp, measurement_fix_plan)
    hypotheses = []
    for exp in ab_plan:
        if not isinstance(exp, dict):
            continue
        hs = exp.get("hypotheses", []) if isinstance(exp.get("hypotheses"), list) else []
        if hs and isinstance(hs[0], dict):
            hypotheses.append(hs[0])
    hyp_count = len(hypotheses)
    approved_hyp_count = len([a for a in approvals if isinstance(a, dict) and str(a.get("agent")) == "doctor" and str(a.get("proposal_type")) == "hypothesis" and str(a.get("decision")).upper() == "APPROVE"])
    unique_hyp_count = len({_semantic_hash(str(h.get("hypothesis_statement", ""))) for h in hypotheses if str(h.get("hypothesis_statement", "")).strip()})
    method_valid_rate = _ratio(sum(1 for exp in ab_plan if isinstance(exp, dict) and str(exp.get("methodology", "")).strip() and isinstance(exp.get("sample_size_gate"), dict)), len(ab_plan))
    ab_status = str(evaluator.get("ab_status", "")).upper()
    exp_success_rate = 1.0 if ab_status not in {"UNDERPOWERED", "METHODOLOGY_MISMATCH", "MISSING_ASSIGNMENT", "INVALID"} else 0.0
    ab_success_rate = 1.0 if str(evaluator.get("decision", "")).upper() == "ROLLOUT_CANDIDATE" else 0.0
    guardrail_awareness = 1.0
    if _f(metrics.get("fill_rate_units")) < 0.90 and _f(metrics.get("writeoff_rate_vs_requested_units")) < 0.02:
        guardrail_awareness = 0.3
    actionable_approved = len([a for a in approvals if isinstance(a, dict) and str(a.get("agent")) == "doctor" and str(a.get("decision")).upper() == "APPROVE"])
    doctor_score = _clamp(
        0.50 * ab_success_rate
        + 0.15 * method_valid_rate
        + 0.15 * exp_success_rate
        + 0.10 * _ratio(approved_hyp_count, max(1, hyp_count))
        + 0.05 * _ratio(unique_hyp_count, max(1, hyp_count))
        + 0.05 * _ratio(actionable_approved, max(1, hyp_count))
    )

    evaluator_dec = str(evaluator.get("decision", "")).upper()
    commander_dec = str(commander.get("normalized_decision", commander.get("decision", ""))).upper()
    decision_alignment = 1.0 if evaluator_dec == commander_dec else 0.0
    successful_rollouts = 1 if commander_dec == "ROLLOUT_CANDIDATE" else 0
    blocked_bad = 1 if commander_dec in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"} and evaluator_dec in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"} else 0
    business_uplift_score = 1.0 if _f(metrics.get("gmv")) > 0 and _f(metrics.get("gp")) > 0 else 0.0
    guardrail_retention = _ratio((1 if _f(metrics.get("fill_rate_units")) >= 0.90 else 0) + (1 if _f(metrics.get("gp_margin")) >= 0 else 0), 2)
    reporting_quality = 1.0 if (out_dir / "index.md").exists() and (out_dir / "RETAIL_MBR.md").exists() else 0.0
    commander_score = _clamp(0.30 * decision_alignment + 0.20 * successful_rollouts + 0.20 * blocked_bad + 0.20 * business_uplift_score + 0.10 * guardrail_retention)

    chains = narrative.get("causal_chains", []) if isinstance(narrative.get("causal_chains"), list) else []
    metric_claims = narrative.get("metric_claims", {}) if isinstance(narrative.get("metric_claims"), dict) else {}
    grounded = bool(validation.get("grounded", False))
    grounded_claim_rate = 0.0
    if metric_claims:
        with_refs = sum(1 for c in metric_claims.values() if isinstance(c, dict) and isinstance(c.get("evidence_refs"), list) and len(c.get("evidence_refs", [])) > 0)
        grounded_claim_rate = _ratio(with_refs, len(metric_claims))
    if not grounded:
        grounded_claim_rate *= 0.5
    unique_explanations_count = len({str(c.get("explanation_short", "")).strip() for c in metric_claims.values() if isinstance(c, dict) and str(c.get("explanation_short", "")).strip()})
    structure_complete = sum(
        1 for c in chains if isinstance(c, dict) and all(str(c.get(k, "")).strip() for k in ["observation", "root_cause", "recommended_action"])
    )
    chain_quality = _ratio(structure_complete, max(1, len(chains)))
    realism_critique = sum(1 for c in chains if isinstance(c, dict) and any(x in str(c.get("root_cause", "")).lower() for x in ["availability", "measurement", "spoilage"]))
    actions_approved = len([a for a in approvals if isinstance(a, dict) and str(a.get("agent")) == "narrative_analyst" and str(a.get("decision")).upper() == "APPROVE"])
    narrative_score = _clamp(0.45 * grounded_claim_rate + 0.25 * chain_quality + 0.15 * _ratio(unique_explanations_count, max(1, len(metric_claims))) + 0.15 * _ratio(actions_approved, max(1, len(chains))))

    system_safety = _clamp(0.5 * captain_score + 0.5 * guardrail_retention)
    business_value = _clamp(0.6 * doctor_score + 0.4 * commander_score)
    reasoning_quality = _clamp(0.7 * narrative_score + 0.3 * _ratio(unique_hyp_count, max(1, hyp_count)))
    final_score = _clamp(0.40 * business_value + 0.30 * reasoning_quality + 0.20 * system_safety + 0.10 * reporting_quality)
    replaceable = grounded_claim_rate < 0.5 or unique_hyp_count < 2

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "captain": {
            "issue_coverage_score": round(cap_issue_cov, 4),
            "false_positive_rate_estimate": round(false_positive_rate, 4),
            "realism_critique_count": realism_critique_count,
            "approved_realism_fixes_count": approved_realism_fixes_count,
            "evidence_density": round(evidence_density, 4),
            "score": round(captain_score, 4),
        },
        "doctor": {
            "hypotheses_generated_count": hyp_count,
            "hypotheses_approved_count": approved_hyp_count,
            "unique_hypotheses_count": unique_hyp_count,
            "methodology_valid_rate": round(method_valid_rate, 4),
            "design_contract_field_coverage": (round(design_cov, 4) if isinstance(design_cov, float) else None),
            "design_contract_gap_count": len(design_gaps),
            "design_contract_gap_codes": design_gaps,
            "design_contract_complete": design_complete,
            "required_design_fields": required_design_fields,
            "experiments_run_success_rate": round(exp_success_rate, 4),
            "ab_success_weight": 0.50,
            "ab_success_rate": round(ab_success_rate, 4),
            "guardrail_awareness_score": round(guardrail_awareness, 4),
            "number_of_actionable_recommendations_approved": actionable_approved,
            "score": round(doctor_score, 4),
        },
        "commander": {
            "decision_alignment_with_evaluator": round(decision_alignment, 4),
            "successful_rollouts_count": successful_rollouts,
            "blocked_bad_experiments_count": blocked_bad,
            "business_uplift_score": round(business_uplift_score, 4),
            "guardrail_retention_score": round(guardrail_retention, 4),
            "reporting_quality_score": round(reporting_quality, 4),
            "score": round(commander_score, 4),
        },
        "narrative_analyst": {
            "grounded_claim_rate": round(grounded_claim_rate, 4),
            "unique_explanations_count": unique_explanations_count,
            "causal_chain_quality_score": round(chain_quality, 4),
            "realism_critique_count": realism_critique,
            "actions_approved_by_commander_count": actions_approved,
            "score": round(narrative_score, 4),
        },
        "overall": {
            "system_safety_score": round(system_safety, 4),
            "business_value_score": round(business_value, 4),
            "reasoning_quality_score": round(reasoning_quality, 4),
            "reporting_quality_score": round(reporting_quality, 4),
            "final_score": round(final_score, 4),
            "replaceable_by_python": replaceable,
        },
        "version": "agent_quality.v2",
    }

    out_json = Path(f"data/agent_quality/{run_id}_agent_quality_v2.json")
    _safe_write(out_json, json.dumps(payload, ensure_ascii=False, indent=2))

    lines = [
        f"# AGENT SCORECARD — {run_id}",
        "",
        f"- Final score: `{payload['overall']['final_score']:.3f}`",
        f"- replaceable_by_python: `{payload['overall']['replaceable_by_python']}`",
        f"- system_safety: `{payload['overall']['system_safety_score']:.3f}`",
        f"- business_value: `{payload['overall']['business_value_score']:.3f}`",
        f"- reasoning_quality: `{payload['overall']['reasoning_quality_score']:.3f}`",
        "",
        "## Captain",
        f"- score: `{payload['captain']['score']:.3f}`",
        f"- issue_coverage_score: `{payload['captain']['issue_coverage_score']}`",
        f"- false_positive_rate_estimate: `{payload['captain']['false_positive_rate_estimate']}`",
        "",
        "## Doctor",
        f"- score: `{payload['doctor']['score']:.3f}`",
        f"- hypotheses_generated_count: `{payload['doctor']['hypotheses_generated_count']}`",
        f"- hypotheses_approved_count: `{payload['doctor']['hypotheses_approved_count']}`",
        f"- ab_success_rate: `{payload['doctor']['ab_success_rate']}`",
        f"- design_contract_complete: `{payload['doctor']['design_contract_complete']}`",
        f"- design_contract_field_coverage: `{payload['doctor']['design_contract_field_coverage']}`",
        f"- design_contract_gap_codes: `{payload['doctor']['design_contract_gap_codes']}`",
        "",
        "## Commander",
        f"- score: `{payload['commander']['score']:.3f}`",
        f"- decision_alignment_with_evaluator: `{payload['commander']['decision_alignment_with_evaluator']}`",
        f"- guardrail_retention_score: `{payload['commander']['guardrail_retention_score']}`",
        "",
        "## Narrative Analyst",
        f"- score: `{payload['narrative_analyst']['score']:.3f}`",
        f"- grounded_claim_rate: `{payload['narrative_analyst']['grounded_claim_rate']}`",
        f"- causal_chain_quality_score: `{payload['narrative_analyst']['causal_chain_quality_score']}`",
        "",
    ]
    _safe_write(out_dir / "AGENT_SCORECARD.md", "\n".join(lines))

    links_path = out_dir / "links.json"
    links_doc = _load(links_path)
    if isinstance(links_doc, dict):
        outputs = links_doc.get("outputs", {})
        if not isinstance(outputs, dict):
            outputs = {}
        outputs["agent_scorecard_v2"] = str(out_dir / "AGENT_SCORECARD.md")
        outputs["agent_quality_v2_json"] = f"data/agent_quality/{run_id}_agent_quality_v2.json"
        links_doc["outputs"] = outputs
        _safe_write(links_path, json.dumps(links_doc, ensure_ascii=False, indent=2))

    print(f"ok: agent quality v2 written for run_id={run_id}")


if __name__ == "__main__":
    main()
