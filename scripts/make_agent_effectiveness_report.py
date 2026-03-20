#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def _f(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _ratio(num: float, den: float) -> float:
    return 0.0 if den <= 0 else max(0.0, min(1.0, num / den))


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def _extract_approvals(doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    rows = (doc or {}).get("approvals", [])
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def _agent_rows(rows: list[dict[str, Any]], agent: str) -> list[dict[str, Any]]:
    return [r for r in rows if str(r.get("agent", "")).strip() == agent]


def _approved(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if str(r.get("decision", "")).upper() == "APPROVE"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Outcome-based agent effectiveness report")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    l1_dir = Path(f"reports/L1_ops/{run_id}")
    l1_dir.mkdir(parents=True, exist_ok=True)

    approvals = _extract_approvals(_load(Path(f"data/governance/approvals_{run_id}.json")))
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
    captain = _load(Path(f"data/llm_reports/{run_id}_captain.json")) or {}
    evaluator = _load(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")) or {}
    commander = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}
    claims = _load(l1_dir / "causal_claims.json") or {}
    claims_val = _load(l1_dir / "causal_claims_validation.json") or {}
    metrics = (_load(Path(f"data/metrics_snapshots/{run_id}.json")) or {}).get("metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}

    cap_rows = _agent_rows(approvals, "captain") + _agent_rows(approvals, "narrative_analyst")
    cap_gaps = [r for r in cap_rows if str(r.get("proposal_type", "")) == "realism_gap"]
    cap_fixes = [r for r in cap_rows if str(r.get("proposal_type", "")) == "improvement"]
    metric_claims = claims.get("metric_claims", {}) if isinstance(claims.get("metric_claims"), dict) else {}
    claim_rows = [c for c in metric_claims.values() if isinstance(c, dict)]
    with_refs = sum(1 for c in claim_rows if isinstance(c.get("evidence_refs"), list) and len(c.get("evidence_refs", [])) > 0)
    grounded_rate = _ratio(with_refs, len(claim_rows))
    if isinstance(claims_val, dict) and claims_val.get("grounded") is False:
        grounded_rate *= 0.5
    unique_short = {str(c.get("explanation_short", "")).strip() for c in claim_rows if str(c.get("explanation_short", "")).strip()}
    uniqueness_rate = _ratio(len(unique_short), len([c for c in claim_rows if str(c.get("explanation_short", "")).strip()]))
    false_alarm_rate = _ratio(
        len([r for r in cap_rows if str(r.get("decision", "")).upper() == "REJECT"]),
        len(cap_rows),
    )
    captain_score = _clamp(0.55 * grounded_rate + 0.25 * _ratio(len(_approved(cap_fixes)), max(1, len(cap_fixes))) + 0.20 * uniqueness_rate - 0.30 * false_alarm_rate)
    if bool(captain.get("fallback_used")):
        captain_score = _clamp(captain_score - 0.15)

    doc_rows = _agent_rows(approvals, "doctor")
    hyp_rows = [r for r in doc_rows if str(r.get("proposal_type", "")) == "hypothesis"]
    hyp_approved = _approved(hyp_rows)
    assignment_ready = str(doctor.get("assignment_status", "")).lower() in {"ready", "present"}
    ab_status = str(evaluator.get("ab_status", "")).upper()
    experiments_launched = len(hyp_approved) if assignment_ready else 0
    ab_success_rate = 1.0 if str(evaluator.get("decision", "")).upper() == "ROLLOUT_CANDIDATE" and experiments_launched > 0 else 0.0
    underpowered_rate = 1.0 if ab_status == "UNDERPOWERED" else 0.0
    mismatch_rate = 1.0 if ab_status in {"METHODOLOGY_MISMATCH", "MISSING_ASSIGNMENT"} else 0.0
    first_exp = ((doctor.get("ab_plan") or [{}])[0] if isinstance(doctor.get("ab_plan"), list) and doctor.get("ab_plan") else {})
    if not isinstance(first_exp, dict):
        first_exp = {}
    hyp0 = ((first_exp.get("hypotheses") or [{}])[0] if isinstance(first_exp.get("hypotheses"), list) and first_exp.get("hypotheses") else {})
    if not isinstance(hyp0, dict):
        hyp0 = {}
    evidence_complete = 1.0 if (
        str(first_exp.get("methodology", "")).strip()
        and isinstance(hyp0.get("evidence_refs"), list)
        and len(hyp0.get("evidence_refs", [])) > 0
        and _f(first_exp.get("mde")) > 0
    ) else 0.0
    unique_approved_explanations = len({str(r.get("title", "")).strip() for r in hyp_approved if str(r.get("title", "")).strip()})
    uniqueness_component = _ratio(unique_approved_explanations, max(1, len(hyp_approved)))
    approved_hyp_component = _ratio(len(hyp_approved), max(1, len(hyp_rows)))
    penalty_component = _clamp(1.0 - (0.5 * underpowered_rate + 0.5 * mismatch_rate))
    doctor_score = _clamp(
        0.55 * ab_success_rate
        + 0.15 * evidence_complete
        + 0.15 * penalty_component
        + 0.10 * approved_hyp_component
        + 0.05 * uniqueness_component
    )

    cmd_rows = [r for r in approvals if str(r.get("source", "")) in {"commander", "human"}]
    approved_exps = [r for r in cmd_rows if str(r.get("proposal_type", "")) in {"hypothesis", "experiment_plan"} and str(r.get("decision", "")).upper() == "APPROVE"]
    portfolio_win_rate = _ratio(1.0 if str(evaluator.get("decision", "")).upper() == "ROLLOUT_CANDIDATE" and len(approved_exps) > 0 else 0.0, 1.0)
    net_business_impact = _f(metrics.get("gmv")) * 0.4 + _f(metrics.get("gp")) * 0.4 - _f(metrics.get("lost_gmv_oos")) * 0.2
    impact_norm = 1.0 if net_business_impact > 0 else 0.0
    fill_ok = 1.0 if _f(metrics.get("fill_rate_units")) >= 0.90 else 0.0
    margin_ok = 1.0 if _f(metrics.get("gp_margin")) >= 0.0 else 0.0
    guardrail_retention = 0.5 * fill_ok + 0.5 * margin_ok
    rejected = [r for r in cmd_rows if str(r.get("decision", "")).upper() == "REJECT"]
    quality_rejects = [r for r in rejected if str(r.get("reason_code", "")).strip() in {"guardrail_risk", "missing_evidence", "bad_methodology", "unrealistic"}]
    rejection_quality = _ratio(len(quality_rejects), max(1, len(rejected)))
    commander_score = _clamp(0.45 * portfolio_win_rate + 0.25 * impact_norm + 0.20 * guardrail_retention + 0.10 * rejection_quality)

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "approvals_path": f"data/governance/approvals_{run_id}.json",
        "captain_narrative": {
            "realism_gaps_proposed": len(cap_gaps),
            "realism_gaps_approved": len(_approved(cap_gaps)),
            "realism_fixes_approved": len(_approved(cap_fixes)),
            "grounded_claim_rate": round(grounded_rate, 4),
            "false_alarm_rate": round(false_alarm_rate, 4),
            "explanation_uniqueness_rate": round(uniqueness_rate, 4),
            "score": round(captain_score, 4),
        },
        "doctor": {
            "hypotheses_proposed": len(hyp_rows),
            "hypotheses_approved": len(hyp_approved),
            "experiments_launched": experiments_launched,
            "ab_success_rate": round(ab_success_rate, 4),
            "underpowered_rate": round(underpowered_rate, 4),
            "methodology_mismatch_rate": round(mismatch_rate, 4),
            "unique_approved_explanations": unique_approved_explanations,
            "approved_improvement_suggestions": len([r for r in _approved(doc_rows) if str(r.get("proposal_type", "")) == "improvement"]),
            "evidence_completeness": round(evidence_complete, 4),
            "score": round(doctor_score, 4),
        },
        "commander": {
            "portfolio_win_rate": round(portfolio_win_rate, 4),
            "net_business_impact": round(net_business_impact, 4),
            "guardrail_retention_rate": round(guardrail_retention, 4),
            "rejection_quality": round(rejection_quality, 4),
            "score": round(commander_score, 4),
        },
        "overall": {
            "score": round(_clamp((captain_score + doctor_score + commander_score) / 3.0), 4),
            "status": "PASS" if (captain_score >= 0.7 and doctor_score >= 0.6 and commander_score >= 0.6) else ("WARN" if (captain_score >= 0.5 and doctor_score >= 0.45 and commander_score >= 0.45) else "FAIL"),
        },
        "version": "agent_effectiveness.outcome_v1",
    }

    out_json = Path(f"data/agent_reports/{run_id}_agent_effectiveness.json")
    _safe_write(out_json, json.dumps(payload, ensure_ascii=False, indent=2))

    improved: list[str] = []
    broke: list[str] = []
    missed: list[str] = []
    if payload["doctor"]["ab_success_rate"] > 0:
        improved.append("Doctor produced at least one approved hypothesis with rollout-level AB outcome.")
    else:
        broke.append("Doctor has no rollout-level AB win in this run.")
    if payload["captain_narrative"]["grounded_claim_rate"] < 0.8:
        broke.append("Narrative grounding is weak; claims lack enough evidence references.")
    if payload["captain_narrative"]["false_alarm_rate"] > 0.4:
        broke.append("High false alarm rate from proposed realism gaps.")
    if payload["commander"]["guardrail_retention_rate"] < 1.0:
        broke.append("Commander-approved path failed one or more guardrails.")
    if payload["doctor"]["methodology_mismatch_rate"] > 0:
        missed.append("Measurement mismatch detected; assignment/join reliability needs hardening.")
    if payload["doctor"]["underpowered_rate"] > 0:
        missed.append("AB sample size is underpowered for reliable decisioning.")

    next_fix = "Strengthen assignment integrity and evidence completeness before next RUN_AB decision."
    lines = [
        f"# AGENT SCOREBOARD — {run_id}",
        "",
        f"- Overall status: `{payload['overall']['status']}`",
        f"- Overall score: `{payload['overall']['score']:.3f}`",
        f"- Approvals source: `data/governance/approvals_{run_id}.json`",
        "",
        "## Scores",
        f"- Captain/Narrative: `{payload['captain_narrative']['score']:.3f}`",
        f"- Doctor: `{payload['doctor']['score']:.3f}`",
        f"- Commander: `{payload['commander']['score']:.3f}`",
        "",
        "## Metrics (Outcome-based)",
        f"- Doctor AB success rate: `{payload['doctor']['ab_success_rate']}`",
        f"- Doctor methodology mismatch rate: `{payload['doctor']['methodology_mismatch_rate']}`",
        f"- Commander portfolio win rate: `{payload['commander']['portfolio_win_rate']}`",
        f"- Captain/Narrative grounded claim rate: `{payload['captain_narrative']['grounded_claim_rate']}`",
        "",
        "## What agents improved",
        *([f"- {x}" for x in improved] if improved else ["- No major improvements detected in this run."]),
        "",
        "## What agents broke",
        *([f"- {x}" for x in broke] if broke else ["- No hard breakage detected."]),
        "",
        "## What they missed",
        *([f"- {x}" for x in missed] if missed else ["- No major blind spots detected."]),
        "",
        "## What to fix next",
        f"- {next_fix}",
        "",
    ]
    _safe_write(l1_dir / "AGENT_SCOREBOARD.md", "\n".join(lines))
    print(f"ok: agent effectiveness report written for run_id={run_id}")


if __name__ == "__main__":
    main()
