#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent effectiveness v2 evaluation")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    out_dir = Path(f"reports/L1_ops/{run_id}")
    out_dir.mkdir(parents=True, exist_ok=True)

    captain = _load(Path(f"data/llm_reports/{run_id}_captain.json")) or {}
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
    commander = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}
    evaluator = _load(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")) or {}
    causal = _load(out_dir / "causal_claims.json") or {}
    claims_val = _load(out_dir / "causal_claims_validation.json") or {}
    mbr_csv = out_dir / "mbr_kpi.csv"

    metric_claims = causal.get("metric_claims", {}) if isinstance(causal.get("metric_claims"), dict) else {}
    unique_short = set()
    total_short = 0
    for c in metric_claims.values():
        if not isinstance(c, dict):
            continue
        s = str(c.get("explanation_short", "")).strip()
        if s:
            total_short += 1
            unique_short.add(s)
    uniqueness_rate = (len(unique_short) / total_short) if total_short else 0.0

    top_delta_coverage = 0.0
    if mbr_csv.exists():
        rows: list[dict[str, str]] = []
        with mbr_csv.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append(r)
        rows_sorted = sorted(rows, key=lambda r: abs(_f(r.get("delta_prev_abs"))), reverse=True)
        top = rows_sorted[:3]
        covered = 0
        for r in top:
            metric_key = ""
            for k, c in metric_claims.items():
                if isinstance(c, dict) and str(c.get("metric_id", "")) == str(k):
                    if str(r.get("kpi", "")).lower().find(str(k).replace("_", " ").lower()) >= 0:
                        metric_key = k
                        break
            if metric_key:
                covered += 1
        top_delta_coverage = (covered / len(top)) if top else 0.0

    grounded_rate = 1.0 if bool(claims_val.get("grounded", False)) else 0.0
    causal_md = (out_dir / "CAUSAL_EXPLANATION.md").read_text(encoding="utf-8") if (out_dir / "CAUSAL_EXPLANATION.md").exists() else ""
    counterfactual_present = "Alternative:" in causal_md

    ab_plan = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
    first = ab_plan[0] if ab_plan and isinstance(ab_plan[0], dict) else {}
    hyps = first.get("hypotheses", []) if isinstance(first.get("hypotheses"), list) else []
    h0 = hyps[0] if hyps and isinstance(hyps[0], dict) else {}

    cap_eval = captain.get("eval_metrics", {}) if isinstance(captain.get("eval_metrics"), dict) else {}
    fallback_used = bool(captain.get("fallback_used"))
    captain_score = (
        0.4 * (1.0 if bool(cap_eval.get("no_extra_issues", False)) else 0.0)
        + 0.3 * _f(cap_eval.get("actionability"))
        + 0.3 * (1.0 if bool(cap_eval.get("safety", False)) else 0.0)
    )
    if fallback_used:
        captain_score = max(0.0, captain_score - 0.2)

    doctor_go = str(doctor.get("normalized_decision", doctor.get("decision", ""))).upper() in {"RUN_AB", "ROLLOUT_CANDIDATE"}
    evidence_ready = str(doctor.get("assignment_status", "")).lower() in {"ready", "present"} and bool((doctor.get("evidence") or {}).get("ab_report")) if isinstance(doctor.get("evidence"), dict) else False
    go_without_evidence = doctor_go and not evidence_ready

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "narrative": {
            "grounded_rate": grounded_rate,
            "uniqueness_rate": uniqueness_rate,
            "top_delta_coverage": top_delta_coverage,
            "counterfactual_present": counterfactual_present,
        },
        "doctor": {
            "hypothesis_mechanism_present": bool(str(h0.get("mechanism", "")).strip() or h0.get("mechanism")),
            "methodology_complete": bool(first.get("methodology") and first.get("sample_size_gate")),
            "evidence_density": len((doctor.get("evidence") or {}).get("artifacts", [])) if isinstance((doctor.get("evidence") or {}).get("artifacts"), list) else 0,
            "go_without_evidence_penalty": bool(go_without_evidence),
        },
        "captain": {
            "non_hallucination": bool(cap_eval.get("no_extra_issues", False)),
            "actionable_sql_correctness": _f(cap_eval.get("actionability")),
            "fallback_used": fallback_used,
            "fallback_penalty_applied": fallback_used,
            "score": captain_score,
        },
        "commander": {
            "decision": commander.get("normalized_decision", commander.get("decision")),
            "blocked_by_count": len(commander.get("blocked_by", []) if isinstance(commander.get("blocked_by"), list) else []),
        },
        "evaluator": {
            "decision": evaluator.get("decision"),
            "ab_status": evaluator.get("ab_status"),
        },
        "version": "agent_effectiveness.v2",
    }

    out_json = out_dir / "agent_effectiveness.json"
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [
        f"# Agent Effectiveness v2 — {run_id}",
        "",
        "## Narrative",
        f"- grounded_rate: `{grounded_rate:.3f}`",
        f"- uniqueness_rate: `{uniqueness_rate:.3f}`",
        f"- top_delta_coverage: `{top_delta_coverage:.3f}`",
        f"- counterfactual_present: `{counterfactual_present}`",
        "",
        "## Doctor",
        f"- hypothesis_mechanism_present: `{payload['doctor']['hypothesis_mechanism_present']}`",
        f"- methodology_complete: `{payload['doctor']['methodology_complete']}`",
        f"- evidence_density: `{payload['doctor']['evidence_density']}`",
        f"- go_without_evidence_penalty: `{payload['doctor']['go_without_evidence_penalty']}`",
        "",
        "## Captain",
        f"- non_hallucination: `{payload['captain']['non_hallucination']}`",
        f"- actionable_sql_correctness: `{payload['captain']['actionable_sql_correctness']}`",
        f"- fallback_used: `{payload['captain']['fallback_used']}`",
        f"- fallback_penalty_applied: `{payload['captain']['fallback_penalty_applied']}`",
        f"- score: `{payload['captain']['score']:.3f}`",
        "",
    ]
    (out_dir / "agent_effectiveness.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"ok: agent effectiveness v2 written for run_id={run_id}")


if __name__ == "__main__":
    main()
