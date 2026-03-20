#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import write_sha256_sidecar

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
    if path.suffix.lower() == ".json":
        write_sha256_sidecar(path)


def _f(v: Any) -> float | None:
    try:
        return float(v)
    except Exception:
        return None


def _delta(a: Any, b: Any) -> float | None:
    fa, fb = _f(a), _f(b)
    if fa is None or fb is None:
        return None
    return fa - fb


def _mk_driver(
    idx: int,
    title: str,
    observation: str,
    mechanism: str,
    evidence_refs: list[str],
    confidence: str,
    alternative: str,
    next_check: str,
    impacted_metrics: list[str],
) -> dict[str, Any]:
    return {
        "driver_id": idx,
        "title": title,
        "observation": observation,
        "mechanism": mechanism,
        "evidence_refs": evidence_refs,
        "confidence": confidence,
        "alternative_explanation": alternative,
        "next_check": next_check,
        "impacted_metrics": impacted_metrics,
    }


def _metric_claim(metric_id: str, fact: Any, prev: Any, refs: list[str]) -> dict[str, Any]:
    ff = _f(fact)
    pp = _f(prev)
    if ff is None or pp is None:
        return {
            "metric_id": metric_id,
            "explanation_short": "Data unavailable for grounded explanation.",
            "explanation_long": "Current or previous value is missing; causal interpretation is blocked for this metric.",
            "evidence_refs": refs,
            "observation_delta": None,
            "root_cause": "missing_data",
            "confidence_level": "low",
            "alternative_explanations_considered": [
                "metric unavailable in current snapshot",
                "metric unavailable in previous snapshot",
            ],
        }
    delta_abs = ff - pp
    delta_rel = (delta_abs / pp) if pp != 0 else 0.0
    direction = "increased" if delta_abs >= 0 else "decreased"
    short = f"{metric_id} {direction} by {delta_abs:+.3f} ({delta_rel:+.2%}) versus previous period."
    long = (
        f"Observation: {metric_id} changed from {pp:.3f} to {ff:.3f} ({delta_abs:+.3f}, {delta_rel:+.2%}). "
        "This explanation is grounded in metrics snapshot values and should be interpreted together with "
        "availability, margin, and measurement-status checks."
    )
    return {
        "metric_id": metric_id,
        "observation_delta": {
            "fact": ff,
            "prev": pp,
            "delta_abs": delta_abs,
            "delta_pct": delta_rel,
        },
        "root_cause": "metric_shift_observed_in_snapshot",
        "explanation_short": short,
        "explanation_long": long,
        "evidence_refs": refs,
        "confidence_level": "medium",
        "alternative_explanations_considered": [
            "calendar_effect",
            "mix_shift",
            "measurement_noise",
        ],
    }


def _top_delta_metrics(curr: dict[str, Any], prev: dict[str, Any], limit: int = 3) -> list[str]:
    scored: list[tuple[float, str]] = []
    for k, v in curr.items():
        if isinstance(v, (int, float)) and isinstance(prev.get(k), (int, float)):
            pv = float(prev.get(k))
            cv = float(v)
            delta = abs(cv - pv)
            scored.append((delta, k))
    scored.sort(reverse=True)
    out: list[str] = []
    for _, k in scored:
        if k not in out:
            out.append(k)
        if len(out) >= limit:
            break
    return out


def _metric_group(metric: str) -> str:
    if metric in {"fill_rate_units", "oos_lost_gmv_rate", "lost_gmv_oos"}:
        return "availability"
    if metric in {"writeoff_units", "writeoff_cogs", "writeoff_rate_vs_requested_units", "perishable_gmv_share"}:
        return "spoilage"
    if metric in {"gmv", "aov", "gp", "gp_margin", "gp_per_order", "orders_cnt"}:
        return "unit_economics"
    if metric in {"active_buyers_avg", "new_buyers_7d", "churn_rate", "rep_mean"}:
        return "buyers"
    return "other"


def _norm_tokens(text: str, top_n: int = 8) -> str:
    toks = re.findall(r"[a-z0-9_]+", text.lower())
    if not toks:
        return ""
    uniq = []
    seen = set()
    for t in toks:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
        if len(uniq) >= top_n:
            break
    return " ".join(uniq)


def _top_delta_metrics_diverse(curr: dict[str, Any], prev: dict[str, Any], limit: int = 3) -> list[str]:
    ranked = _top_delta_metrics(curr, prev, limit=max(12, limit * 4))
    out: list[str] = []
    used_groups: set[str] = set()
    for metric in ranked:
        grp = _metric_group(metric)
        if grp not in used_groups:
            out.append(metric)
            used_groups.add(grp)
        if len(out) >= limit:
            return out
    for metric in ranked:
        if metric not in out:
            out.append(metric)
        if len(out) >= limit:
            break
    return out


def _causal_chain(
    idx: int,
    metric: str,
    fact: Any,
    prev: Any,
    run_id: str,
    *,
    ab_status: str,
    dq_fail: int,
    synthetic_bias: dict[str, Any],
) -> dict[str, Any]:
    ff = _f(fact)
    pp = _f(prev)
    action_trace_ref = f"artifact:data/decision_traces/{run_id}_actions.jsonl"
    approvals_ref = f"artifact:data/agent_governance/{run_id}_agent_approvals.json"
    if ff is None or pp is None:
        grp = _metric_group(metric)
        missing_cause = {
            "availability": "availability_oos",
            "spoilage": "goodhart_starvation_attempt",
            "unit_economics": "pricing_competitor_reactive",
            "buyers": "promo_cannibalization",
        }.get(grp, "demand_shock")
        claim_id = hashlib.sha1(f"{run_id}:{metric}:missing_data".encode("utf-8")).hexdigest()[:12]
        return {
            "claim_id": claim_id,
            "driver_rank": idx,
            "metric": metric,
            "observation_metric": metric,
            "baseline_value": pp,
            "fact_value": ff,
            "delta_pct": None,
            "observation": f"{metric} is missing in current or previous period.",
            "cause_type": missing_cause,
            "root_cause_statement": "Current evidence is incomplete, so root cause cannot be validated.",
            "evidence_refs": [
                {"source": "metrics_snapshot", "path": f"metrics.{metric}", "value": fact},
                {"source": "decision_trace", "path": action_trace_ref, "value": "required_for_decision_link"},
            ],
            "alternatives_considered": ["data_lag", "schema_gap"],
            "confidence": 0.2,
            "falsifiability_test": "Provide both baseline and fact values for this metric and recompute delta.",
            "recommendation_next_step": "restore_metric_pipeline",
            "expected_impact_range": "BLOCKED_BY_DATA",
            "evidence_pattern_hash": hashlib.sha1(f"{missing_cause}|{metric}".encode("utf-8")).hexdigest()[:12],
            "cause_signature_hash": hashlib.sha1(f"{missing_cause}|missing_data".encode("utf-8")).hexdigest()[:12],
        }
    delta_abs = ff - pp
    delta_pct = 0.0 if pp == 0 else (delta_abs / pp) * 100.0
    root = "metric_shift_observed"
    cause_type = "demand_shock"
    if metric in {"fill_rate_units", "oos_lost_gmv_rate", "lost_gmv_oos"}:
        root = "availability_change"
        cause_type = "availability_oos"
    elif metric in {"gmv", "aov", "gp", "gp_margin", "gp_per_order"}:
        root = "price_mix_or_competitor_reaction"
        cause_type = "pricing_competitor_reactive"
    elif metric in {"writeoff_units", "writeoff_cogs", "writeoff_rate_vs_requested_units", "perishable_gmv_share"}:
        root = "spoilage_policy_or_inventory_shift"
        cause_type = "goodhart_starvation_attempt"
    elif metric in {"orders_cnt", "active_buyers_avg", "new_buyers_7d"}:
        root = "promo_or_assortment_funnel_shift"
        cause_type = "promo_cannibalization"
    elif metric in {"churn_rate", "rep_mean"}:
        root = "supply_or_leadtime_service_shift"
        cause_type = "supply_leadtime"
    base_conf = 0.6
    if ab_status in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "UNDERPOWERED", "ASSIGNMENT_RECOVERED"}:
        base_conf -= 0.2
    if dq_fail > 0:
        base_conf -= 0.1
    if str((synthetic_bias or {}).get("status", "")).upper() in {"WARN", "FAIL"}:
        base_conf -= 0.1
    confidence = max(0.2, min(0.9, round(base_conf, 2)))
    obs = f"{metric} moved from {pp:.3f} to {ff:.3f} ({delta_abs:+.3f}, {delta_pct:+.2f}%)."
    claim_id = hashlib.sha1(f"{run_id}:{metric}:{cause_type}:{idx}".encode("utf-8")).hexdigest()[:12]
    evidence_refs = [
        {"source": "metrics_snapshot", "path": f"metrics.{metric}", "value": ff},
        {"source": "metrics_snapshot_prev", "path": f"metrics.{metric}", "value": pp},
        {"source": "decision_trace", "path": action_trace_ref, "value": "linked"},
        {"source": "approvals", "path": approvals_ref, "value": "linked"},
    ]
    metric_names_used = [metric, "fill_rate_units", "gp_margin", "oos_lost_gmv_rate"]
    root_text = f"{root}. This explanation is constrained by current decision and AB observability status."
    cause_signature_hash = hashlib.sha1(
        f"{cause_type}|{_norm_tokens(root_text, top_n=10)}".encode("utf-8")
    ).hexdigest()[:12]
    return {
        "claim_id": claim_id,
        "driver_rank": idx,
        "metric": metric,
        "observation_metric": metric,
        "baseline_value": pp,
        "fact_value": ff,
        "delta_pct": round(delta_pct, 3),
        "observation": obs,
        "cause_type": cause_type,
        "root_cause_statement": root_text,
        "evidence_refs": evidence_refs,
        "alternatives_considered": ["demand_shock", "pricing_effect", "measurement_noise"],
        "confidence": confidence,
        "falsifiability_test": "If store-day decomposition does not reproduce this delta direction, reject this claim.",
        "recommendation_next_step": f"review_driver_for_{metric}",
        "expected_impact_range": "+1%..+3%" if delta_pct < 0 else "-1%..-3%",
        "evidence_pattern_hash": hashlib.sha1(f"{cause_type}|{','.join(sorted(metric_names_used))}".encode("utf-8")).hexdigest()[:12],
        "cause_signature_hash": cause_signature_hash,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build grounded narrative explanation from evidence pack")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--evidence-pack", default="")
    args = parser.parse_args()

    run_id = args.run_id
    out_dir = Path(f"reports/L1_ops/{run_id}")
    log_path = Path(f"data/logs/narrative_analyst_{run_id}.log")
    try:
        evidence_path = Path(args.evidence_pack) if args.evidence_pack else out_dir / "evidence_pack.json"
        if not evidence_path.exists():
            raise SystemExit(f"Missing evidence pack: {evidence_path}")
        ep = json.loads(evidence_path.read_text(encoding="utf-8"))
        ev = ep.get("evidence", {}) if isinstance(ep.get("evidence"), dict) else {}
        snap = ev.get("metrics_snapshot", {}) if isinstance(ev.get("metrics_snapshot"), dict) else {}
        m = snap.get("metrics", {}) if isinstance(snap.get("metrics"), dict) else {}
        mbr_meta = ev.get("retail_mbr_meta", {}) if isinstance(ev.get("retail_mbr_meta"), dict) else {}
        prev_id = str(mbr_meta.get("prev_run_id_used", "") or "").strip()
        prev_snap = {}
        if prev_id:
            p = Path(f"data/metrics_snapshots/{prev_id}.json")
            if p.exists():
                prev_snap = json.loads(p.read_text(encoding="utf-8"))
        pm = prev_snap.get("metrics", {}) if isinstance(prev_snap.get("metrics"), dict) else {}
        ab = ev.get("ab_report", {}) if isinstance(ev.get("ab_report"), dict) else {}
        dq = ev.get("dq_report", {}) if isinstance(ev.get("dq_report"), dict) else {}
        doctor = ev.get("doctor", {}) if isinstance(ev.get("doctor"), dict) else {}
        evaluator = ev.get("evaluator", {}) if isinstance(ev.get("evaluator"), dict) else {}
        commander = ev.get("commander", {}) if isinstance(ev.get("commander"), dict) else {}
        synthetic_bias = ev.get("synthetic_bias_report", {}) if isinstance(ev.get("synthetic_bias_report"), dict) else {}

        ab_status = str(ab.get("status", "missing")).upper()
        blind = ab_status in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "ASSIGNMENT_RECOVERED", "UNDERPOWERED"}
        dq_rows = dq.get("rows", []) if isinstance(dq.get("rows"), list) else []
        dq_fail = sum(1 for r in dq_rows if isinstance(r, dict) and str(r.get("status")) == "FAIL")
        dq_warn = sum(1 for r in dq_rows if isinstance(r, dict) and str(r.get("status")) == "WARN")

        metric_priority = _top_delta_metrics_diverse(m, pm, limit=3)
        while len(metric_priority) < 3:
            for fallback in ("gmv", "fill_rate_units", "writeoff_cogs"):
                if fallback not in metric_priority:
                    metric_priority.append(fallback)
                if len(metric_priority) >= 3:
                    break

        claims: list[dict[str, Any]] = []
        drivers: list[dict[str, Any]] = []
        for i, mk in enumerate(metric_priority[:3], start=1):
            claim = _causal_chain(
                i,
                mk,
                m.get(mk),
                pm.get(mk),
                run_id,
                ab_status=ab_status,
                dq_fail=dq_fail,
                synthetic_bias=synthetic_bias,
            )
            claims.append(claim)
            evidence_refs = [
                f"artifact:data/metrics_snapshots/{run_id}.json#/metrics/{mk}",
                f"artifact:data/dq_reports/{run_id}.json#/rows",
                f"artifact:data/agent_reports/{run_id}_experiment_evaluator.json#/ab_status",
            ]
            drivers.append(
                _mk_driver(
                    idx=i,
                    title=f"Driver from {mk}",
                    observation=str(claim.get("observation")),
                    mechanism=str(claim.get("root_cause_statement")),
                    evidence_refs=evidence_refs,
                    confidence="high" if _f(claim.get("confidence")) and float(claim["confidence"]) >= 0.8 else "medium",
                    alternative=", ".join(claim.get("alternatives_considered", [])) if isinstance(claim.get("alternatives_considered"), list) else "none",
                    next_check=str(claim.get("falsifiability_test", "check metric decomposition")),
                    impacted_metrics=[mk],
                )
            )

        metric_ids = [
            "active_buyers_avg",
            "new_buyers_7d",
            "churn_rate",
            "rep_mean",
            "orders_cnt",
            "gmv",
            "aov",
            "gp",
            "gp_margin",
            "gp_per_order",
            "writeoff_units",
            "writeoff_cogs",
            "writeoff_rate_vs_requested_units",
            "perishable_gmv_share",
            "fill_rate_units",
            "oos_lost_gmv_rate",
            "lost_gmv_oos",
        ]
        metric_claims: dict[str, Any] = {}
        for mk in metric_ids:
            refs = [f"artifact:data/metrics_snapshots/{run_id}.json#/metrics/{mk}"]
            metric_claims[mk] = _metric_claim(mk, m.get(mk), pm.get(mk), refs)
        for claim in claims:
            mk = str(claim.get("metric", ""))
            if mk and isinstance(metric_claims.get(mk), dict):
                metric_claims[mk]["driver_id"] = str(claim.get("claim_id", ""))

        summary = []
        if blind:
            summary.append(
                "Measurement blind spot detected; causal uplift claims are disabled for this run."
            )
        summary.append(
            f"Decision path: evaluator={evaluator.get('decision', 'missing')}, commander={commander.get('normalized_decision', commander.get('decision', 'missing'))}."
        )
        summary.append(
            f"Top driver identified: {drivers[0]['title']} with confidence {claims[0].get('confidence')}."
        )
        summary.append(
            f"DQ context: fail={dq_fail}, warn={dq_warn}; synthetic_bias_status={synthetic_bias.get('status', 'missing')}."
        )

        payload = {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "blind_measurement": blind,
            "ab_status": ab_status,
            "executive_summary": summary,
            "drivers": drivers[:3],
            "causal_chains": claims[:3],
            "metric_claims": metric_claims,
            "data_quality_limits": [
                "No causal uplift interpretation allowed when assignment is missing/reconstructed/mismatched."
                if blind
                else "Causal interpretation allowed subject to guardrails and confidence bounds."
            ],
            "version": "causal_claims.v2",
        }

        out_json = out_dir / "causal_claims.json"
        _safe_write(out_json, json.dumps(payload, ensure_ascii=False, indent=2))
        _safe_write(Path(f"data/agent_reports/{run_id}_narrative_claims.json"), json.dumps(payload, ensure_ascii=False, indent=2))

        md_lines = [
            f"# Causal Explanation — {run_id}",
            "",
            "## Executive Summary",
            *[f"- {x}" for x in summary],
            "",
            "## Top 3 Drivers",
        ]
        for d in payload["drivers"]:
            md_lines.extend(
                [
                    f"<a id=\"driver-{d['driver_id']}\"></a>",
                    f"### Driver #{d['driver_id']}: {d['title']}",
                    f"- Observation: {d['observation']}",
                    f"- Mechanism: {d['mechanism']}",
                    f"- Evidence: {', '.join(d['evidence_refs'])}",
                    f"- Confidence: {d['confidence']}",
                    f"- Alternative: {d['alternative_explanation']}",
                    f"- Next check: {d['next_check']}",
                    "",
                ]
            )
        md_lines.extend(["## Metric-level short explanations"])
        for mk in metric_ids:
            c = metric_claims.get(mk, {})
            if not isinstance(c, dict):
                continue
            md_lines.append(f"- {mk}: {c.get('explanation_short')}")
        md_lines.extend(["", "## Structured Causal Chains"])
        for c in claims[:3]:
            md_lines.extend(
                [
                    f"### {c['claim_id']} ({c['metric']})",
                    f"- Observation: {c['observation']}",
                    f"- Root cause hypothesis: {c['root_cause_statement']}",
                    f"- Supporting evidence: {c['evidence_refs']}",
                    f"- Alternative explanations considered: {c['alternatives_considered']}",
                    f"- Confidence score: {c['confidence']}",
                    f"- What data confirms/refutes: {c['falsifiability_test']}",
                    f"- Actionable recommendation: {c['recommendation_next_step']}",
                    "",
                ]
            )
        md_lines.extend(
            [
                "## Data quality & measurement limits",
                *[f"- {x}" for x in payload["data_quality_limits"]],
                "",
            ]
        )
        _safe_write(out_dir / "CAUSAL_EXPLANATION.md", "\n".join(md_lines))
        en_lines = [line for line in md_lines]
        if en_lines and en_lines[0].startswith("# Causal Explanation"):
            en_lines[0] = f"# Causal Explanation (EN) — {run_id}"
        _safe_write(out_dir / "CAUSAL_EXPLANATION.en.md", "\n".join(en_lines))
        analyst_summary = {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "UNGROUNDED" if blind else "GROUNDED_CANDIDATE",
            "causal_chain_count": len(claims[:3]),
            "blocked_by_data": [x for x in payload["data_quality_limits"] if "No causal uplift" in x],
            "sources": {
                "metrics_snapshot": f"data/metrics_snapshots/{run_id}.json",
                "dq_report": f"data/dq_reports/{run_id}.json",
                "doctor": f"data/agent_reports/{run_id}_doctor_variance.json",
                "evaluator": f"data/agent_reports/{run_id}_experiment_evaluator.json",
                "commander": f"data/agent_reports/{run_id}_commander_priority.json",
                "synthetic_bias": f"data/realism_reports/{run_id}_synthetic_bias.json",
            },
            "version": "narrative_analyst.v2",
        }
        _safe_write(Path(f"data/agent_reports/{run_id}_narrative_analyst.json"), json.dumps(analyst_summary, ensure_ascii=False, indent=2))
        _safe_write(log_path, "ok: narrative analyst completed\n")
        print(f"ok: narrative analysis written for run_id={run_id}")
    except SystemExit as exc:
        msg = str(exc)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(_redact(f"blocked: {msg}\n"), encoding="utf-8")
        out_dir.mkdir(parents=True, exist_ok=True)
        skeleton = {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "BLOCKED_BY_DATA",
            "reason": msg,
            "causal_chains": [],
            "version": "causal_claims.v2",
        }
        _safe_write(out_dir / "causal_claims.json", json.dumps(skeleton, ensure_ascii=False, indent=2))
        _safe_write(Path(f"data/agent_reports/{run_id}_narrative_claims.json"), json.dumps(skeleton, ensure_ascii=False, indent=2))
        _safe_write(
            out_dir / "CAUSAL_EXPLANATION.md",
            f"# Causal Explanation — {run_id}\n\n⚠️ BLOCKED_BY_DATA\n\n- reason: `{msg}`\n",
        )
        _safe_write(out_dir / "CAUSAL_EXPLANATION.en.md", f"# Causal Explanation (EN) — {run_id}\n\n⚠️ BLOCKED_BY_DATA\n\n- reason: `{msg}`\n")
        print(f"WARN: narrative blocked by data for run_id={run_id}")
    except Exception:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(_redact(traceback.format_exc()), encoding="utf-8")
        out_dir.mkdir(parents=True, exist_ok=True)
        skeleton = {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "BLOCKED_BY_DATA",
            "reason": "narrative_runtime_failure",
            "causal_chains": [],
            "version": "causal_claims.v2",
        }
        _safe_write(out_dir / "causal_claims.json", json.dumps(skeleton, ensure_ascii=False, indent=2))
        _safe_write(Path(f"data/agent_reports/{run_id}_narrative_claims.json"), json.dumps(skeleton, ensure_ascii=False, indent=2))
        _safe_write(
            out_dir / "CAUSAL_EXPLANATION.md",
            f"# Causal Explanation — {run_id}\n\n⚠️ BLOCKED_BY_DATA\n\n- reason: `narrative_runtime_failure`\n- details: see `{log_path}`\n",
        )
        _safe_write(
            out_dir / "CAUSAL_EXPLANATION.en.md",
            f"# Causal Explanation (EN) — {run_id}\n\n⚠️ BLOCKED_BY_DATA\n\n- reason: `narrative_runtime_failure`\n- details: see `{log_path}`\n",
        )
        print(f"WARN: narrative analyst failed; fallback artifacts written for run_id={run_id}")


if __name__ == "__main__":
    main()
