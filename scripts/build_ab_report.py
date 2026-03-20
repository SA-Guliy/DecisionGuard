#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
import sys

from scipy import stats  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.status_taxonomy import AB_DECISION_INVALID_STATUSES, MEASUREMENT_BLOCKED_STATES, goal_from_metric as _goal_from_metric
from src.architecture_v3 import load_anti_goodhart_verdict

BLOCKED_STATUSES = set(AB_DECISION_INVALID_STATUSES)

METHOD_BY_METRIC: dict[str, str] = {
    "aov": "Welch t-test",
    "gmv": "Welch t-test",
    "orders_cnt": "Welch t-test",
    "active_buyers_avg": "Welch t-test",
    "new_buyers_7d": "Bootstrap (count metric)",
    "writeoff_units": "Bootstrap (count metric)",
    "writeoff_cogs": "Bootstrap (continuous monetary metric)",
    "gp_margin": "Delta Method / Bootstrap",
    "fill_rate_units": "Delta Method / Bootstrap",
    "oos_lost_gmv_rate": "Delta Method / Bootstrap",
}

OBSERVED_METRIC_ORDER: list[str] = [
    "orders_cnt",
    "gmv",
    "gp",
    "gp_margin",
    "aov",
    "fill_rate_units",
    "lost_gmv_oos",
    "oos_lost_gmv_rate",
    "new_buyers_7d",
    "active_buyers_avg",
    "churn_rate",
    "rep_mean",
    "writeoff_units",
    "writeoff_cogs",
    "writeoff_rate_vs_requested_units",
]


def _methodology_meta_for_metric(metric: str) -> dict[str, str]:
    m = (metric or "").strip().lower()
    if m in {"aov", "gmv", "gp_per_order", "orders_cnt", "active_buyers_avg"}:
        return {
            "metric_type": "continuous",
            "statistical_principle": "Two-sample tests: two population means",
            "test_family": "Welch t-test (unequal variances)",
            "reason_selected": "Continuous metric at two-arm comparison; Welch is robust to unequal variances and unequal sample sizes.",
            "null_hypothesis_metric": f"{m}_t = {m}_c",
            "alternative_hypothesis_metric": f"{m}_t != {m}_c",
        }
    if m in {"buyers", "new_buyers_7d"}:
        return {
            "metric_type": "proportion_or_count",
            "statistical_principle": "Two-sample tests: proportions / conversion-type outcomes",
            "test_family": "Two-proportion test or bootstrap on unit-level binary outcomes",
            "reason_selected": "Buyer outcomes are count/conversion-like; compare arm-level rates on the randomized unit.",
            "null_hypothesis_metric": f"{m}_t = {m}_c",
            "alternative_hypothesis_metric": f"{m}_t != {m}_c",
        }
    if m in {"gp_margin", "fill_rate_units", "oos_lost_gmv_rate", "writeoff_rate_adj"}:
        return {
            "metric_type": "ratio_or_proportion",
            "statistical_principle": "Two-sample tests: proportions / ratio metrics",
            "test_family": "Delta method or bootstrap (policy-selected by metric type)",
            "reason_selected": "Ratio/proportion metric; normality on raw values is less reliable, so ratio-aware method policy is preferred.",
            "null_hypothesis_metric": f"{m}_t = {m}_c",
            "alternative_hypothesis_metric": f"{m}_t != {m}_c",
        }
    return {
        "metric_type": "unknown",
        "statistical_principle": "Method policy fallback by metric type",
        "test_family": "Metric-specific deterministic policy",
        "reason_selected": "Metric is not in the strict map; report falls back to deterministic policy metadata and requires manual review.",
        "null_hypothesis_metric": f"{m or 'metric'}_t = {m or 'metric'}_c",
        "alternative_hypothesis_metric": f"{m or 'metric'}_t != {m or 'metric'}_c",
    }


def _doctor_methodology_meta(doctor: dict[str, Any], ab_primary_metric: str) -> dict[str, Any] | None:
    if not isinstance(doctor, dict):
        return None
    candidates: list[dict[str, Any]] = []
    if isinstance(doctor.get("ab_interpretation_methodology"), dict):
        candidates.append(doctor["ab_interpretation_methodology"])
    rec = doctor.get("recommended_experiment", {}) if isinstance(doctor.get("recommended_experiment"), dict) else {}
    if isinstance(rec.get("statistical_methodology"), dict):
        candidates.append(rec["statistical_methodology"])
    ab_plan = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
    if ab_plan and isinstance(ab_plan[0], dict) and isinstance(ab_plan[0].get("statistical_methodology"), dict):
        candidates.append(ab_plan[0]["statistical_methodology"])
    for sm in candidates:
        primary_metric = str(sm.get("primary_metric", "")).strip()
        if primary_metric and ab_primary_metric and primary_metric != ab_primary_metric:
            continue
        prov = sm.get("selection_provenance", {}) if isinstance(sm.get("selection_provenance"), dict) else {}
        val = sm.get("validation", {}) if isinstance(sm.get("validation"), dict) else {}
        return {
            "metric_type": str(sm.get("metric_type", "unknown") or "unknown"),
            "statistical_principle": str(sm.get("statistical_principle", "") or "").strip() or "Missing (doctor output)",
            "test_family": str(sm.get("test_family", "") or "").strip() or "Missing (doctor output)",
            "reason_selected": str(sm.get("reason_selected", "") or "").strip() or "Doctor output missing method rationale.",
            "null_hypothesis_metric": str(sm.get("null_hypothesis_metric", "") or "").strip() or f"{(ab_primary_metric or 'metric')}_t = {(ab_primary_metric or 'metric')}_c",
            "alternative_hypothesis_metric": str(sm.get("alternative_hypothesis_metric", "") or "").strip() or f"{(ab_primary_metric or 'metric')}_t != {(ab_primary_metric or 'metric')}_c",
            "test_side": str(sm.get("test_side", "two-sided") or "two-sided"),
            "selected_by": str(prov.get("selected_by", "doctor_unknown") or "doctor_unknown"),
            "selection_mode": str(prov.get("selection_mode", "unknown") or "unknown"),
            "fallback_reason": str(prov.get("fallback_reason", "") or "").strip(),
            "model_intent": str(prov.get("model_intent", "") or "").strip(),
            "why_not_alternatives": str(sm.get("why_not_alternatives", "") or "").strip(),
            "alternatives_considered": sm.get("alternatives_considered", []) if isinstance(sm.get("alternatives_considered"), list) else [],
            "executor_method": str(sm.get("executor_method", "") or "").strip(),
            "validation_passed": bool(val.get("passed", False)),
            "validation_issues": val.get("issues", []) if isinstance(val.get("issues"), list) else [],
        }
    return None


def _methodology_meta_from_doctor_or_policy(doctor: dict[str, Any], ab_primary_metric: str) -> dict[str, Any]:
    doc_meta = _doctor_methodology_meta(doctor, ab_primary_metric)
    if isinstance(doc_meta, dict):
        return doc_meta
    base = _methodology_meta_for_metric(ab_primary_metric)
    base.update(
        {
            "test_side": "two-sided",
            "selected_by": "deterministic_policy_from_metric_type",
            "selection_mode": "fallback",
            "fallback_reason": "doctor_methodology_missing",
            "model_intent": "",
            "why_not_alternatives": "",
            "alternatives_considered": [],
            "executor_method": "",
            "validation_passed": True,
            "validation_issues": [],
        }
    )
    return base


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _safe_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _safe_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _fmt_num(v: Any, d: int = 4) -> str:
    try:
        return f"{float(v):.{d}f}"
    except Exception:
        return "—"


def _fmt_pct(v: Any, d: int = 2) -> str:
    try:
        return f"{float(v) * 100:.{d}f}%"
    except Exception:
        return "—"


def _fmt_money(v: Any, d: int = 2) -> str:
    try:
        return f"${float(v):.{d}f}"
    except Exception:
        return "—"


def _to_float(v: Any) -> float | None:
    try:
        if v is None:
            return None
        return float(v)
    except Exception:
        return None


def _load_goal1_store_week_category_rows(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    ref = str(snapshot.get("goal1_store_week_category_ref", "")).strip()
    if not ref:
        return []
    path = Path(ref)
    candidates = [path]
    if not path.is_absolute():
        candidates.append(ROOT / path)
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                return [r for r in payload if isinstance(r, dict)]
            if isinstance(payload, dict):
                rows = payload.get("rows")
                if isinstance(rows, list):
                    return [r for r in rows if isinstance(r, dict)]
        except Exception:
            return []
    return []


def _summarize_goal1_store_week_category(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "rows": len(rows),
        "stores": 0,
        "weeks": 0,
        "categories": 0,
        "received_cogs": None,
        "sold_cogs": None,
        "expiry_writeoff_cogs": None,
        "dairy_meat_present": False,
        "store_high_low_split_ready": False,
        "top_categories_by_writeoff": [],
    }
    if not rows:
        return summary
    stores = {str(r.get("store_id", "")).strip() for r in rows if str(r.get("store_id", "")).strip()}
    weeks = {str(r.get("iso_week", "")).strip() for r in rows if str(r.get("iso_week", "")).strip()}
    categories = {str(r.get("category_id", "")).strip() for r in rows if str(r.get("category_id", "")).strip()}

    received_cogs = 0.0
    sold_cogs = 0.0
    expiry_writeoff_cogs = 0.0
    cat_writeoff: dict[str, float] = {}
    store_totals: dict[str, dict[str, float]] = {}
    for r in rows:
        rec = _to_float(r.get("received_cogs")) or 0.0
        sold = _to_float(r.get("sold_cogs")) or 0.0
        wr_exp = _to_float(r.get("expiry_writeoff_cogs")) or 0.0
        received_cogs += rec
        sold_cogs += sold
        expiry_writeoff_cogs += wr_exp
        cat = str(r.get("category_id", "")).strip() or "unknown"
        cat_writeoff[cat] = cat_writeoff.get(cat, 0.0) + wr_exp
        store = str(r.get("store_id", "")).strip()
        if store:
            st = store_totals.setdefault(store, {"rec": 0.0, "wr": 0.0})
            st["rec"] += rec
            st["wr"] += wr_exp

    per_store_rates: list[float] = []
    for totals in store_totals.values():
        if totals["rec"] > 0:
            per_store_rates.append(totals["wr"] / totals["rec"])
    per_store_rates.sort()

    top_categories = sorted(cat_writeoff.items(), key=lambda x: x[1], reverse=True)[:2]
    category_tokens = {c.lower() for c in categories}
    summary.update(
        {
            "stores": len(stores),
            "weeks": len(weeks),
            "categories": len(categories),
            "received_cogs": received_cogs,
            "sold_cogs": sold_cogs,
            "expiry_writeoff_cogs": expiry_writeoff_cogs,
            "dairy_meat_present": ("dairy" in category_tokens and "meat" in category_tokens),
            "store_high_low_split_ready": len(per_store_rates) >= 2,
            "top_categories_by_writeoff": top_categories,
        }
    )
    return summary


def _fmt_metric_value(metrics: dict[str, Any], key: str) -> str:
    value = metrics.get(key)
    if key in {"aov", "gmv", "gp", "lost_gmv_oos", "writeoff_cogs"}:
        return _fmt_money(value, 2)
    if key in {"gp_margin", "fill_rate_units", "oos_lost_gmv_rate", "churn_rate", "writeoff_rate_vs_requested_units"}:
        return _fmt_pct(value, 2)
    if key in {"orders_cnt", "new_buyers_7d", "writeoff_units", "active_buyers_avg"}:
        return _fmt_num(value, 0)
    return _fmt_num(value, 2)


def _observed_metric_keys(metrics: dict[str, Any]) -> list[str]:
    extras = sorted([k for k in metrics.keys() if k not in OBSERVED_METRIC_ORDER])
    return [*OBSERVED_METRIC_ORDER, *extras]


def _goal_observed_metrics_rows(
    *,
    metrics: dict[str, Any],
    primary_metric: str,
    supporting_metrics: list[str],
    guardrails: list[str],
) -> list[dict[str, Any]]:
    supporting_set = set(supporting_metrics)
    guardrail_set = set(guardrails)
    rows: list[dict[str, Any]] = []
    for metric_name in _observed_metric_keys(metrics):
        if metric_name == primary_metric:
            role = "primary"
        elif metric_name in supporting_set:
            role = "supporting"
        elif metric_name in guardrail_set:
            role = "guardrail"
        else:
            role = "observed"
        rows.append(
            {
                "metric": metric_name,
                "role": role,
                "value": metrics.get(metric_name),
                "display_value": _fmt_metric_value(metrics, metric_name),
            }
        )
    return rows


def _find_ab(run_id: str, experiment_id: str) -> Path | None:
    if experiment_id.strip():
        p = Path(f"data/ab_reports/{run_id}_{experiment_id.strip()}_ab.json")
        return p if p.exists() else None
    candidates = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab.json"))
    return candidates[0] if candidates else None


def _find_prev_snapshot(run_id: str, now_snapshot: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    now_ts = str(now_snapshot.get("generated_at", "")).strip()
    try:
        now_dt = datetime.fromisoformat(now_ts.replace("Z", "+00:00"))
    except Exception:
        now_dt = None
    best: tuple[datetime, Path] | None = None
    for p in Path("data/metrics_snapshots").glob("*.json"):
        if p.stem == run_id:
            continue
        snap = _load_json(p) or {}
        ts = str(snap.get("generated_at", "")).strip()
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            continue
        if now_dt and dt >= now_dt:
            continue
        if best is None or dt > best[0]:
            best = (dt, p)
    if not best:
        return None, None
    prev_path = best[1]
    return prev_path.stem, _load_json(prev_path)


@dataclass
class WelchStats:
    p_value: float | None
    ci_low_rel: float | None
    ci_high_rel: float | None
    delta_abs: float | None
    delta_rel: float | None
    method: str


def _welch_stats(
    mean_c: float,
    var_c: float,
    n_c: int,
    mean_t: float,
    var_t: float,
    n_t: int,
    alpha: float,
) -> WelchStats:
    if n_c <= 1 or n_t <= 1:
        return WelchStats(None, None, None, None, None, "welch_t_test")
    se2 = (var_c / n_c) + (var_t / n_t)
    if se2 <= 0:
        return WelchStats(None, None, None, None, None, "welch_t_test")
    se = math.sqrt(se2)
    num = se2 * se2
    den = ((var_c / n_c) ** 2) / (n_c - 1) + ((var_t / n_t) ** 2) / (n_t - 1)
    if den <= 0:
        return WelchStats(None, None, None, None, None, "welch_t_test")
    df = num / den
    delta_abs = mean_t - mean_c
    delta_rel = (delta_abs / mean_c) if mean_c != 0 else None
    t_crit = float(stats.t.ppf(1.0 - (alpha / 2.0), df))
    ci_low_abs = delta_abs - (t_crit * se)
    ci_high_abs = delta_abs + (t_crit * se)
    ci_low_rel = (ci_low_abs / mean_c) if mean_c != 0 else None
    ci_high_rel = (ci_high_abs / mean_c) if mean_c != 0 else None
    p_value = float(
        stats.ttest_ind_from_stats(
            mean1=mean_t,
            std1=math.sqrt(max(var_t, 0.0)),
            nobs1=n_t,
            mean2=mean_c,
            std2=math.sqrt(max(var_c, 0.0)),
            nobs2=n_c,
            equal_var=False,
        ).pvalue
    )
    return WelchStats(p_value, ci_low_rel, ci_high_rel, delta_abs, delta_rel, "welch_t_test")


def _extract_top_hypothesis(doctor: dict[str, Any]) -> dict[str, Any]:
    portfolio = doctor.get("hypothesis_portfolio", []) if isinstance(doctor.get("hypothesis_portfolio"), list) else []
    rows = [x for x in portfolio if isinstance(x, dict)]
    rows.sort(
        key=lambda h: (
            int(h.get("rank", 9999)) if str(h.get("rank", "")).isdigit() else 9999,
            -float(h.get("ice_score", 0.0) or 0.0),
        )
    )
    return rows[0] if rows else {}


def _resolve_current_ab_contract_metric(doctor: dict[str, Any]) -> tuple[str | None, str]:
    if not isinstance(doctor, dict):
        return None, "missing_doctor"
    rec = doctor.get("recommended_experiment", {}) if isinstance(doctor.get("recommended_experiment"), dict) else {}
    rec_sm = rec.get("statistical_methodology", {}) if isinstance(rec.get("statistical_methodology"), dict) else {}
    ab_plan = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
    first_exp = ab_plan[0] if ab_plan and isinstance(ab_plan[0], dict) else {}
    first_sm = first_exp.get("statistical_methodology", {}) if isinstance(first_exp.get("statistical_methodology"), dict) else {}
    ab_interp = doctor.get("ab_interpretation_methodology", {}) if isinstance(doctor.get("ab_interpretation_methodology"), dict) else {}
    candidates: list[tuple[str, Any]] = [
        ("doctor.ab_interpretation_methodology.primary_metric", ab_interp.get("primary_metric")),
        ("doctor.recommended_experiment.statistical_methodology.primary_metric", rec_sm.get("primary_metric")),
        ("doctor.ab_plan[0].statistical_methodology.primary_metric", first_sm.get("primary_metric")),
        ("doctor.recommended_experiment.metric", rec.get("metric")),
        ("doctor.ab_plan[0].metric", first_exp.get("metric")),
    ]
    for source, value in candidates:
        metric = str(value or "").strip()
        if metric:
            return metric, source
    return None, "missing"


def _decision_by_rules(
    p_value: float | None,
    ci_low: float | None,
    ci_high: float | None,
    alpha: float,
    underpowered: bool,
) -> tuple[str, str, bool]:
    if p_value is None or ci_low is None or ci_high is None:
        return ("INCONCLUSIVE", "Missing p-value/CI for primary metric.", False)
    ci_contains_zero = ci_low <= 0.0 <= ci_high
    inconsistent = ((p_value <= alpha) and ci_contains_zero) or ((p_value > alpha) and (not ci_contains_zero))
    if inconsistent:
        return ("INVALID_METHODS", "ERROR: Mathematical inconsistency detected in pipeline.", True)
    if underpowered:
        return ("UNDERPOWERED", "INCONCLUSIVE (UNDERPOWERED)", False)
    if p_value <= alpha and not ci_contains_zero:
        return ("OK", "Reject H0. The result is statistically significant.", False)
    return (
        "INCONCLUSIVE",
        "Fail to Reject H0. The result is NOT statistically significant. Any observed delta is indistinguishable from random noise.",
        False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build deterministic AB report v2")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--alpha", type=float, default=0.05)
    args = parser.parse_args()

    run_id = args.run_id
    alpha = float(args.alpha)
    ci_level = int(round((1 - alpha) * 100))

    out_md = Path(f"reports/L1_ops/{run_id}/AB_STAT_REPORT.md")
    out_md_canonical = Path(f"reports/L1_ops/{run_id}/AB_STAT_REPORT_CANONICAL.md")
    out_json_base = Path(f"data/ab_reports/{run_id}_unknown_ab_v2.json")
    log_path = Path(f"data/logs/build_ab_report_{run_id}.log")

    try:
        ab_path = _find_ab(run_id, args.experiment_id)
        if not ab_path:
            missing_md = "\n".join(
                [
                    f"# AB Statistical Report — {run_id}",
                    "",
                    "FATAL: AB report artifact is missing.",
                ]
            )
            _safe_write(out_md, missing_md)
            _safe_write(out_md_canonical, missing_md)
            _safe_write_json(out_json_base, {"run_id": run_id, "status": "BLOCKED_BY_DATA", "reason": "missing_ab_artifact"})
            print(f"ok: ab report v2 written for run_id={run_id}")
            return

        ab = _load_json(ab_path) or {}
        experiment_id = str(ab.get("experiment_id", "")).strip() or "unknown"
        out_json = Path(f"data/ab_reports/{run_id}_{experiment_id}_ab_v2.json")

        doctor = _load_json(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
        evaluator = _load_json(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")) or {}
        snapshot = _load_json(Path(f"data/metrics_snapshots/{run_id}.json")) or {}
        prev_run_id, prev_snapshot = _find_prev_snapshot(run_id, snapshot)
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        prev_metrics = prev_snapshot.get("metrics", {}) if isinstance(prev_snapshot, dict) and isinstance(prev_snapshot.get("metrics"), dict) else {}
        goal1_store_week_category_rows = _load_goal1_store_week_category_rows(snapshot)
        goal1_store_week_category_summary = _summarize_goal1_store_week_category(goal1_store_week_category_rows)
        run_cfg = snapshot.get("run_config", {}) if isinstance(snapshot.get("run_config"), dict) else {}
        data_source_type = str(snapshot.get("data_source_type", "unknown")).strip().lower() if isinstance(snapshot, dict) else "unknown"
        contract_completeness = snapshot.get("contract_completeness", {}) if isinstance(snapshot.get("contract_completeness"), dict) else {}
        goal1_contract_ready = bool(contract_completeness.get("goal1_contract_ready", False))

        summary = ab.get("summary", {}) if isinstance(ab.get("summary"), dict) else {}
        ab_design_contract = summary.get("ab_design_contract", {}) if isinstance(summary.get("ab_design_contract"), dict) else {}
        arms = ab.get("arms", {}) if isinstance(ab.get("arms"), dict) else {}
        ab_failure_meta = ab.get("failure_meta", {}) if isinstance(ab.get("failure_meta"), dict) else {}
        c = arms.get("control", {}) if isinstance(arms.get("control"), dict) else {}
        t = arms.get("treatment", {}) if isinstance(arms.get("treatment"), dict) else {}
        sample_gate = ab.get("sample_size_gate", {}) if isinstance(ab.get("sample_size_gate"), dict) else {}

        top_h = _extract_top_hypothesis(doctor)
        hypothesis_stmt = str(top_h.get("hypothesis_statement", "")).strip() or "missing"
        next_target_metric = str(top_h.get("target_metric", "")).strip()
        next_target_goal = _goal_from_metric(next_target_metric)
        ab_primary_metric = str(summary.get("primary_metric", "")).strip()
        ab_primary_goal = _goal_from_metric(ab_primary_metric)
        current_contract_metric, current_contract_source = _resolve_current_ab_contract_metric(doctor)
        current_contract_goal = _goal_from_metric(current_contract_metric or "")
        meth_meta = _methodology_meta_from_doctor_or_policy(doctor, ab_primary_metric)
        method_label = str(meth_meta.get("test_family") or METHOD_BY_METRIC.get(ab_primary_metric, "Metric-specific method (see contract)"))
        if current_contract_metric:
            if current_contract_goal != "unknown" and ab_primary_goal != "unknown":
                current_alignment_status = "PASS" if current_contract_goal == ab_primary_goal else "FAIL"
            else:
                current_alignment_status = "INCONCLUSIVE"
        else:
            current_alignment_status = "N/A_NO_CURRENT_CONTRACT_METRIC"
        next_alignment_status = (
            "MATCH"
            if (next_target_goal != "unknown" and ab_primary_goal != "unknown" and next_target_goal == ab_primary_goal)
            else ("DIFFERENT" if next_target_goal != "unknown" and ab_primary_goal != "unknown" else "UNKNOWN")
        )

        measurement_state = str(doctor.get("measurement_state", evaluator.get("measurement_state", ""))).upper()
        base_status = str(ab.get("status", "")).upper()
        unit = str(ab.get("unit_type", run_cfg.get("experiment_unit", "unknown")))
        unit_cfg = str(run_cfg.get("experiment_unit", "unknown"))
        unit_alignment_status = "PASS" if (unit.lower() == unit_cfg.lower()) else "FAIL"
        treat_pct = int(run_cfg.get("experiment_treat_pct", 50) or 50)
        duration_days = int(run_cfg.get("horizon_days", 14) or 14)
        window_start = str(run_cfg.get("start_date", "missing"))
        window_end = str(run_cfg.get("end_date", "missing"))
        assignment_salt = str(run_cfg.get("experiment_salt", "missing"))

        mean_c = float(c.get("mean_aov", 0.0) or 0.0)
        mean_t = float(t.get("mean_aov", 0.0) or 0.0)
        var_c = float(c.get("var_aov", 0.0) or 0.0)
        var_t = float(t.get("var_aov", 0.0) or 0.0)
        n_c = int(float(c.get("n_orders", 0) or 0))
        n_t = int(float(t.get("n_orders", 0) or 0))
        welch = _welch_stats(mean_c, var_c, n_c, mean_t, var_t, n_t, alpha)

        min_orders = int(sample_gate.get("min_orders_per_arm", 0) or 0)
        min_units = int(sample_gate.get("min_units_per_arm", 0) or 0)
        n_units_c = int(float(summary.get("n_units_control", 0) or 0))
        n_units_t = int(float(summary.get("n_units_treatment", 0) or 0))
        underpowered = (n_c < min_orders) or (n_t < min_orders) or (n_units_c < min_units) or (n_units_t < min_units)

        decision_status, decision_text, inconsistent = _decision_by_rules(
            p_value=welch.p_value,
            ci_low=welch.ci_low_rel,
            ci_high=welch.ci_high_rel,
            alpha=alpha,
            underpowered=underpowered,
        )

        final_status = base_status
        fatal_reason = ""
        if current_alignment_status == "FAIL":
            final_status = "INVALID_METHODS"
            fatal_reason = "CURRENT_AB_CONTRACT_METRIC_MISMATCH"
        elif data_source_type not in {"synthetic", "real", "mixed"}:
            final_status = "BLOCKED_BY_DATA"
            fatal_reason = f"unknown_data_source_type:{data_source_type or 'missing'}"
        elif ab_primary_metric in {"writeoff_rate_adj", "writeoff_units", "writeoff_cogs"} and not goal1_contract_ready:
            final_status = "BLOCKED_BY_DATA"
            fatal_reason = "goal1_contract_incomplete"
        elif measurement_state in MEASUREMENT_BLOCKED_STATES:
            final_status = "BLOCKED_BY_DATA"
            fatal_reason = f"measurement_state={measurement_state}"
        elif base_status in BLOCKED_STATUSES:
            final_status = base_status
            fatal_reason = f"ab_status={base_status}"
        elif inconsistent:
            final_status = "INVALID_METHODS"
            fatal_reason = "p-value and CI disagreement"
        else:
            final_status = decision_status if decision_status in {"OK", "UNDERPOWERED", "INCONCLUSIVE"} else base_status

        error_rows: list[tuple[str, str, str]] = []
        fm_code = str(ab_failure_meta.get("error_code", "") or "").strip().upper()
        fm_family = str(ab_failure_meta.get("error_family", "") or "").strip()
        if fm_code and fm_code != "NONE":
            layer_map = {
                "DATA_SCHEMA": "Data Schema",
                "DATA_JOIN": "Data/Join",
                "DATA_ACCESS": "Data Access",
                "DATA_ASSIGNMENT": "Data Assignment",
                "DATA_CONTRACT": "Data Contract",
                "CONTRACT": "Contract",
                "METHOD": "Method",
                "STATS": "Statistics",
            }
            error_rows.append(
                (
                    fm_code,
                    layer_map.get(fm_family, fm_family or "Unknown"),
                    "AB analysis failure_meta (root cause from preflight/runtime checks).",
                )
            )
        if current_alignment_status == "FAIL":
            error_rows.append(
                (
                    "CONTRACT_CURRENT_AB_METRIC_MISMATCH",
                    "Contract",
                    f"Current AB contract goal `{current_contract_goal}` does not match AB primary metric goal `{ab_primary_goal}`.",
                )
            )
        if next_alignment_status == "DIFFERENT":
            error_rows.append(
                (
                    "CONTEXT_NEXT_CONTOUR_DIFFERS_FROM_CURRENT_AB",
                    "Context",
                    f"Next experiment goal `{next_target_goal}` differs from current AB goal `{ab_primary_goal}` (informational, not fatal).",
                )
            )
        if unit_alignment_status != "PASS":
            error_rows.append(
                (
                    "CONTRACT_UNIT_ALIGNMENT_FAIL",
                    "Contract",
                    f"AB unit `{unit}` differs from run_config experiment_unit `{unit_cfg}`.",
                )
            )
        if ab_primary_metric in {"writeoff_rate_adj", "writeoff_units", "writeoff_cogs"} and not goal1_contract_ready:
            error_rows.append(
                (
                    "DATA_GOAL1_CONTRACT_INCOMPLETE",
                    "Data Contract",
                    "Goal1 required fields are incomplete (batch/reason/expiry coverage). "
                    "Remediation: run schema migration + regenerate simulation + refresh metrics snapshot.",
                )
            )
        if data_source_type not in {"synthetic", "real", "mixed"}:
            error_rows.append(
                (
                    "DATA_SOURCE_TYPE_UNKNOWN",
                    "Data Contract",
                    "metrics snapshot has unknown data_source_type. Remediation: set run_config.data_source_type to synthetic|real|mixed and regenerate snapshot.",
                )
            )
        if base_status in {"MISSING_ASSIGNMENT"}:
            if not fm_code:
                error_rows.append(
                    (
                        "DATA_ASSIGNMENT_MISSING",
                        "Data/Join",
                        "Assignment log/coverage is missing, so causal arm comparison is not observable.",
                    )
                )
        if base_status in {"METHODOLOGY_MISMATCH"}:
            error_rows.append(
                (
                    "METHOD_ANALYSIS_UNIT_MISMATCH",
                    "Method",
                    "Experiment randomization unit and realized analysis unit differ (fallback or join issue).",
                )
            )
        if inconsistent:
            error_rows.append(
                (
                    "STATS_PVALUE_CI_CONTRADICTION",
                    "Statistics",
                    "p-value significance and confidence interval sign/exclusion disagree.",
                )
            )
        if measurement_state in MEASUREMENT_BLOCKED_STATES:
            error_rows.append(
                (
                    f"MEASUREMENT_STATE_{measurement_state}",
                    "Measurement",
                    f"Measurement state is `{measurement_state}`; AB decisioning is blocked or unobservable.",
                )
            )
        if final_status == "INVALID_METHODS" and fatal_reason and not any(r[0] == "STATS_PVALUE_CI_CONTRADICTION" for r in error_rows):
            error_rows.append(
                (
                    "METHOD_INVALID_FOR_DECISIONING",
                    "Method/Contract",
                    fatal_reason,
                )
            )
        if any(code.startswith("DATA_") and code != "DATA_ASSIGNMENT_MISSING" for code, _, _ in error_rows):
            error_rows = [r for r in error_rows if r[0] != "DATA_ASSIGNMENT_MISSING"]

        # Policy update: keep diagnostic numbers for INVALID_METHODS if computable, but still null out
        # numbers for truly unobservable states (missing assignment / methodology mismatch / recovered).
        if final_status in {"BLOCKED_BY_DATA", "MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "ASSIGNMENT_RECOVERED"}:
            primary_uplift = None
            primary_ci = None
            primary_p = None
        else:
            primary_uplift = welch.delta_rel
            primary_ci = [welch.ci_low_rel, welch.ci_high_rel]
            primary_p = welch.p_value

        plan_source = "ab_control"

        # Goal tables (strict 3 blocks, Goal1 first)
        goal_rows: dict[str, dict[str, Any]] = {
            "goal1": {
                "metric": "writeoff_units",
                "supporting_metrics": ["writeoff_cogs", "writeoff_rate_vs_requested_units"],
                "prev": prev_metrics.get("writeoff_units"),
                "plan": prev_metrics.get("writeoff_units"),
                "control": None,
                "treatment": None,
                "abs_delta": None,
                "rel_delta": None,
                "p_value": None,
                "ci95": None,
                "decision": "Descriptive only",
                "status": "Targeted" if ab_primary_goal == "goal1" else "Monitored",
                "guardrails": ["fill_rate_units", "oos_lost_gmv_rate", "gp_margin"],
            },
            "goal2": {
                "metric": "aov",
                "supporting_metrics": ["gmv", "gp"],
                "prev": prev_metrics.get("aov"),
                "plan": mean_c,
                "control": mean_c,
                "treatment": mean_t,
                "abs_delta": welch.delta_abs,
                "rel_delta": primary_uplift,
                "p_value": primary_p,
                "ci95": primary_ci,
                "decision": decision_text,
                "status": "Targeted" if ab_primary_goal == "goal2" else "Monitored",
                "guardrails": ["gmv", "gp_margin", "fill_rate_units"],
            },
            "goal3": {
                "metric": "new_buyers_7d",
                "supporting_metrics": ["active_buyers_avg", "churn_rate"],
                "prev": prev_metrics.get("new_buyers_7d"),
                "plan": prev_metrics.get("new_buyers_7d"),
                "control": None,
                "treatment": None,
                "abs_delta": None,
                "rel_delta": None,
                "p_value": None,
                "ci95": None,
                "decision": "Descriptive only",
                "status": "Targeted" if ab_primary_goal == "goal3" else "Monitored",
                "guardrails": ["churn_rate", "rep_mean"],
            },
        }
        for goal_payload in goal_rows.values():
            metric_name = str(goal_payload.get("metric", ""))
            supporting_metrics = goal_payload.get("supporting_metrics", [])
            guardrails = goal_payload.get("guardrails", [])
            goal_payload["observed_metrics"] = _goal_observed_metrics_rows(
                metrics=metrics,
                primary_metric=metric_name,
                supporting_metrics=supporting_metrics if isinstance(supporting_metrics, list) else [],
                guardrails=guardrails if isinstance(guardrails, list) else [],
            )

        # Anti-Goodhart single source-of-truth: data/agent_quality/<run>_anti_goodhart_verdict.json
        anti_goodhart = False
        anti_goodhart_error = ""
        try:
            anti_goodhart_verdict = load_anti_goodhart_verdict(run_id)
            anti_goodhart = bool(anti_goodhart_verdict.get("anti_goodhart_triggered", False))
            if str(anti_goodhart_verdict.get("status", "")).upper() != "PASS":
                anti_goodhart_error = "ANTI_GOODHART_MISMATCH:verdict_status_fail"
        except Exception as exc:
            anti_goodhart_error = f"ANTI_GOODHART_MISMATCH:{exc}"
        if anti_goodhart_error and final_status not in BLOCKED_STATUSES:
            final_status = "BLOCKED_BY_DATA"
            fatal_reason = anti_goodhart_error

        payload = {
            "run_id": run_id,
            "experiment_id": experiment_id,
            "status": final_status,
            "reason": fatal_reason or decision_text,
            "measurement_state": measurement_state,
            "data_source_type": data_source_type,
            "contract_completeness": contract_completeness,
            "alignment_status": current_alignment_status,
            "hypothesis_target_goal": next_target_goal,
            "ab_primary_goal": ab_primary_goal,
            "current_ab_contour": {
                "metric": ab_primary_metric,
                "goal": ab_primary_goal,
                "contract_metric": current_contract_metric,
                "contract_metric_source": current_contract_source,
                "contract_goal": current_contract_goal,
                "contract_alignment_status": current_alignment_status,
            },
            "next_experiment_contour": {
                "metric": next_target_metric,
                "goal": next_target_goal,
                "source": "doctor.hypothesis_portfolio[0].target_metric",
                "vs_current_ab_status": next_alignment_status,
            },
            "alpha": alpha,
            "ci_level": ci_level,
            "method_name": welch.method,
            "method_label": method_label,
            "methodology": {
                "selected_by": meth_meta["selected_by"],
                "selection_mode": meth_meta.get("selection_mode", "unknown"),
                "fallback_reason": meth_meta.get("fallback_reason"),
                "model_intent": meth_meta.get("model_intent"),
                "metric_type": meth_meta["metric_type"],
                "statistical_principle": meth_meta["statistical_principle"],
                "test_family": meth_meta["test_family"],
                "reason_selected": meth_meta["reason_selected"],
                "why_not_alternatives": meth_meta.get("why_not_alternatives", ""),
                "alternatives_considered": meth_meta.get("alternatives_considered", []),
                "executor_method": meth_meta.get("executor_method", ""),
                "test_side": meth_meta.get("test_side", "two-sided"),
                "null_hypothesis": {
                    "claims": "There is no effect in the population.",
                    "metric_form": meth_meta["null_hypothesis_metric"],
                },
                "alternative_hypothesis": {
                    "claims": "There is an effect in the population.",
                    "metric_form": meth_meta["alternative_hypothesis_metric"],
                },
            },
            "analysis_population": "ITT",
            "plan_source": plan_source,
            "prev_run_id": prev_run_id,
            "primary_metric": {
                "name": ab_primary_metric,
                "control": mean_c if final_status not in BLOCKED_STATUSES else None,
                "treatment": mean_t if final_status not in BLOCKED_STATUSES else None,
                "uplift": primary_uplift,
                "ci95": primary_ci,
                "p_value": primary_p,
            },
            "sampling": {
                "unit": unit,
                "duration_days": duration_days,
                "window_start": window_start,
                "window_end": window_end,
                "assignment_method": "deterministic_hash_salt_unit_id",
                "assignment_salt": assignment_salt,
                "sample_size_required": {"orders_per_arm": min_orders, "units_per_arm": min_units},
                "sample_size_actual": {
                    "orders_control": n_c,
                    "orders_treatment": n_t,
                    "units_control": n_units_c,
                    "units_treatment": n_units_t,
                },
                "srm_status": summary.get("srm_status"),
                "unit_alignment_status": unit_alignment_status,
                "underpowered": underpowered,
            },
            "ab_design_contract": ab_design_contract,
            "goal1_store_week_category": {
                "rows": int(goal1_store_week_category_summary.get("rows") or 0),
                "stores": int(goal1_store_week_category_summary.get("stores") or 0),
                "categories": int(goal1_store_week_category_summary.get("categories") or 0),
                "source_ref": str(snapshot.get("goal1_store_week_category_ref", "")),
            },
            "goals": goal_rows,
            "anti_goodhart_triggered": anti_goodhart,
            "anti_goodhart_sot_error": anti_goodhart_error or None,
            "version": "ab_report_v2",
        }

        # Canonical v1.1 required additions (3.1 / 4.4 / 5.3 / 6.4 / 7.5 / 8.3).
        def _status_from_delta(cur: Any, prev: Any, threshold: float = 0.02) -> str:
            c = _to_float(cur)
            p = _to_float(prev)
            if c is None or p is None:
                return "WARN"
            return "PASS" if abs(c - p) <= threshold else "WARN"

        cur_waste_rate = metrics.get("writeoff_rate_vs_requested_units")
        prev_waste_rate = prev_metrics.get("writeoff_rate_vs_requested_units")
        fill_now = _to_float(metrics.get("fill_rate_units"))
        oos_now = _to_float(metrics.get("oos_lost_gmv_rate"))
        gp_margin_now = _to_float(metrics.get("gp_margin"))
        writeoff_cogs_now = _to_float(metrics.get("writeoff_cogs"))
        received_cogs_now = _to_float(metrics.get("received_cogs"))
        sold_cogs_now = _to_float(metrics.get("sold_cogs"))
        net_revenue_now = _to_float(metrics.get("gmv"))
        wic_now = (
            (net_revenue_now - sold_cogs_now - writeoff_cogs_now)
            if net_revenue_now is not None and sold_cogs_now is not None and writeoff_cogs_now is not None
            else None
        )
        waste_improved = (
            (_to_float(cur_waste_rate) is not None and _to_float(prev_waste_rate) is not None)
            and (_to_float(cur_waste_rate) < _to_float(prev_waste_rate))
        )
        understock_artifact = bool(waste_improved and fill_now is not None and oos_now is not None and fill_now < 0.90 and oos_now > 0.10)
        design_is_store_time = str(ab_design_contract.get("randomization_unit_cfg") or unit_cfg).strip().lower() == "store"
        exploratory_flag = underpowered or (not design_is_store_time)
        timeseries_path = Path(f"data/ab_reports/{run_id}_{experiment_id}_timeseries.csv")
        stability_data_available = timeseries_path.exists()
        goal1_rows_cnt = int(goal1_store_week_category_summary.get("rows") or 0)
        goal1_store_cnt = int(goal1_store_week_category_summary.get("stores") or 0)
        goal1_category_cnt = int(goal1_store_week_category_summary.get("categories") or 0)
        top_categories = goal1_store_week_category_summary.get("top_categories_by_writeoff", [])
        top_categories_display = ", ".join(
            [f"{name}:{_fmt_money(value)}" for name, value in top_categories if isinstance(name, str)]
        ) or "n/a"
        received_cogs_eff = received_cogs_now
        if received_cogs_eff is None:
            received_cogs_eff = _to_float(goal1_store_week_category_summary.get("received_cogs"))
        sold_cogs_eff = sold_cogs_now
        if sold_cogs_eff is None:
            sold_cogs_eff = _to_float(goal1_store_week_category_summary.get("sold_cogs"))
        expiry_writeoff_cogs_now = _to_float(metrics.get("expiry_writeoff_cogs"))
        if expiry_writeoff_cogs_now is None:
            expiry_writeoff_cogs_now = _to_float(goal1_store_week_category_summary.get("expiry_writeoff_cogs"))
        if (
            net_revenue_now is not None
            and sold_cogs_eff is not None
            and expiry_writeoff_cogs_now is not None
        ):
            wic_now = net_revenue_now - sold_cogs_eff - expiry_writeoff_cogs_now
        expiry_cov_val = _to_float(
            ((contract_completeness.get("checks", {}) or {}).get("expiry_date_coverage", {}) or {}).get("value")
        )
        promo_proxy_status = "PASS" if goal1_rows_cnt > 0 else "FAIL"
        promo_proxy_note = (
            f"store-week-category rows={goal1_rows_cnt}; promo fields are not in aggregate, using density proxy."
            if goal1_rows_cnt > 0
            else "goal1_store_week_category artifact is missing or empty."
        )
        expiry_cov_status = "PASS" if (expiry_cov_val is not None and expiry_cov_val >= 0.99) else "FAIL"

        sanity_rows = [
            (
                "Baseline ExpiryWasteRate parity",
                _fmt_pct(cur_waste_rate),
                _fmt_pct(prev_waste_rate),
                _status_from_delta(cur_waste_rate, prev_waste_rate, 0.015),
                "Pre-period parity check before reading outcomes.",
            ),
            (
                "Volume parity by orders",
                f"{n_c}/{n_t}",
                "target≈balanced",
                ("PASS" if (n_c > 0 and n_t > 0 and (min(n_c, n_t) / max(n_c, n_t)) >= 0.8) else "WARN"),
                "Large volume imbalance can confound comparisons.",
            ),
            (
                "Promo intensity parity",
                f"rows={goal1_rows_cnt}",
                ">=1",
                promo_proxy_status,
                promo_proxy_note,
            ),
            (
                "Expiry coverage parity",
                _fmt_pct(expiry_cov_val),
                ">=99.00%",
                expiry_cov_status,
                "coverage from metrics_snapshot.contract_completeness.checks.expiry_date_coverage",
            ),
        ]

        category_seg_status = "PASS" if goal1_category_cnt >= 2 else ("WARN" if goal1_rows_cnt > 0 else "FAIL")
        store_seg_status = (
            "PASS"
            if (design_is_store_time and goal1_store_cnt >= 2)
            else ("WARN" if goal1_store_cnt > 0 else "FAIL")
        )
        sku_tier_status = "WARN" if goal1_rows_cnt > 0 else "FAIL"
        baseline_split_status = (
            "PASS"
            if bool(goal1_store_week_category_summary.get("store_high_low_split_ready"))
            else ("WARN" if goal1_store_cnt > 0 else "FAIL")
        )
        segment_rows = [
            (
                "Category split (dairy/meat)",
                category_seg_status,
                (
                    "canonical categories present."
                    if bool(goal1_store_week_category_summary.get("dairy_meat_present"))
                    else f"top categories by expiry writeoff cogs: {top_categories_display}"
                ),
            ),
            (
                "Store-level split",
                store_seg_status,
                f"stores={goal1_store_cnt}; randomization/analysis should be store-time for Goal1 inbound/inventory.",
            ),
            (
                "SKU tier split (top20 vs tail)",
                sku_tier_status,
                "proxy from store-week-category aggregate; strict SKU-tier split requires SKU-level fact.",
            ),
            (
                "Baseline waste split (high/low)",
                baseline_split_status,
                "derived from per-store expiry_waste_rate_cogs split (high/low) when >=2 stores available.",
            ),
        ]

        sell_through_value = None
        if sold_cogs_eff is not None and received_cogs_eff not in {None, 0}:
            sell_through_value = sold_cogs_eff / float(received_cogs_eff)
        received_status = "OK" if received_cogs_eff is not None else "FAIL"
        sell_through_status = "OK" if sell_through_value is not None else ("WARN" if received_cogs_eff == 0 else "FAIL")
        expiry_cogs_status = "OK" if expiry_writeoff_cogs_now is not None else "FAIL"
        commercial_status = "OK" if wic_now is not None else "FAIL"
        decomposition_rows = [
            ("ReceivedCOGS (volume)", _fmt_money(received_cogs_eff), received_status),
            (
                "SoldCOGS / ReceivedCOGS (sell-through proxy)",
                _fmt_pct(sell_through_value) if sell_through_value is not None else "n/a",
                sell_through_status,
            ),
            ("ExpiryWriteoffCOGS", _fmt_money(expiry_writeoff_cogs_now), expiry_cogs_status),
            ("Availability (Fill/OOS)", f"{_fmt_pct(fill_now)} / {_fmt_pct(oos_now)}", "BREACH" if (fill_now is not None and oos_now is not None and (fill_now < 0.90 or oos_now > 0.10)) else "OK"),
            ("Commercial (Net Revenue / GM$ / WIC)", f"{_fmt_money(net_revenue_now)} / {_fmt_money(metrics.get('gp'))} / {_fmt_money(wic_now)}", commercial_status),
        ]

        lines = [
            f"# AB Statistical Report — {run_id}",
            "",
            "SECTION 0: Experiment Header",
            f"- run_id: `{run_id}`",
            f"- experiment_id: `{experiment_id}`",
            f"- experiment_unit: `{unit}`",
            f"- treat_pct: `{treat_pct}`",
            f"- duration_days: `{duration_days}`",
            f"- window_start: `{window_start}`",
            f"- window_end: `{window_end}`",
            f"- data_source_type: `{data_source_type}`",
            f"- goal1_contract_ready: `{goal1_contract_ready}`",
            f"- assignment: `deterministic hash + salt + unit_id` (salt=`{assignment_salt}`)",
            "- analysis population: `ITT`",
            "- exclusions: `none`; missing orders are kept as non-conversion in ITT joins.",
            f"- alpha: `{alpha}`; CI level: `{ci_level}%`",
            f"- multiple testing: `{'Holm-Bonferroni' if ab_primary_goal=='unknown' else 'single primary, others descriptive'}`",
            "",
            "SECTION 0A: Statistical Methodology (human-readable)",
            f"- selected_by: `{meth_meta.get('selected_by', 'unknown')}`",
            f"- selection_mode: `{meth_meta.get('selection_mode', 'unknown')}`",
            f"- metric_type: `{meth_meta['metric_type']}`",
            f"- statistical_principle: `{meth_meta['statistical_principle']}`",
            f"- test_family: `{meth_meta['test_family']}`",
            f"- why_selected: {meth_meta['reason_selected']}",
            f"- test_side: `{meth_meta.get('test_side', 'two-sided')}`",
            "",
            "SECTION 0B: AB Design Contract (methodology prerequisites)",
            f"- randomization_unit_cfg: `{ab_design_contract.get('randomization_unit_cfg')}`",
            f"- analysis_unit_realized: `{ab_design_contract.get('analysis_unit_realized')}`",
            f"- pre_period_weeks: `{ab_design_contract.get('pre_period_weeks')}`",
            f"- test_period_weeks: `{ab_design_contract.get('test_period_weeks')}`",
            f"- wash_in_days: `{ab_design_contract.get('wash_in_days')}`",
            f"- attribution_window_rule: `{ab_design_contract.get('attribution_window_rule')}`",
            f"- alpha(plan): `{ab_design_contract.get('alpha')}`; power_target: `{ab_design_contract.get('power_target')}`; mde_target: `{ab_design_contract.get('mde_target')}`",
            f"- metric_semantics: `{ab_design_contract.get('metric_semantics')}`",
            f"- surrogate_batch_id_strategy: `{ab_design_contract.get('surrogate_batch_id_strategy')}`",
            "",
            "SECTION 1: Contour Alignment (current AB vs next experiment)",
            f"- hypothesis_statement: {hypothesis_stmt}",
            f"- current_ab_metric: `{ab_primary_metric}`",
            f"- current_ab_goal: `{ab_primary_goal}`",
            f"- current_contract_metric: `{current_contract_metric or 'missing'}`",
            f"- current_contract_metric_source: `{current_contract_source}`",
            f"- current_contract_goal: `{current_contract_goal}`",
            f"- current_alignment_status: `{current_alignment_status}`",
            f"- next_experiment_metric: `{next_target_metric or 'missing'}`",
            f"- next_experiment_goal: `{next_target_goal}`",
            f"- next_vs_current_ab_status: `{next_alignment_status}`",
            "",
            "### H0 / Ha (mini-table)",
            "|  | Null hypothesis (H0) | Alternative hypothesis (Ha) |",
            "|---|---|---|",
            "| Claims | There is no effect in the population. | There is an effect in the population. |",
            f"| Metric ({ab_primary_metric or 'primary_metric'}) | `{meth_meta['null_hypothesis_metric']}` | `{meth_meta['alternative_hypothesis_metric']}` |",
            "",
            "### Abbreviations / Glossary (расшифровка)",
            "| Term | Meaning |",
            "|---|---|",
            "| `Δ abs` | absolute lift — абсолютная разница (`Treatment - Control`) |",
            "| `Δ rel` | relative lift — относительная разница (`(T-C)/Control`) |",
            "| `pp` | percentage points — процентные пункты (напр. 4.6% -> 3.9% = -0.7pp) |",
            "| `CI95` | 95% confidence interval — 95% доверительный интервал |",
            "| `p-value` | вероятность получить такой/более экстремальный результат при верной H0 |",
            "| `H0` / `Ha` | null / alternative hypothesis — нулевая / альтернативная гипотеза |",
            "| `MDE` | minimum detectable effect — минимальный эффект, который тест способен надежно заметить |",
            "| `SRM` | sample ratio mismatch — проверка корректности аллокации групп |",
            "| `ITT` | intention-to-treat — анализ по назначению в группу, даже при неполном фактическом воздействии |",
            "",
        ]
        design_gaps = ab_design_contract.get("design_gaps", []) if isinstance(ab_design_contract.get("design_gaps"), list) else []
        if design_gaps:
            lines.extend(
                [
                    "### Design Gaps (must be fixed for methodology-first standard)",
                    *[f"- `{g}`" for g in design_gaps],
                    "",
                ]
            )
        lines.extend(
            [
            "### Errors & Root Causes (mini-table)",
            "| Error Code | Layer | Root Cause |",
            "|---|---|---|",
            ]
        )
        if error_rows:
            for code, layer, cause in error_rows:
                lines.append(f"| {code} | {layer} | {cause} |")
        else:
            lines.append("| none | — | No blocking/diagnostic errors recorded by current checks. |")
        if current_alignment_status == "FAIL":
            lines.extend(
                [
                    "",
                    "## ❌ FATAL",
                    "Stop: current AB contract metric does not align with AB primary metric.",
                ]
            )
        if str(meth_meta.get("fallback_reason", "")).strip():
            lines.extend(
                [
                    "",
                    "### Method Selection Fallback",
                    f"- fallback_reason: `{meth_meta.get('fallback_reason')}`",
                ]
            )
        if meth_meta.get("validation_issues"):
            lines.extend(
                [
                    "",
                    "### Method Validation Issues",
                ]
            )
            for issue in meth_meta.get("validation_issues", []):
                lines.append(f"- `{issue}`")
        if meth_meta.get("alternatives_considered"):
            lines.extend(
                [
                    "",
                    "### Alternatives Considered",
                    f"- {', '.join([str(x) for x in meth_meta.get('alternatives_considered', [])])}",
                ]
            )
        if str(meth_meta.get("why_not_alternatives", "")).strip():
            lines.append(f"- why_not_alternatives: {meth_meta.get('why_not_alternatives')}")

        lines.extend(
            [
                "",
                "SECTION 2: Goal Blocks (MUST be exactly 3 blocks, Goal1 first)",
                "",
                "## 2.1 Goal 1 (Writeoffs & Waste)",
                f"A) Goal Status: `{goal_rows['goal1']['status']}`",
                f"B) Metrics: primary=`{goal_rows['goal1']['metric']}`; supporting={goal_rows['goal1']['supporting_metrics']}; guardrails={goal_rows['goal1']['guardrails']}",
                "C) Comparison Table (Plan / Prev / Control / Treatment):",
                "| Metric | Prev | Plan | Control | Treatment | Abs Delta (T-C) | Rel Delta % | alpha | p-value | CI95 | Decision |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
                f"| writeoff_units | {_fmt_num(goal_rows['goal1']['prev'],2)} | {_fmt_num(goal_rows['goal1']['plan'],2)} | — | — | — | — | {alpha:.2f} | — | — | {goal_rows['goal1']['decision']} |",
                "D) Statistical Method: `descriptive_only` (not primary in this run)",
                f"E) Statistical Decision: `{goal_rows['goal1']['decision']}`",
                "",
                "## 2.2 Goal 2 (Revenue & AOV)",
                f"A) Goal Status: `{goal_rows['goal2']['status']}`",
                f"B) Metrics: primary=`{goal_rows['goal2']['metric']}`; supporting={goal_rows['goal2']['supporting_metrics']}; guardrails={goal_rows['goal2']['guardrails']}",
                "C) Comparison Table (Plan / Prev / Control / Treatment):",
                "| Metric | Prev | Plan | Control | Treatment | Abs Delta (T-C) | Rel Delta % | alpha | p-value | CI95 | Decision |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
                (
                    f"| aov | {_fmt_money(goal_rows['goal2']['prev'])} | {_fmt_money(goal_rows['goal2']['plan'])} | "
                    f"{_fmt_money(goal_rows['goal2']['control'])} | {_fmt_money(goal_rows['goal2']['treatment'])} | "
                    f"{_fmt_money(goal_rows['goal2']['abs_delta'])} | {_fmt_pct(goal_rows['goal2']['rel_delta'])} | {alpha:.2f} | "
                    f"{_fmt_num(goal_rows['goal2']['p_value'],4)} | [{_fmt_pct((goal_rows['goal2']['ci95'] or [None, None])[0])}, {_fmt_pct((goal_rows['goal2']['ci95'] or [None, None])[1])}] | {decision_text} |"
                ),
                f"D) Statistical Method: principle=`{meth_meta['statistical_principle']}`; test_family=`{meth_meta['test_family']}`; executor_method=`{meth_meta.get('executor_method') or welch.method}`; computed_method_name=`{welch.method}`; why=`{meth_meta['reason_selected']}`; test_side=`{meth_meta.get('test_side', 'two-sided')}`; assumptions checks: n_per_arm=({n_c},{n_t}), underpowered=`{underpowered}`, SRM=`{summary.get('srm_status')}`",
                f"E) Statistical Decision: `{decision_text}`",
                "",
                "## 2.3 Goal 3 (Audience & Buyers)",
                f"A) Goal Status: `{goal_rows['goal3']['status']}`",
                f"B) Metrics: primary=`{goal_rows['goal3']['metric']}`; supporting={goal_rows['goal3']['supporting_metrics']}; guardrails={goal_rows['goal3']['guardrails']}",
                "C) Comparison Table (Plan / Prev / Control / Treatment):",
                "| Metric | Prev | Plan | Control | Treatment | Abs Delta (T-C) | Rel Delta % | alpha | p-value | CI95 | Decision |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
                f"| new_buyers_7d | {_fmt_num(goal_rows['goal3']['prev'],0)} | {_fmt_num(goal_rows['goal3']['plan'],0)} | — | — | — | — | {alpha:.2f} | — | — | {goal_rows['goal3']['decision']} |",
                "D) Statistical Method: `descriptive_only` (not primary in this run)",
                f"E) Statistical Decision: `{goal_rows['goal3']['decision']}`",
                "",
                "## 2.4 Full Observed Metrics in Each Goal Contour (including guardrails)",
                "",
                "SECTION 3: Cross-goal Tradeoffs (required)",
                f"- Anti-Goodhart triggered: `{anti_goodhart}`",
                (
                    "- Recommendation: `NO-GO` due to guardrail conflict while optimizing Goal1."
                    if anti_goodhart
                    else "- Recommendation: no cross-goal Goodhart trigger detected in current snapshot."
                ),
                "",
                "SECTION 4: Expected vs Actual Impact (next experiment contour)",
                f"- Next contour expected impact range: `{top_h.get('expected_uplift_range', 'missing')}`",
                f"- Actual delta: `{_fmt_pct(primary_uplift)}`",
                (
                    "- Expectation mismatch: true"
                    if (str(top_h.get("expected_uplift_range", "")).strip() and primary_uplift is not None and not str(top_h.get("expected_uplift_range", "")).startswith(_fmt_pct(primary_uplift)))
                    else "- Expectation mismatch: not detected by deterministic parser"
                ),
                "",
                "SECTION 5: Final AB Status",
                f"- status: `{final_status}`",
                f"- reason: `{fatal_reason or decision_text}`",
                "",
                "SECTION 6: Method Checks",
                f"- statistical_principle: `{meth_meta['statistical_principle']}`",
                f"- test_family: `{meth_meta['test_family']}`",
                f"- method_selected_by: `{meth_meta.get('selected_by', 'unknown')}`",
                f"- method_selection_mode: `{meth_meta.get('selection_mode', 'unknown')}`",
                f"- method_executor_method: `{meth_meta.get('executor_method') or 'unknown'}`",
                f"- current_ab_alignment: `{current_alignment_status}` (contract_goal=`{current_contract_goal}`, ab_primary=`{ab_primary_goal}`)",
                f"- next_contour_vs_current_ab: `{next_alignment_status}` (next_goal=`{next_target_goal}`, ab_primary=`{ab_primary_goal}`)",
                f"- unit_alignment: `{unit_alignment_status}` (ab=`{unit}`, run_config=`{unit_cfg}`)",
                f"- SRM: `{summary.get('srm_status')}`",
                "- method_by_metric_policy:",
                "  - continuous metrics (e.g., aov): Welch t-test",
                "  - proportions: z-test / chi-square",
                "  - ratio metrics (margin/fill/oos): delta method or bootstrap",
                "",
                "## 3.1 Sanity checks (invariants) — required before reading outcomes",
                "| Check | Current | Pre-period/Baseline | Status | Note |",
                "|---|---|---|---|---|",
            ]
        )
        for check_name, cur_v, prev_v, st, note in sanity_rows:
            lines.append(f"| {check_name} | {cur_v} | {prev_v} | {st} | {note} |")
        lines.extend(
            [
                "",
                "## 4.4 Required segments (pre-registered; avoid p-hacking)",
                "| Segment | Status | Note |",
                "|---|---|---|",
            ]
        )
        for seg_name, seg_status, seg_note in segment_rows:
            lines.append(f"| {seg_name} | {seg_status} | {seg_note} |")
        lines.extend(
            [
                "",
                "## 5.3 Decomposition (required interpretation block)",
                "| Component | Value | Status |",
                "|---|---|---|",
            ]
        )
        for comp_name, comp_value, comp_status in decomposition_rows:
            lines.append(f"| {comp_name} | {comp_value} | {comp_status} |")
        lines.extend(
            [
                f"- under_stocking_artifact_flag: `{understock_artifact}`",
                "",
                "## 6.4 Power / MDE planning (required, even if approximate)",
                f"- baseline_expiry_waste_rate_pre_period: `{_fmt_pct(prev_waste_rate)}`",
                "- practical_threshold: `X pp` OR `$Y per store-week` (must be pre-declared in contract)",
                f"- planned_duration_days: `{duration_days}`",
                f"- sample_size_gate_orders_per_arm: `{min_orders}`",
                f"- sample_size_gate_units_per_arm: `{min_units}`",
                f"- mde_estimate_reported: `{_fmt_num(summary.get('mde_estimate'), 4)}`",
                f"- mde_target_contract: `{ab_design_contract.get('mde_target')}`",
                f"- experiment_label: `{'exploratory' if exploratory_flag else 'decision-capable'}`",
                "",
                "## 7.5 Rollout ramp & post-launch monitoring (standard)",
                "- ramp_plan: `10% -> 25% -> 50% -> 100%` (3-7 days each step)",
                "- kill_switch_fill: `FillRate drop beyond δ_fill (rolling 7d)`",
                "- kill_switch_oos: `OOS increase beyond δ_oos`",
                "- kill_switch_margin: `GM$/WIC degradation beyond ε_margin`",
                "- post_launch_recheck: `2 weeks after 100% rollout`",
                "",
                "## 8.3 Effect stability over time (required in every experiment report)",
                f"- timeseries_data_available: `{stability_data_available}`",
                (
                    f"- source_timeseries: `{timeseries_path}`"
                    if stability_data_available
                    else "- source_timeseries: `missing` (need daily/per-block exports for stability diagnostics)"
                ),
                "- required_views: `per-block delta`, `cumulative delta`, `consistency across blocks`",
                "",
            ]
        )

        contour_lines: list[str] = []
        for goal_key, goal_label in (
            ("goal1", "Goal 1 (Writeoffs & Waste)"),
            ("goal2", "Goal 2 (Revenue & AOV)"),
            ("goal3", "Goal 3 (Audience & Buyers)"),
        ):
            goal_payload = goal_rows.get(goal_key, {})
            observed_rows = goal_payload.get("observed_metrics", []) if isinstance(goal_payload.get("observed_metrics"), list) else []
            contour_lines.extend(
                [
                    f"### {goal_label} — Observed Metrics in Contour",
                    "| Metric | Role | Observed Value |",
                    "|---|---|---:|",
                ]
            )
            for obs in observed_rows:
                if not isinstance(obs, dict):
                    continue
                contour_lines.append(
                    f"| {obs.get('metric', 'missing')} | {obs.get('role', 'observed')} | {obs.get('display_value', '—')} |"
                )
            contour_lines.append("")
        try:
            section3_idx = lines.index("SECTION 3: Cross-goal Tradeoffs (required)")
            lines[section3_idx:section3_idx] = contour_lines
        except ValueError:
            lines.extend(contour_lines)

        if final_status in {"BLOCKED_BY_DATA", "MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "ASSIGNMENT_RECOVERED", "INVALID_METHODS"}:
            lines.extend(
                [
                    "",
                    "## ❌ FATAL",
                    (
                        "Causality is not observable for this run. Uplift/CI/p-value are null by policy."
                        if final_status in {"BLOCKED_BY_DATA", "MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "ASSIGNMENT_RECOVERED"}
                        else "Methods are invalid for decisioning. Diagnostic uplift/CI/p-value may be shown above, but are not decision-valid."
                    ),
                ]
            )

        report_md = "\n".join(lines) + "\n"
        _safe_write(out_md, report_md)

        metric_name_up = (ab_primary_metric or "primary_metric").upper()
        ci95_rel_disp = (
            f"[{_fmt_pct((primary_ci or [None, None])[0])}, {_fmt_pct((primary_ci or [None, None])[1])}]"
            if isinstance(primary_ci, list) and len(primary_ci) == 2
            else "—"
        )
        primary_decision_label = (
            "Reject H0"
            if (primary_p is not None and primary_p <= alpha and isinstance(primary_ci, list) and len(primary_ci) == 2 and not ((primary_ci[0] or 0) <= 0 <= (primary_ci[1] or 0)))
            else "Fail to Reject H0"
        )
        canonical_lines = [
            f"# AB Statistical Report — {run_id} (Revised, copy-ready)",
            "",
            "## 0) Experiment Header",
            f"- run_id: `{run_id}`",
            f"- experiment_id: `{experiment_id}`",
            f"- randomization_unit_cfg: `{ab_design_contract.get('randomization_unit_cfg') or unit_cfg}`",
            "- assignment: `deterministic hash + salt + unit_id`",
            f"- treat_pct: `{treat_pct}`",
            f"- duration_days: `{duration_days}`",
            f"- window_start: `{window_start}`",
            f"- window_end: `{window_end}`",
            "- analysis_population: `ITT`",
            "- exclusions: `none`",
            f"- alpha: `{alpha}`",
            f"- CI level: `{ci_level}%`",
            f"- test_side: `{meth_meta.get('test_side', 'two-sided')}`",
            "- multiple testing policy: `single primary, others descriptive`",
            f"- SRM_check: `{summary.get('srm_status') or 'missing'}`",
            "",
            "## 0A) Metric Semantics Lock",
            "- Currency: **USD**",
            "- `net_price = price - discounts`",
            "- `GMV = Σ(net_price)` within test window",
            "- `AOV = GMV / orders` within test window",
            "",
            "## 0B) Statistical Methodology (as reported)",
            f"- metric_type: `{meth_meta.get('metric_type', 'unknown')}`",
            f"- statistical_principle: `{meth_meta.get('statistical_principle', 'missing')}`",
            f"- test_family: `{meth_meta.get('test_family', 'missing')}`",
            f"- why_selected: {meth_meta.get('reason_selected', 'missing')}",
            f"- test_side: `{meth_meta.get('test_side', 'two-sided')}`",
            "",
        ]
        if str(ab_design_contract.get("randomization_unit_cfg", "")).strip().lower() == "customer" and ab_primary_metric == "aov":
            canonical_lines.extend(
                [
                    "### Critical validity note (unit consistency)",
                    "- Randomization is by customer, but AOV often uses order-level rows.",
                    "- Prefer customer-level aggregation or clustered inference by customer.",
                    "",
                ]
            )
        canonical_lines.extend(
            [
                f"## 1) Hypotheses (Primary metric = {metric_name_up})",
                f"- H0: `{meth_meta.get('null_hypothesis_metric', f'{ab_primary_metric}_t = {ab_primary_metric}_c')}`",
                f"- Ha: `{meth_meta.get('alternative_hypothesis_metric', f'{ab_primary_metric}_t != {ab_primary_metric}_c')}`",
                "",
                "## 2) Realized Group Sizes",
                "| Arm | n_customers | n_orders |",
                "|---|---:|---:|",
                f"| Control | {n_units_c} | {n_c} |",
                f"| Treatment | {n_units_t} | {n_t} |",
                "",
                f"## 3) Primary Result — {ab_primary_goal.upper()} ({metric_name_up})",
                "### Reported summary",
                "| Metric | Control | Treatment | Δ abs (T−C) | Δ rel | p-value | CI95 (rel) | Decision |",
                "|---|---:|---:|---:|---:|---:|---|---|",
                f"| {metric_name_up} | {_fmt_money(summary.get('primary_metric_control')) if ab_primary_metric in {'aov', 'gmv', 'gp'} else _fmt_num(summary.get('primary_metric_control'), 4)} | {_fmt_money(summary.get('primary_metric_treatment')) if ab_primary_metric in {'aov', 'gmv', 'gp'} else _fmt_num(summary.get('primary_metric_treatment'), 4)} | {_fmt_money(summary.get('primary_metric_delta_abs')) if ab_primary_metric in {'aov', 'gmv', 'gp'} else _fmt_num(summary.get('primary_metric_delta_abs'), 4)} | {_fmt_pct(primary_uplift)} | {_fmt_num(primary_p,4)} | {ci95_rel_disp} | {primary_decision_label} |",
                "",
                "### Interpretation",
                f"- status: `{final_status}`",
                f"- reason: `{fatal_reason or decision_text}`",
                "",
                "## 4) Guardrails (not split by arm → no causal attribution)",
                "- fill_rate_units floor: `90.00%`",
                "- oos_lost_gmv_rate ceiling: `10.00%`",
                f"- observed_fill_rate_units: `{_fmt_pct(metrics.get('fill_rate_units'))}`",
                f"- observed_oos_lost_gmv_rate: `{_fmt_pct(metrics.get('oos_lost_gmv_rate'))}`",
                f"- observed_gp_margin: `{_fmt_pct(metrics.get('gp_margin'))}`",
                "",
                "## 5) Final AB Status",
                f"- status: `{final_status}`",
                f"- reason: `{fatal_reason or decision_text}`",
                "",
                "## 6) What to do next (analysis plan)",
                "- Option A: aggregate to randomized unit before test (customer-level for customer randomization).",
                "- Option B: clustered inference / cluster bootstrap at randomized unit.",
                "- For Goal1 inbound/inventory changes: move to store-time experiment design (canonical).",
                "",
                "## 3.1 Sanity checks (invariants) — required before reading outcomes",
                "| Check | Current | Pre-period/Baseline | Status | Note |",
                "|---|---|---|---|---|",
            ]
        )
        for check_name, cur_v, prev_v, st, note in sanity_rows:
            canonical_lines.append(f"| {check_name} | {cur_v} | {prev_v} | {st} | {note} |")
        canonical_lines.extend(
            [
                "",
                "## 4.4 Required segments (pre-registered; avoid p-hacking)",
                "| Segment | Status | Note |",
                "|---|---|---|",
            ]
        )
        for seg_name, seg_status, seg_note in segment_rows:
            canonical_lines.append(f"| {seg_name} | {seg_status} | {seg_note} |")
        canonical_lines.extend(
            [
                "",
                "## 5.3 Decomposition (required interpretation block)",
                "| Component | Value | Status |",
                "|---|---|---|",
            ]
        )
        for comp_name, comp_value, comp_status in decomposition_rows:
            canonical_lines.append(f"| {comp_name} | {comp_value} | {comp_status} |")
        canonical_lines.extend(
            [
                f"- under_stocking_artifact_flag: `{understock_artifact}`",
                "",
                "## 6.4 Power / MDE planning (required, even if approximate)",
                f"- baseline_expiry_waste_rate_pre_period: `{_fmt_pct(prev_waste_rate)}`",
                "- practical_threshold: `X pp` OR `$Y per store-week` (must be pre-declared in contract)",
                f"- planned_duration_days: `{duration_days}`",
                f"- sample_size_gate_orders_per_arm: `{min_orders}`",
                f"- sample_size_gate_units_per_arm: `{min_units}`",
                f"- mde_estimate_reported: `{_fmt_num(summary.get('mde_estimate'), 4)}`",
                f"- mde_target_contract: `{ab_design_contract.get('mde_target')}`",
                f"- experiment_label: `{'exploratory' if exploratory_flag else 'decision-capable'}`",
                "",
                "## 7.5 Rollout ramp & post-launch monitoring (standard)",
                "- ramp_plan: `10% -> 25% -> 50% -> 100%` (3-7 days each step)",
                "- kill_switch_fill: `FillRate drop beyond δ_fill (rolling 7d)`",
                "- kill_switch_oos: `OOS increase beyond δ_oos`",
                "- kill_switch_margin: `GM$/WIC degradation beyond ε_margin`",
                "- post_launch_recheck: `2 weeks after 100% rollout`",
                "",
                "## 8.3 Effect stability over time (required in every experiment report)",
                f"- timeseries_data_available: `{stability_data_available}`",
                (
                    f"- source_timeseries: `{timeseries_path}`"
                    if stability_data_available
                    else "- source_timeseries: `missing` (need daily/per-block exports for stability diagnostics)"
                ),
                "- required_views: `per-block delta`, `cumulative delta`, `consistency across blocks`",
                "",
                "## Appendix — Glossary",
                "- `Δ abs`: absolute lift (`Treatment - Control`)",
                "- `Δ rel`: relative lift (`(T-C)/Control`)",
                "- `CI95`: 95% confidence interval",
                "- `MDE`: minimum detectable effect",
                "- `SRM`: sample ratio mismatch",
                "- `ITT`: intention-to-treat",
                "",
            ]
        )
        _safe_write(out_md_canonical, "\n".join(canonical_lines))
        _safe_write_json(out_json, payload)
        print(f"ok: ab report v2 written for run_id={run_id}")
    except Exception as exc:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(f"{exc}\n{traceback.format_exc()}", encoding="utf-8")
        fallback_md = "\n".join(
            [
                f"# AB Statistical Report — {run_id}",
                "",
                "FATAL: AB report generator runtime error.",
                f"- log: `{log_path}`",
            ]
        )
        _safe_write(out_md, fallback_md)
        _safe_write(out_md_canonical, fallback_md)
        _safe_write_json(out_json_base, {"run_id": run_id, "status": "BLOCKED_BY_DATA", "reason": "runtime_error"})
        print(f"ok: ab report v2 fallback written for run_id={run_id}")


if __name__ == "__main__":
    main()
