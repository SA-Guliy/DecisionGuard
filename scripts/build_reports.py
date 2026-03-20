#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.status_taxonomy import (
    AB_DECISION_INVALID_STATUSES,
    AB_METHOD_VALIDITY_ERROR_STATUSES,
    goal_from_metric as _goal_from_metric,
)
from src.architecture_v3 import (
    REQUIRED_GATE_ORDER,
    list_gate_results,
    load_anti_goodhart_verdict,
    load_gate_result,
    validate_v3_contract_set,
)
from src.security_utils import verify_sha256_sidecar, write_json_manifest, write_sha256_sidecar

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"password", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"token", re.IGNORECASE), "[REDACTED]"),
]

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

CANONICAL_STANDARD_PATH = Path("human_reports/L1/v13_ab_final_003/канонический_стандарт.md")
AB_STANDARD_TEMPLATE_PATH = Path("human_reports/L1/v13_ab_final_003/AB_stat_report_standart.md")
DECISION_STANDARD_TEMPLATE_PATH = Path("reports/L1_ops/v13_agent_prod_013/Decision Card_standard.md")
DECISION_CANONICAL_OUTPUT = "DECISION_CARD_CANONICAL.md"
AB_CANONICAL_OUTPUT = "AB_STAT_REPORT_CANONICAL.md"


def _redact_text(value: str) -> str:
    out = value
    for pattern, repl in REDACTION_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _assert_integrity(path: Path, *, required: bool = True) -> None:
    if not path.exists():
        raise FileNotFoundError(f"missing_artifact:{path}")
    ok, reason = verify_sha256_sidecar(path, required=required)
    if not ok:
        raise ValueError(reason)


def _load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _extract_h2_headings(text: str) -> list[str]:
    headings: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("## "):
            headings.append(line[3:].strip())
    return headings


def _normalize_heading(text: str) -> str:
    s = text.strip().lower()
    s = s.replace("—", "-").replace("–", "-")
    s = re.sub(r"[`*_]", "", s)
    s = re.sub(r"\s+", " ", s)
    return s


def _metric(metrics: dict[str, Any], key: str) -> float | None:
    value = metrics.get(key)
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _fmt_number(value: Any, decimals: int = 2) -> str:
    try:
        v = float(value)
    except Exception:
        return "missing"
    return f"{v:.{decimals}f}"


def _fmt_int(value: Any) -> str:
    try:
        return str(int(round(float(value))))
    except Exception:
        return "missing"


def _fmt_money(value: Any, decimals: int = 2) -> str:
    try:
        v = float(value)
    except Exception:
        return "missing"
    return f"${v:.{decimals}f}"


def _fmt_pct(value: Any, decimals: int = 2) -> str:
    try:
        v = float(value)
    except Exception:
        return "missing"
    return f"{(v * 100):.{decimals}f}%"


def _fmt_metric_value(metrics: dict[str, Any], key: str) -> str:
    value = metrics.get(key)
    if key in {"aov", "gmv", "gp", "lost_gmv_oos", "writeoff_cogs"}:
        return _fmt_money(value, 2)
    if key in {"gp_margin", "fill_rate_units", "oos_lost_gmv_rate", "churn_rate", "writeoff_rate_vs_requested_units"}:
        return _fmt_pct(value, 2)
    if key in {"orders_cnt", "new_buyers_7d", "writeoff_units"}:
        return _fmt_int(value)
    return _fmt_number(value, 2)


def _fmt_uplift_pct(value: Any) -> str:
    try:
        v = float(value)
    except Exception:
        return "—"
    return f"{v * 100:.2f}%"


def _fmt_ci_pct(ci_value: Any) -> str:
    if not isinstance(ci_value, (list, tuple)) or len(ci_value) != 2:
        return "—"
    lo = _fmt_uplift_pct(ci_value[0])
    hi = _fmt_uplift_pct(ci_value[1])
    if lo == "—" or hi == "—":
        return "—"
    return f"[{lo}, {hi}]"


def _fmt_p_value(value: Any) -> str:
    try:
        v = float(value)
    except Exception:
        return "missing"
    return f"{v:.4f}"


def _to_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
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
    }
    if not rows:
        return summary
    stores = {str(r.get("store_id", "")).strip() for r in rows if str(r.get("store_id", "")).strip()}
    weeks = {str(r.get("iso_week", "")).strip() for r in rows if str(r.get("iso_week", "")).strip()}
    categories = {str(r.get("category_id", "")).strip() for r in rows if str(r.get("category_id", "")).strip()}
    received_cogs = 0.0
    sold_cogs = 0.0
    expiry_writeoff_cogs = 0.0
    for r in rows:
        received_cogs += _to_float(r.get("received_cogs")) or 0.0
        sold_cogs += _to_float(r.get("sold_cogs")) or 0.0
        expiry_writeoff_cogs += _to_float(r.get("expiry_writeoff_cogs")) or 0.0
    summary.update(
        {
            "stores": len(stores),
            "weeks": len(weeks),
            "categories": len(categories),
            "received_cogs": received_cogs,
            "sold_cogs": sold_cogs,
            "expiry_writeoff_cogs": expiry_writeoff_cogs,
        }
    )
    return summary


def _fmt_cell(value: Any, metric: str) -> str:
    if value is None:
        return "—"
    if metric in {"aov", "gmv", "gp", "lost_gmv_oos", "writeoff_cogs"}:
        return _fmt_money(value, 2)
    if metric in {"gp_margin", "fill_rate_units", "oos_lost_gmv_rate", "churn_rate", "writeoff_rate_vs_requested_units"}:
        return _fmt_pct(value, 2)
    if metric in {"orders_cnt", "new_buyers_7d", "writeoff_units", "active_buyers_avg"}:
        return _fmt_int(value)
    return _fmt_number(value, 2)


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


def _is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        s = value.strip().lower()
        return bool(s and s not in {"missing", "none", "null", "nan", "n/a", "unknown"})
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def _normalize_design_gap_code(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "missing"
    code = raw.lower()
    if code.endswith("_missing"):
        code = code[: -len("_missing")]
    aliases = {
        "randomization_unit_cfg": "randomization_unit",
        "analysis_unit_realized": "analysis_unit",
    }
    return aliases.get(code, code)


def _required_field_value(contract: dict[str, Any], key: str) -> Any:
    if key in contract:
        return contract.get(key)
    aliases = {
        "randomization_unit": "randomization_unit_cfg",
        "analysis_unit": "analysis_unit_realized",
    }
    alt = aliases.get(key)
    return contract.get(alt) if alt else None


def _build_ab_design_contract(
    *,
    ab_summary: dict[str, Any],
    first_exp: dict[str, Any],
    recommended_exp: dict[str, Any],
    run_cfg: dict[str, Any],
    doctor: dict[str, Any],
) -> dict[str, Any]:
    src = ab_summary.get("ab_design_contract")
    summary_contract = src if isinstance(src, dict) else {}
    metric_semantics_raw = summary_contract.get("metric_semantics")
    metric_semantics = metric_semantics_raw if isinstance(metric_semantics_raw, dict) else {}
    fallback_source = "ab_summary"
    if not summary_contract:
        fallback_source = "doctor_ab_plan_fallback" if first_exp else "run_config_fallback"
    contract: dict[str, Any] = {
        "randomization_unit_cfg": (
            summary_contract.get("randomization_unit_cfg")
            or first_exp.get("randomization_unit")
            or recommended_exp.get("randomization_unit")
            or run_cfg.get("experiment_unit")
        ),
        "analysis_unit_realized": (
            summary_contract.get("analysis_unit_realized")
            or first_exp.get("analysis_unit")
            or recommended_exp.get("analysis_unit")
        ),
        "pre_period_weeks": (
            summary_contract.get("pre_period_weeks")
            or first_exp.get("pre_period_weeks")
            or recommended_exp.get("pre_period_weeks")
        ),
        "test_period_weeks": (
            summary_contract.get("test_period_weeks")
            or first_exp.get("test_period_weeks")
            or recommended_exp.get("test_period_weeks")
        ),
        "wash_in_days": (
            summary_contract.get("wash_in_days")
            or first_exp.get("wash_in_days")
            or recommended_exp.get("wash_in_days")
        ),
        "attribution_window_rule": (
            summary_contract.get("attribution_window_rule")
            or first_exp.get("attribution_window_rule")
            or recommended_exp.get("attribution_window_rule")
        ),
        "test_side": (
            summary_contract.get("test_side")
            or first_exp.get("test_side")
            or recommended_exp.get("test_side")
        ),
        "alpha": summary_contract.get("alpha") or first_exp.get("alpha"),
        "power_target": summary_contract.get("power_target") or first_exp.get("power_target"),
        "mde_target": (
            summary_contract.get("mde_target")
            or first_exp.get("mde_target")
            or ((first_exp.get("sample_size_gate") or {}).get("mde") if isinstance(first_exp.get("sample_size_gate"), dict) else None)
        ),
        "metric_semantics": (
            metric_semantics
            or (first_exp.get("metric_semantics") if isinstance(first_exp.get("metric_semantics"), dict) else {})
            or (
                recommended_exp.get("metric_semantics")
                if isinstance(recommended_exp.get("metric_semantics"), dict)
                else {}
            )
        ),
        "surrogate_batch_id_strategy": (
            summary_contract.get("surrogate_batch_id_strategy")
            or first_exp.get("surrogate_batch_id_strategy")
            or recommended_exp.get("surrogate_batch_id_strategy")
        ),
    }
    required_raw = ((doctor.get("measurement_fix_plan") or {}).get("required_design_fields") if isinstance(doctor.get("measurement_fix_plan"), dict) else None)
    required_design_fields = [str(x).strip() for x in required_raw] if isinstance(required_raw, list) else []
    if not required_design_fields:
        required_design_fields = [
            "pre_period_weeks",
            "test_period_weeks",
            "wash_in_days",
            "attribution_window_rule",
            "test_side",
            "randomization_unit",
            "analysis_unit",
        ]
    required_design_fields = [x for x in required_design_fields if x]
    raw_design_gaps = summary_contract.get("design_gaps")
    normalized_gaps = (
        [_normalize_design_gap_code(x) for x in raw_design_gaps]
        if isinstance(raw_design_gaps, list)
        else []
    )
    for key in required_design_fields:
        if not _is_present(_required_field_value(contract, key)):
            normalized_gaps.append(_normalize_design_gap_code(key))
    seen: set[str] = set()
    design_gap_codes: list[str] = []
    for code in normalized_gaps:
        if code in seen:
            continue
        seen.add(code)
        design_gap_codes.append(code)
    present_count = sum(1 for key in required_design_fields if _is_present(_required_field_value(contract, key)))
    coverage = (present_count / len(required_design_fields)) if required_design_fields else None
    contract["required_design_fields"] = required_design_fields
    contract["design_gaps"] = raw_design_gaps if isinstance(raw_design_gaps, list) else []
    contract["design_gap_codes"] = design_gap_codes
    contract["is_complete"] = len(design_gap_codes) == 0
    contract["field_coverage_ratio"] = coverage
    contract["contract_source"] = fallback_source
    return contract


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


def _decision_with_ceiling(
    base_decision: str,
    *,
    measurement_state: str,
    ab_status: str,
    alignment_status: str,
    guardrail_breach: bool,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    decision = base_decision
    ms = measurement_state.upper()
    abs = ab_status.upper()
    if alignment_status == "FAIL_CURRENT_AB":
        return "STOP", ["current_ab_metric_misalignment"]
    if ms != "OBSERVABLE":
        reasons.append("measurement_state_not_observable")
        decision = "HOLD_NEED_DATA"
    if abs == "INVALID_METHODS":
        reasons.append("invalid_methods")
        decision = "HOLD_NEED_DATA"
    if guardrail_breach and decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
        reasons.append("guardrail_breach")
        decision = "HOLD_RISK"
    return decision, reasons


def _safe_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact_text(text), encoding="utf-8")


def _safe_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact_text(json.dumps(payload, ensure_ascii=False, indent=2)), encoding="utf-8")


def _artifact_meta(path_str: str | None) -> dict[str, Any] | None:
    if not path_str:
        return None
    p = Path(path_str)
    if not p.exists() or not p.is_file():
        return None
    data = p.read_bytes()
    st = p.stat()
    return {
        "path": path_str,
        "size_bytes": st.st_size,
        "mtime": st.st_mtime,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _json_paths_from_links_payload(links: dict[str, Any], *, include: list[Path] | None = None) -> list[Path]:
    out: list[Path] = []

    def _collect(raw: Any) -> None:
        if isinstance(raw, str) and raw.strip():
            p = Path(raw.strip())
            if p.suffix.lower() == ".json":
                out.append(p)
            return
        if isinstance(raw, list):
            for item in raw:
                _collect(item)
            return
        if isinstance(raw, dict):
            for item in raw.values():
                _collect(item)

    _collect(links.get("inputs"))
    _collect(links.get("outputs"))
    if include:
        out.extend(include)
    return out


def _write_metrics_csv(path: Path, metrics: dict[str, Any]) -> None:
    rows = [(k, metrics.get(k)) for k in _observed_metric_keys(metrics)]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerows(rows)


def _make_charts(charts_dir: Path, run_id: str, metrics: dict[str, Any], baseline_metrics: dict[str, Any] | None) -> list[str]:
    notes: list[str] = []
    try:
        # Headless-safe matplotlib setup for CLI/runtime environments.
        os.environ.setdefault("MPLCONFIGDIR", str((Path("data/logs/mpl_cache")).resolve()))
        import matplotlib  # type: ignore

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        notes.append("matplotlib unavailable; charts skipped")
        return notes

    charts_dir.mkdir(parents=True, exist_ok=True)

    def val(key: str, base_default: float = 0.0) -> tuple[float, float]:
        cur = _metric(metrics, key)
        cur_v = cur if cur is not None else base_default
        base = _metric(baseline_metrics or {}, key)
        base_v = base if base is not None else cur_v
        return base_v, cur_v

    def bar_chart(filename: str, title: str, metric_key: str) -> None:
        b, c = val(metric_key)
        fig, ax = plt.subplots(figsize=(6, 3.5))
        ax.bar(["baseline", "scenario"], [b, c], color=["#4C78A8", "#F58518"])
        ax.set_title(title)
        ax.grid(axis="y", alpha=0.25)
        fig.tight_layout()
        fig.savefig(charts_dir / filename)
        plt.close(fig)

    bar_chart("goal1_writeoff.png", "Goal1: Writeoff Units (lower is better)", "writeoff_units")
    bar_chart("goal2_aov.png", "Goal2: AOV (higher is better)", "aov")
    bar_chart("goal3_buyers.png", "Goal3: New Buyers 7d (higher is better)", "new_buyers_7d")

    # Impact chart: baseline vs scenario for GMV and writeoff.
    b_gmv, c_gmv = val("gmv")
    b_writeoff, c_writeoff = val("writeoff_units")
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    axes[0].plot([0, 1], [b_gmv, c_gmv], marker="o", color="#4C78A8", label="GMV")
    axes[0].plot([0, 1], [b_writeoff, c_writeoff], marker="o", color="#E45756", label="Writeoff Units")
    axes[0].set_xticks([0, 1], ["baseline", "scenario"])
    axes[0].set_title("Baseline vs Scenario")
    axes[0].grid(alpha=0.25)
    axes[0].legend(loc="best")

    deltas = [c_gmv - b_gmv, c_writeoff - b_writeoff]
    axes[1].bar(["GMV", "Writeoff"], deltas, color=["#54A24B", "#F58518"])
    axes[1].axhline(0.0, color="black", lw=1)
    axes[1].set_title("Impact Delta (scenario - baseline)")
    axes[1].grid(axis="y", alpha=0.25)
    fig.suptitle(f"Impact Summary: {run_id}")
    fig.tight_layout()
    fig.savefig(charts_dir / "impact_chart.png")
    fig.savefig(charts_dir / "impact.png")
    plt.close(fig)

    # Availability driver chart: fill rate vs OOS lost GMV rate.
    b_fill, c_fill = val("fill_rate_units")
    b_oos, c_oos = val("oos_lost_gmv_rate")
    fig, ax1 = plt.subplots(figsize=(7, 3.8))
    ax1.plot([0, 1], [b_fill, c_fill], marker="o", color="#4C78A8", label="fill_rate_units")
    ax1.set_xticks([0, 1], ["baseline", "scenario"])
    ax1.set_ylabel("Fill Rate", color="#4C78A8")
    ax1.tick_params(axis="y", labelcolor="#4C78A8")
    ax1.grid(alpha=0.25)
    ax2 = ax1.twinx()
    ax2.plot([0, 1], [b_oos, c_oos], marker="o", color="#E45756", label="oos_lost_gmv_rate")
    ax2.set_ylabel("OOS Lost GMV Rate", color="#E45756")
    ax2.tick_params(axis="y", labelcolor="#E45756")
    fig.suptitle("Availability Driver: Fill vs OOS")
    fig.tight_layout()
    fig.savefig(charts_dir / "availability_driver.png")
    plt.close(fig)

    return notes


def main() -> None:
    parser = argparse.ArgumentParser(description="Build L1 ops reports from existing artifacts")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--baseline-run-id", default=None, help="Optional baseline run for impact chart")
    args = parser.parse_args()

    run_id = args.run_id
    log_path = Path(f"data/logs/build_reports_{run_id}.log")
    out_dir = Path(f"reports/L1_ops/{run_id}")
    log_path = Path(f"data/logs/build_reports_{run_id}.log")
    try:
        dq_path = Path(f"data/dq_reports/{run_id}.json")
        captain_path = Path(f"data/llm_reports/{run_id}_captain.json")
        metrics_path = Path(f"data/metrics_snapshots/{run_id}.json")
        doctor_path = Path(f"data/agent_reports/{run_id}_doctor_variance.json")
        evaluator_path = Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")
        commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
        security_path = Path(f"data/security_reports/security_{run_id}.json")
        ab_path = None
        run_cfg_probe = _load_json(metrics_path) or {}
        if isinstance(run_cfg_probe, dict):
            exp_id_probe = str(((run_cfg_probe.get("run_config") or {}).get("experiment_id", "") if isinstance(run_cfg_probe.get("run_config"), dict) else "")).strip()
            if exp_id_probe:
                ab_path = Path(f"data/ab_reports/{run_id}_{exp_id_probe}_ab.json")
        if isinstance(ab_path, Path) and not ab_path.exists():
            ab_path = None
        if not isinstance(ab_path, Path):
            candidates = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab.json"))
            ab_path = candidates[0] if candidates else None

        for p in [dq_path, captain_path, metrics_path, doctor_path, evaluator_path, commander_path, security_path]:
            _assert_integrity(p, required=True)
        if isinstance(ab_path, Path):
            _assert_integrity(ab_path, required=True)

        dq = _load_json(dq_path) or {}
        captain = _load_json(captain_path) or {}
        snapshot = _load_json(metrics_path) or {}
        doctor = _load_json(doctor_path) or {}
        commander = _load_json(commander_path) or {}
        security = _load_json(security_path) or {}
        ab = _load_json(ab_path) if isinstance(ab_path, Path) else None
        ab_v2_path = None
        ab_v2 = None
        if isinstance(ab_path, Path):
            exp_from_ab = ab_path.stem.replace(f"{run_id}_", "").replace("_ab", "")
            ab_v2_path = Path(f"data/ab_reports/{run_id}_{exp_from_ab}_ab_v2.json")
            if ab_v2_path.exists():
                _assert_integrity(ab_v2_path, required=False)
                ab_v2 = _load_json(ab_v2_path)

        baseline_id = args.baseline_run_id
        if not baseline_id:
            baseline_id = ((doctor.get("inputs") or {}).get("control_run_id") if isinstance(doctor, dict) else None)
        baseline_snapshot = _load_json(Path(f"data/metrics_snapshots/{baseline_id}.json")) if baseline_id else None

        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        captain_eval = captain.get("eval_metrics", {}) if isinstance(captain.get("eval_metrics"), dict) else {}
        commander_decision = str(commander.get("decision", "HOLD"))
        blocked_by = commander.get("blocked_by", []) if isinstance(commander.get("blocked_by"), list) else []
        dq_rows = dq.get("rows", []) if isinstance(dq.get("rows"), list) else []
        dq_fail = sum(1 for r in dq_rows if isinstance(r, dict) and str(r.get("status")) == "FAIL")
        dq_warn = sum(1 for r in dq_rows if isinstance(r, dict) and str(r.get("status")) == "WARN")
        ab_summary = (ab or {}).get("summary", {}) if isinstance((ab or {}).get("summary"), dict) else {}
        ab_v2_primary = (ab_v2 or {}).get("primary_metric", {}) if isinstance((ab_v2 or {}).get("primary_metric"), dict) else {}
        doctor_plan = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
        first_exp = doctor_plan[0] if doctor_plan and isinstance(doctor_plan[0], dict) else {}
        recommended_exp = doctor.get("recommended_experiment", {}) if isinstance(doctor.get("recommended_experiment"), dict) else {}
        run_cfg = snapshot.get("run_config", {}) if isinstance(snapshot.get("run_config"), dict) else {}
        ab_design_contract = _build_ab_design_contract(
            ab_summary=ab_summary,
            first_exp=first_exp,
            recommended_exp=recommended_exp,
            run_cfg=run_cfg,
            doctor=doctor,
        )
        hypotheses = first_exp.get("hypotheses", []) if isinstance(first_exp.get("hypotheses"), list) else []
        first_hypothesis = hypotheses[0] if hypotheses and isinstance(hypotheses[0], dict) else {}
        hypothesis_portfolio = doctor.get("hypothesis_portfolio", []) if isinstance(doctor.get("hypothesis_portfolio"), list) else []
        portfolio_sorted = sorted(
            [h for h in hypothesis_portfolio if isinstance(h, dict)],
            key=lambda h: (int(h.get("rank", 9999)) if str(h.get("rank", "")).strip().isdigit() else 9999, -float(h.get("ice_score", 0.0) or 0.0)),
        )
        top_portfolio_hyp = portfolio_sorted[0] if portfolio_sorted else {}
        hypothesis_text = (
            str(first_hypothesis.get("hypothesis_statement", "")).strip()
            or str(top_portfolio_hyp.get("hypothesis_statement", "")).strip()
            or "missing"
        )
        expected_impact = (
            str(first_hypothesis.get("expected_effect_range", "")).strip()
            or str(top_portfolio_hyp.get("expected_uplift_range", "")).strip()
            or "missing"
        )
        top_goal_metric = str(top_portfolio_hyp.get("target_metric", "")).strip()
        required_sample = first_exp.get("sample_size_gate", {}) if isinstance(first_exp.get("sample_size_gate"), dict) else {}
        actual_sample = ab_summary.get("actual_sample_size", {}) if isinstance(ab_summary.get("actual_sample_size"), dict) else {}
        report_warnings: list[str] = []
        data_source_type = str(snapshot.get("data_source_type", "unknown")).strip().lower() if isinstance(snapshot, dict) else "unknown"
        contract_completeness = snapshot.get("contract_completeness", {}) if isinstance(snapshot.get("contract_completeness"), dict) else {}
        goal1_contract_ready = bool(contract_completeness.get("goal1_contract_ready", False))
        goal1_rows = _load_goal1_store_week_category_rows(snapshot if isinstance(snapshot, dict) else {})
        goal1_summary = _summarize_goal1_store_week_category(goal1_rows)
        goal1_rows_cnt = int(goal1_summary.get("rows") or 0)
        goal1_store_cnt = int(goal1_summary.get("stores") or 0)
        goal1_category_cnt = int(goal1_summary.get("categories") or 0)
        expiry_cov = _to_float(
            ((contract_completeness.get("checks", {}) or {}).get("expiry_date_coverage", {}) or {}).get("value")
        )
        ab_metric_from_summary = str(ab_summary.get("primary_metric", "")).strip().lower()
        if ab_metric_from_summary in {"writeoff_rate_adj", "writeoff_units", "writeoff_cogs"} and not goal1_contract_ready:
            report_warnings.append(
                "goal1_contract_incomplete: batch_id/writeoff_reason/expiry coverage below threshold; status should remain BLOCKED_BY_DATA until fixed."
            )
        if data_source_type not in {"synthetic", "real", "mixed"}:
            report_warnings.append("unknown_data_source_type: set run_config.data_source_type to synthetic|real|mixed and regenerate snapshot.")

        charts_dir = out_dir / "charts"
        out_dir.mkdir(parents=True, exist_ok=True)

        _write_metrics_csv(out_dir / "metrics_table.csv", metrics)

        chart_notes = _make_charts(
            charts_dir=charts_dir,
            run_id=run_id,
            metrics=metrics,
            baseline_metrics=(baseline_snapshot or {}).get("metrics") if isinstance(baseline_snapshot, dict) else None,
        )

        ab_status_raw = str((ab_v2 or {}).get('status') if isinstance(ab_v2, dict) else ((ab or {}).get('status') if isinstance(ab, dict) else 'missing'))
        ab_notes = (ab or {}).get("notes", []) if isinstance((ab or {}).get("notes"), list) else []
        measurement_state = str(doctor.get("measurement_state", "missing"))
        evaluator = _load_json(evaluator_path) or {}
        evaluator_decision = str(evaluator.get("decision", "unknown"))
        evaluator_reasons = evaluator.get("reasons", []) if isinstance(evaluator.get("reasons"), list) else []
        doctor_reasons = doctor.get("reasons", []) if isinstance(doctor.get("reasons"), list) else []
        fatal_unobservable = (
            str(ab_status_raw).upper() in {"METHODOLOGY_MISMATCH", "MISSING_ASSIGNMENT"}
            or any("customer_join_unavailable_fallback_store" in str(n) for n in ab_notes)
        )
        ab_uplift_source = ab_v2_primary.get("uplift") if isinstance(ab_v2_primary, dict) else ab_summary.get("primary_metric_uplift")
        ab_ci_source = ab_v2_primary.get("ci95") if isinstance(ab_v2_primary, dict) else ab_summary.get("primary_metric_uplift_ci95")
        ab_p_source = ab_v2_primary.get("p_value") if isinstance(ab_v2_primary, dict) else ab_summary.get("primary_metric_p_value")
        ab_uplift_display = "—" if fatal_unobservable else _fmt_uplift_pct(ab_uplift_source)
        ab_ci_display = "—" if fatal_unobservable else _fmt_ci_pct(ab_ci_source)
        ab_uplift_raw = ab_uplift_source
        ci_raw = ab_ci_source
        if fatal_unobservable:
            ab_interpretation = "AB not interpretable (measurement blind spot)."
        else:
            try:
                u = float(ab_uplift_raw)
            except Exception:
                u = None
            ci_cross_zero = None
            if isinstance(ci_raw, (list, tuple)) and len(ci_raw) == 2:
                try:
                    lo = float(ci_raw[0])
                    hi = float(ci_raw[1])
                    ci_cross_zero = lo <= 0.0 <= hi
                except Exception:
                    ci_cross_zero = None
            if u is None:
                ab_interpretation = "AB effect unavailable."
            elif u < 0:
                ab_interpretation = "Treatment is WORSE than control on primary metric."
            elif u > 0:
                ab_interpretation = "Treatment is BETTER than control on primary metric."
            else:
                ab_interpretation = "Treatment equals control on primary metric."
            if ci_cross_zero is True:
                ab_interpretation += " CI crosses 0 => effect is not statistically reliable."
            elif ci_cross_zero is False:
                ab_interpretation += " CI is fully above/below 0 => direction is statistically consistent."
        primary_metric_name = str(ab_summary.get("primary_metric", "primary_metric"))
        alpha = 0.05
        p_value = ab_p_source
        p_value_fmt = _fmt_p_value(p_value)
        ab_primary_metric = str((ab_v2_primary.get("name") if isinstance(ab_v2_primary, dict) else None) or ab_summary.get("primary_metric", "")).strip()
        ab_goal = _goal_from_metric(ab_primary_metric)
        next_goal_metric = top_goal_metric
        next_goal = _goal_from_metric(next_goal_metric)
        current_contract_metric, current_contract_source = _resolve_current_ab_contract_metric(doctor)
        current_contract_goal = _goal_from_metric(current_contract_metric or "")
        if current_contract_metric:
            if current_contract_goal != "unknown" and ab_goal != "unknown":
                current_alignment_status = "PASS_CURRENT_AB" if current_contract_goal == ab_goal else "FAIL_CURRENT_AB"
            else:
                current_alignment_status = "INCONCLUSIVE_CURRENT_AB"
        else:
            current_alignment_status = "N/A_NO_CURRENT_CONTRACT_METRIC"
        next_vs_current_status = (
            "MATCH"
            if (next_goal != "unknown" and ab_goal != "unknown" and next_goal == ab_goal)
            else ("DIFFERENT" if next_goal != "unknown" and ab_goal != "unknown" else "UNKNOWN")
        )
        reject_by_p = False
        if p_value_fmt != "missing":
            reject_by_p = float(p_value) < alpha  # type: ignore[arg-type]
        reject_by_ci = False
        ci_raw = ab_summary.get("primary_metric_uplift_ci95")
        if isinstance(ci_raw, (list, tuple)) and len(ci_raw) == 2:
            try:
                lo = float(ci_raw[0])
                hi = float(ci_raw[1])
                reject_by_ci = not (lo <= 0.0 <= hi)
            except Exception:
                reject_by_ci = False
        if isinstance(ab_v2, dict):
            stat_decision_text = f"{ab_v2.get('status', 'missing')}: {ab_v2.get('reason', 'missing')}"
        elif fatal_unobservable:
            stat_decision_text = "Not testable (measurement blind spot)."
        elif p_value_fmt == "missing" and ci_raw is None:
            stat_decision_text = "Not testable (missing p-value and CI)."
        else:
            inconsistent = False
            if reject_by_ci:
                stat_decision_text = "Reject H0 (CI excludes 0 at 95%)."
            else:
                stat_decision_text = "Fail to reject H0 (CI includes 0 at 95%)."
            if p_value_fmt != "missing":
                stat_decision_text += f" Auxiliary p-value={p_value_fmt}."
                if (reject_by_p and not reject_by_ci) or ((not reject_by_p) and reject_by_ci):
                    inconsistent = True
                    stat_decision_text += " Warning: p-value/CI inconsistency."
            if inconsistent:
                stat_decision_text += " Final status: INCONCLUSIVE until methods are aligned."
        if current_alignment_status == "FAIL_CURRENT_AB":
            report_warnings.append(
                f"current_ab_metric_mismatch: contract_goal={current_contract_goal} vs ab_goal={ab_goal}"
            )
        if next_vs_current_status == "DIFFERENT":
            report_warnings.append(
                f"next_contour_differs: next_goal={next_goal} vs current_ab_goal={ab_goal}"
            )
        sample_gate = (ab or {}).get("sample_size_gate", {}) if isinstance(ab, dict) else {}
        n_orders_c = ab_summary.get("n_orders_control")
        n_orders_t = ab_summary.get("n_orders_treatment")
        n_units_c = ab_summary.get("n_units_control")
        n_units_t = ab_summary.get("n_units_treatment")
        min_orders = sample_gate.get("min_orders_per_arm")
        min_units = sample_gate.get("min_units_per_arm")

        decision_card = [
            f"# Decision Card — {run_id}",
            "",
            f"- Decision: `{commander_decision}`",
            f"- Hypothesis: {hypothesis_text}",
            f"- Expected impact: `{expected_impact}`",
            f"- DQ: fail={dq_fail}, warn={dq_warn}",
            f"- Captain verdict: `{((captain.get('result') or {}).get('verdict') if isinstance(captain.get('result'), dict) else 'unknown')}`",
            f"- Doctor decision: `{doctor.get('decision', 'unknown')}`",
            f"- Security passed: `{bool(security.get('passed', False))}`",
            f"- AB status: `{ab_status_raw}`",
            f"- Data source type: `{data_source_type}`",
            f"- Goal1 contract ready: `{goal1_contract_ready}`",
            (
                "- Sample size (required/actual): "
                f"`{required_sample.get('min_orders', required_sample.get('min_orders_per_arm'))}`/"
                f"`{actual_sample.get('control')}` control, "
                f"`{required_sample.get('min_orders', required_sample.get('min_orders_per_arm'))}`/"
                f"`{actual_sample.get('treatment')}` treatment"
            ),
            f"- AB uplift + CI: `{ab_uplift_display}` / `{ab_ci_display}`",
            f"- AB interpretation: {ab_interpretation}",
            f"- AB statistical report: `{out_dir / 'AB_STAT_REPORT.md'}`",
            "",
            "## Contours (Current AB vs Next Experiment)",
            f"- Current AB contour: metric=`{ab_primary_metric}`, goal=`{ab_goal}`, contract_metric=`{current_contract_metric or 'missing'}`, contract_source=`{current_contract_source}`, alignment=`{current_alignment_status}`",
            f"- Next experiment contour: metric=`{next_goal_metric or 'missing'}`, goal=`{next_goal}`, vs_current_ab=`{next_vs_current_status}`",
            "",
            "## Statistical Test Protocol",
            f"- source: `{out_dir / 'AB_STAT_REPORT.md'}`",
            f"- Statistical decision: {stat_decision_text}",
            f"- Current AB contract alignment: `{current_alignment_status}`",
            f"- Next contour vs current AB: `{next_vs_current_status}`",
            "",
            "## North Star Snapshot",
            f"- Goal1 proxy (writeoff_units): `{_fmt_metric_value(metrics, 'writeoff_units')}`",
            f"- Goal2 (aov): `{_fmt_metric_value(metrics, 'aov')}`",
            f"- Goal3 (new_buyers_7d): `{_fmt_metric_value(metrics, 'new_buyers_7d')}`",
            "",
            "## Guardrails",
            f"- gp_margin: `{_fmt_metric_value(metrics, 'gp_margin')}`",
            f"- fill_rate_units: `{_fmt_metric_value(metrics, 'fill_rate_units')}`",
            f"- oos_lost_gmv_rate: `{_fmt_metric_value(metrics, 'oos_lost_gmv_rate')}`",
            "",
            "## Blockers",
        ]
        if fatal_unobservable:
            decision_card.extend(
                [
                    "## FATAL ERROR",
                    "❌ Experiment unobservable: cannot compute uplift. Fix assignment/join.",
                    f"- AB status: `{ab_status_raw or 'missing'}`",
                    f"- AB notes: `{ab_notes}`",
                    "",
                ]
            )
        if blocked_by:
            decision_card.extend([f"- {x}" for x in blocked_by[:10]])
        else:
            decision_card.append("- none")
        # Decision Why Tree: short causal chain for humans.
        reason_lines: list[str] = []
        for r in evaluator_reasons[:2]:
            reason_lines.append(str(r))
        for r in doctor_reasons:
            if isinstance(r, dict):
                code = str(r.get("code", "")).strip()
                msg = str(r.get("message", "")).strip()
                if code or msg:
                    reason_lines.append(f"{code}: {msg}".strip(": "))
            elif str(r).strip():
                reason_lines.append(str(r).strip())
            if len(reason_lines) >= 3:
                break
        if not reason_lines and blocked_by:
            reason_lines = [str(x) for x in blocked_by[:3]]
        decision_card.extend(
            [
                "",
                "## Decision Why Tree",
                f"- Current state: measurement_state=`{measurement_state}`, ab_status=`{ab_status_raw}`, evaluator=`{evaluator_decision}`, commander=`{commander_decision}`",
                "- Top reasons:",
            ]
        )
        if reason_lines:
            decision_card.extend([f"  - {x}" for x in reason_lines[:3]])
        else:
            decision_card.append("  - no explicit reason rows found")
        decision_card.extend(
            [
                "- What would change decision to GO:",
                "  - observable assignment + valid AB join path",
                "  - no guardrail breach (fill_rate/gp_margin/oos)",
                "  - grounded narrative + governance review complete",
            ]
        )

        # Decision Card V2 (strict per-goal structure + machine-readable JSON).
        experiment_id = str(((snapshot.get("run_config") or {}).get("experiment_id") if isinstance(snapshot.get("run_config"), dict) else "") or "missing")
        ab_primary_goal = str((ab_v2 or {}).get("ab_primary_goal") or ab_goal or "unknown")
        hypothesis_target_goal = next_goal
        alignment_status = current_alignment_status
        method_name = str((ab_v2 or {}).get("method_name", "missing")) if isinstance(ab_v2, dict) else "missing"
        sampling = (ab_v2 or {}).get("sampling", {}) if isinstance((ab_v2 or {}).get("sampling"), dict) else {}
        srm_check = str(sampling.get("srm_check") or ab_summary.get("srm_status") or "missing").upper()
        alpha_val = (ab_v2 or {}).get("alpha", 0.05) if isinstance(ab_v2, dict) else 0.05
        ci_level = (ab_v2 or {}).get("ci_level", 0.95) if isinstance(ab_v2, dict) else 0.95
        multiple_testing_policy = (
            "Holm-Bonferroni"
            if str((ab_v2 or {}).get("multiple_testing_policy", "")).strip().lower() == "holm-bonferroni"
            else "single primary, others descriptive"
        )
        ab_status_upper = str(ab_status_raw).upper()
        p_val_check = _to_float(ab_p_source)
        ci_check = ab_ci_source if isinstance(ab_ci_source, (list, tuple)) and len(ab_ci_source) == 2 else None
        ci_contains_zero = None
        if ci_check:
            lo_v = _to_float(ci_check[0])
            hi_v = _to_float(ci_check[1])
            if lo_v is not None and hi_v is not None:
                ci_contains_zero = lo_v <= 0 <= hi_v
        p_ci_contradiction = bool(
            p_val_check is not None
            and ci_contains_zero is not None
            and ((p_val_check <= float(alpha_val) and ci_contains_zero) or (p_val_check > float(alpha_val) and not ci_contains_zero))
        )
        fatal_reasons_v2: list[str] = []
        if alignment_status == "FAIL_CURRENT_AB":
            fatal_reasons_v2.append("current_ab_metric_misalignment")
        if p_ci_contradiction:
            fatal_reasons_v2.append("p_value_ci_contradiction")
        if ab_status_upper in AB_METHOD_VALIDITY_ERROR_STATUSES:
            fatal_reasons_v2.append(ab_status_upper.lower())
        goals_v2 = (ab_v2 or {}).get("goals", {}) if isinstance((ab_v2 or {}).get("goals"), dict) else {}
        guardrail_breach = (
            (_to_float(metrics.get("fill_rate_units")) or 0.0) < 0.90
            or (_to_float(metrics.get("oos_lost_gmv_rate")) or 0.0) > 0.10
            or (_to_float(metrics.get("gp_margin")) or 0.0) < 0.0
        )
        final_decision_v2, ceiling_reason_codes = _decision_with_ceiling(
            commander_decision,
            measurement_state=measurement_state,
            ab_status=ab_status_upper,
            alignment_status=alignment_status,
            guardrail_breach=guardrail_breach,
        )

        goal_defs = [
            ("goal1", "GOAL 1: Writeoff / Inventory Efficiency", "writeoff_units", ["writeoff_cogs", "writeoff_rate_vs_requested_units"], ["fill_rate_units", "oos_lost_gmv_rate", "gp_margin"]),
            ("goal2", "GOAL 2: Revenue / AOV", "aov", ["gmv", "gp"], ["gp_margin", "fill_rate_units", "oos_lost_gmv_rate"]),
            ("goal3", "GOAL 3: Buyers / Audience", "new_buyers_7d", ["active_buyers_avg", "churn_rate"], ["churn_rate", "rep_mean"]),
        ]
        goal_blocks_json: dict[str, Any] = {}
        goal_blocks_md: list[str] = []
        for idx, (goal_id, goal_title, default_metric, supporting, goal_guardrails) in enumerate(goal_defs, start=1):
            g = goals_v2.get(goal_id, {}) if isinstance(goals_v2.get(goal_id), dict) else {}
            metric_name = str(g.get("metric") or default_metric)
            observed_metrics_rows = _goal_observed_metrics_rows(
                metrics=metrics,
                primary_metric=metric_name,
                supporting_metrics=supporting,
                guardrails=goal_guardrails,
            )
            prev_v = g.get("prev")
            plan_v = g.get("plan")
            control_v = g.get("control")
            treatment_v = g.get("treatment")
            abs_delta_v = g.get("abs_delta")
            rel_delta_v = g.get("rel_delta")
            p_v = g.get("p_value")
            ci_v = g.get("ci95")
            goal_decision = str(g.get("decision") or ("INVALID" if "invalid_methods" in fatal_reasons_v2 else "Descriptive only"))
            goal_role = str(g.get("status") or ("Targeted" if goal_id == ab_primary_goal else "Monitored"))
            stat_decision = "INVALID"
            p_num = _to_float(p_v)
            ci_contains = None
            if isinstance(ci_v, (list, tuple)) and len(ci_v) == 2:
                lo = _to_float(ci_v[0])
                hi = _to_float(ci_v[1])
                if lo is not None and hi is not None:
                    ci_contains = lo <= 0 <= hi
            if ab_status_upper == "UNDERPOWERED":
                stat_decision = "UNDERPOWERED"
            elif ab_status_upper in AB_METHOD_VALIDITY_ERROR_STATUSES:
                stat_decision = "INVALID"
            elif p_num is None:
                stat_decision = "Fail to Reject H0"
            elif ci_contains is not None and p_num <= float(alpha_val) and not ci_contains:
                stat_decision = "Reject H0"
            else:
                stat_decision = "Fail to Reject H0"
            goal_blocks_json[goal_id] = {
                "goal_role": goal_role,
                "primary_metric": metric_name,
                "supporting_metrics": supporting,
                "guardrails": goal_guardrails,
                "observed_metrics": observed_metrics_rows,
                "comparison_row": {
                    "metric": metric_name,
                    "prev": prev_v,
                    "plan": plan_v,
                    "control": control_v,
                    "treatment": treatment_v,
                    "abs_delta": abs_delta_v,
                    "rel_delta_pct": rel_delta_v,
                    "alpha": alpha_val,
                    "p_value": p_v,
                    "ci95": ci_v,
                    "decision": stat_decision,
                },
                "methodology": {
                    "method_used": method_name,
                    "why_this_method": "Selected from AB report metadata based on metric type; deterministic from artifact.",
                    "assumptions_checked": [
                        f"sample_size_control={ab_summary.get('n_orders_control')}",
                        f"sample_size_treatment={ab_summary.get('n_orders_treatment')}",
                        f"srm_check={srm_check}",
                    ],
                },
                "statistical_conclusion": {
                    "hypothesis_supported": stat_decision == "Reject H0",
                    "inside_expected_range": "unknown",
                    "guardrail_respected": not guardrail_breach,
                    "summary": goal_decision,
                },
            }
            goal_blocks_md.extend(
                [
                    "",
                    f"## SECTION {idx} — {goal_title}",
                    "",
                    "A) Goal Role",
                    f"- `{goal_role}`",
                    "",
                    "B) Metrics",
                    f"- primary_metric: `{metric_name}`",
                    f"- supporting_metrics: `{supporting}`",
                    f"- guardrails: `{goal_guardrails}`",
                    "",
                    "C) Comparison Table",
                    "",
                    "| Metric | Prev | Plan | Control | Treatment | Abs_Delta | Rel_Delta_pct | alpha | p_value | CI95 | Decision |",
                    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|",
                    f"| {metric_name} | {_fmt_cell(prev_v, metric_name)} | {_fmt_cell(plan_v, metric_name)} | {_fmt_cell(control_v, metric_name)} | {_fmt_cell(treatment_v, metric_name)} | {_fmt_cell(abs_delta_v, metric_name)} | {_fmt_uplift_pct(rel_delta_v) if rel_delta_v is not None else '—'} | {_fmt_number(alpha_val, 2)} | {_fmt_p_value(p_v) if p_v is not None else '—'} | {_fmt_ci_pct(ci_v)} | {stat_decision} |",
                    "",
                    "D) Methodology",
                    f"- method_used: `{method_name}`",
                    "- why_this_method: deterministic from AB artifact and metric type mapping.",
                    f"- assumptions_checked: sample_size_control=`{ab_summary.get('n_orders_control')}`, sample_size_treatment=`{ab_summary.get('n_orders_treatment')}`, srm_check=`{srm_check}`",
                    "",
                    "E) Statistical Conclusion",
                    f"- Is hypothesis supported? `{stat_decision == 'Reject H0'}`",
                    "- Is it inside expected impact range? `unknown`",
                    f"- Is guardrail respected? `{not guardrail_breach}`",
                    "",
                    "F) Observed Metrics in Contour (including guardrails)",
                    "",
                    "| Metric | Role | Observed Value |",
                    "|---|---|---:|",
                ]
            )
            for obs in observed_metrics_rows:
                goal_blocks_md.append(
                    f"| {obs['metric']} | {obs['role']} | {obs['display_value']} |"
                )

        anti_goodhart = False
        anti_goodhart_error = ""
        try:
            anti_goodhart_verdict = load_anti_goodhart_verdict(run_id)
            anti_goodhart = bool(anti_goodhart_verdict.get("anti_goodhart_triggered", False))
            if str(anti_goodhart_verdict.get("status", "")).upper() != "PASS":
                anti_goodhart_error = "ANTI_GOODHART_MISMATCH:verdict_status_fail"
        except Exception as exc:
            anti_goodhart_error = f"ANTI_GOODHART_MISMATCH:{exc}"
        if anti_goodhart_error:
            report_warnings.append("anti_goodhart_sot_invalid")
        cross_tradeoff_lines = [
            "## SECTION 4 — Cross-Goal Tradeoffs",
            "",
            f"- anti_goodhart_triggered: `{anti_goodhart}`",
            f"- anti_goodhart_sot_error: `{anti_goodhart_error or 'none'}`",
            f"- guardrail_breach: `{guardrail_breach}`",
            "- explicit_tradeoff: Goal improvements are not accepted if guardrails are breached.",
        ]
        if guardrail_breach:
            cross_tradeoff_lines.append("- result: `Anti-Goodhart trigger active`")

        decision_card_v2_json = {
            "run_id": run_id,
            "experiment_id": experiment_id,
            "experiment_header": {
                "hypothesis_statement": hypothesis_text,
                "hypothesis_target_goal": hypothesis_target_goal,
                "next_experiment_metric": next_goal_metric,
                "next_experiment_goal": next_goal,
                "ab_primary_goal": ab_primary_goal,
                "ab_primary_metric": ab_primary_metric,
                "current_contract_metric": current_contract_metric,
                "current_contract_metric_source": current_contract_source,
                "current_contract_goal": current_contract_goal,
                "alignment_status": alignment_status,
                "next_vs_current_ab_status": next_vs_current_status,
                "fatal_goal_metric_misalignment": alignment_status == "FAIL_CURRENT_AB",
                "assignment_method": "deterministic hash + salt + unit_id",
                "unit_of_randomization": str((snapshot.get("run_config") or {}).get("experiment_unit", "unknown")) if isinstance(snapshot.get("run_config"), dict) else "unknown",
                "window_days": int((snapshot.get("run_config") or {}).get("horizon_days", 14)) if isinstance(snapshot.get("run_config"), dict) else 14,
                "alpha": alpha_val,
                "multiple_testing_policy": multiple_testing_policy,
                "srm_check": srm_check,
                "measurement_state": measurement_state,
                "ab_status": ab_status_upper,
                "pre_period_weeks": ab_design_contract.get("pre_period_weeks"),
                "test_period_weeks": ab_design_contract.get("test_period_weeks"),
                "wash_in_days": ab_design_contract.get("wash_in_days"),
                "attribution_window_rule": ab_design_contract.get("attribution_window_rule"),
                "randomization_unit_cfg": ab_design_contract.get("randomization_unit_cfg"),
                "analysis_unit_realized": ab_design_contract.get("analysis_unit_realized"),
                "ab_design_contract_complete": ab_design_contract.get("is_complete"),
                "data_source_type": data_source_type,
                "goal1_contract_ready": goal1_contract_ready,
            },
            "ab_design_contract": ab_design_contract,
            "data_source_type": data_source_type,
            "contract_completeness": contract_completeness,
            "goal_blocks": goal_blocks_json,
            "cross_goal_tradeoffs": {
                "anti_goodhart_triggered": anti_goodhart or guardrail_breach,
                "guardrail_breach": guardrail_breach,
            },
            "final_decision": {
                "decision": final_decision_v2,
                "input_decision": commander_decision,
                "ceiling_reason_codes": ceiling_reason_codes,
                "fatal_reasons": fatal_reasons_v2,
            },
            "status": "FATAL" if fatal_reasons_v2 else "OK",
            "version": "decision_card_v2",
        }

        decision_card_v2_md = [
            f"# DECISION CARD V2 — {run_id}",
            "",
            "## SECTION 0 — Experiment Header",
            f"- run_id: `{run_id}`",
            f"- experiment_id: `{experiment_id}`",
            f"- hypothesis_statement: `{hypothesis_text}`",
            f"- next_experiment_metric: `{next_goal_metric or 'missing'}`",
            f"- next_experiment_goal: `{hypothesis_target_goal}`",
            f"- current_ab_metric: `{ab_primary_metric or 'missing'}`",
            f"- current_ab_goal: `{ab_primary_goal}`",
            f"- current_contract_metric: `{current_contract_metric or 'missing'}`",
            f"- current_contract_metric_source: `{current_contract_source}`",
            f"- current_contract_goal: `{current_contract_goal}`",
            f"- current_alignment_status: `{alignment_status}`",
            f"- next_vs_current_ab_status: `{next_vs_current_status}`",
        ]
        decision_card_v2_md.extend(
            [
                "",
                "## SECTION 0B — AB Design Contract",
                f"- contract_source: `{ab_design_contract.get('contract_source')}`",
                f"- randomization_unit_cfg: `{ab_design_contract.get('randomization_unit_cfg')}`",
                f"- analysis_unit_realized: `{ab_design_contract.get('analysis_unit_realized')}`",
                f"- pre_period_weeks: `{ab_design_contract.get('pre_period_weeks')}`",
                f"- test_period_weeks: `{ab_design_contract.get('test_period_weeks')}`",
                f"- wash_in_days: `{ab_design_contract.get('wash_in_days')}`",
                f"- attribution_window_rule: `{ab_design_contract.get('attribution_window_rule')}`",
                f"- test_side: `{ab_design_contract.get('test_side')}`",
                f"- metric_semantics: `{ab_design_contract.get('metric_semantics')}`",
                f"- surrogate_batch_id_strategy: `{ab_design_contract.get('surrogate_batch_id_strategy')}`",
                f"- required_design_fields: `{ab_design_contract.get('required_design_fields')}`",
                f"- design_gap_codes: `{ab_design_contract.get('design_gap_codes')}`",
                f"- field_coverage_ratio: `{ab_design_contract.get('field_coverage_ratio')}`",
                f"- is_complete: `{ab_design_contract.get('is_complete')}`",
            ]
        )
        if alignment_status == "FAIL_CURRENT_AB":
            decision_card_v2_md.extend(
                [
                    "",
                    "### FATAL: Goal/Metric Misalignment",
                    "- Stop: current AB contract metric does not align with AB primary metric.",
                    "- No decision allowed.",
                ]
            )
        decision_card_v2_md.extend(
            [
                f"- assignment_method: `deterministic hash + salt + unit_id`",
                f"- unit_of_randomization: `{decision_card_v2_json['experiment_header']['unit_of_randomization']}`",
                f"- window_days: `{decision_card_v2_json['experiment_header']['window_days']}`",
                f"- alpha: `{alpha_val}`",
                f"- multiple_testing_policy: `{multiple_testing_policy}`",
                f"- SRM_check: `{srm_check}`",
                f"- measurement_state: `{measurement_state}`",
                f"- ab_status: `{ab_status_upper}`",
            ]
        )
        if fatal_reasons_v2:
            decision_card_v2_md.extend(
                [
                    "",
                    "### FATAL",
                    f"- reasons: `{fatal_reasons_v2}`",
                    "- Decision ceiling applied.",
                ]
            )
        decision_card_v2_md.extend(goal_blocks_md)
        decision_card_v2_md.extend([""] + cross_tradeoff_lines + ["", "## SECTION 5 — Final Decision", f"- decision: `{final_decision_v2}`", f"- input_decision: `{commander_decision}`", f"- ceiling_reason_codes: `{ceiling_reason_codes}`"])
        _safe_write(Path(f"reports/L1_ops/{run_id}/DECISION_CARD_V2.md"), "\n".join(decision_card_v2_md) + "\n")
        _safe_write_json(Path(f"data/decision_cards/{run_id}_decision_card_v2.json"), decision_card_v2_json)

        goal_scorecard = [
            f"# Goal Scorecard — {run_id}",
            "",
            "| Goal | North Star | Value | Guardrail | Value |",
            "|---|---|---:|---|---:|",
            f"| Goal1 (spoilage) | writeoff_units | {_fmt_metric_value(metrics, 'writeoff_units')} | fill_rate_units | {_fmt_metric_value(metrics, 'fill_rate_units')} |",
            f"| Goal2 (aov) | aov | {_fmt_metric_value(metrics, 'aov')} | gp_margin | {_fmt_metric_value(metrics, 'gp_margin')} |",
            f"| Goal3 (buyers) | new_buyers_7d | {_fmt_metric_value(metrics, 'new_buyers_7d')} | oos_lost_gmv_rate | {_fmt_metric_value(metrics, 'oos_lost_gmv_rate')} |",
        ]
        _safe_write(out_dir / "goal_scorecard.md", "\n".join(goal_scorecard) + "\n")

        scorecard = [
            f"# Agent Effectiveness — {run_id}",
            "",
            "## Captain Sanity",
            f"- issue_coverage: `{captain_eval.get('issue_coverage')}`",
            f"- no_extra_issues: `{captain_eval.get('no_extra_issues')}`",
            f"- actionability: `{captain_eval.get('actionability')}`",
            f"- safety: `{captain_eval.get('safety')}`",
            f"- semantic_score: `{captain_eval.get('semantic_score')}`",
            f"- fallback_used: `{captain.get('fallback_used')}`",
            "",
            "## Doctor Variance",
            f"- decision: `{doctor.get('decision')}`",
            f"- experiments_count: `{len(doctor.get('ab_plan', []) if isinstance(doctor.get('ab_plan'), list) else [])}`",
            f"- semantic_score: `{((doctor.get('quality') or {}).get('semantic_score') if isinstance(doctor.get('quality'), dict) else None)}`",
            "",
            "## Commander Priority",
            f"- decision: `{commander.get('decision')}`",
            f"- blocked_by_count: `{len(blocked_by)}`",
            f"- interference_risk: `{((commander.get('next_experiment') or {}).get('interference', {}) if isinstance(commander.get('next_experiment'), dict) else {}).get('risk_level')}`",
            f"- priority_score_selected: `{((commander.get('next_experiment') or {}) if isinstance(commander.get('next_experiment'), dict) else {}).get('priority_score')}`",
        ]
        _safe_write(out_dir / "agent_effectiveness.md", "\n".join(scorecard) + "\n")
        _safe_write(out_dir / "agent_scorecard.md", "\n".join(scorecard) + "\n")

        synthetic_bias_path = Path(f"data/realism_reports/{run_id}_synthetic_bias.json")
        synthetic_bias = _load_json(synthetic_bias_path) or {}
        _safe_write(
            out_dir / "synthetic_bias.md",
            "\n".join(
                [
                    f"# Synthetic Bias Audit — {run_id}",
                    "",
                    f"- status: `{synthetic_bias.get('status', 'missing')}`",
                    f"- summary: `{synthetic_bias.get('summary', 'missing')}`",
                    f"- source: `{synthetic_bias_path}`",
                    "",
                ]
            ),
        )

        # Rebuild legacy decision_card.md into a strict, interview-grade structure (A-E).
        blocked_ab_statuses = set(AB_DECISION_INVALID_STATUSES)
        # Policy update: show computed numbers for INVALID_METHODS as diagnostic-only (do not hide),
        # but still hide for truly unobservable states.
        hide_ab_numbers = ab_status_upper in (AB_DECISION_INVALID_STATUSES - {"INVALID_METHODS"})
        top_action_summary = str(top_portfolio_hyp.get("action_summary", "")).strip() or "missing"
        top_mechanism = ""
        hyp_stmt = str(top_portfolio_hyp.get("hypothesis_statement", "")).strip()
        if " because " in hyp_stmt:
            top_mechanism = hyp_stmt.split(" because ", 1)[1].rstrip(".")
        expected_guardrail_bounds = {
            "fill_rate_units_floor": 0.90,
            "gmv_floor": (top_portfolio_hyp.get("guardrails", {}) or {}).get("gmv_floor") if isinstance(top_portfolio_hyp.get("guardrails"), dict) else None,
            "gp_margin_floor": 0.0,
            "oos_lost_gmv_rate_ceiling": 0.10,
        }
        top_scope = top_portfolio_hyp.get("scope", []) if isinstance(top_portfolio_hyp.get("scope"), list) else []
        top_scope_disp = ", ".join(str(x) for x in top_scope) if top_scope else "all"
        h0_metric = ab_primary_metric or "primary_metric"
        h0_status_quo_val = ab_v2_primary.get("control") if isinstance(ab_v2_primary, dict) else None
        if h0_status_quo_val is None:
            h0_status_quo_val = ab_summary.get("primary_metric_control")
        h0_status_quo_disp = _fmt_cell(h0_status_quo_val, h0_metric) if h0_status_quo_val is not None else "—"
        unequal_groups = False
        try:
            unequal_groups = int(float(ab_summary.get("n_orders_control") or 0)) != int(float(ab_summary.get("n_orders_treatment") or 0))
        except Exception:
            unequal_groups = False
        p_value_secondary = None
        p_value_secondary_label = "—"
        try:
            from scipy import stats as _sp_stats  # type: ignore
            arms_payload = (ab or {}).get("arms", {}) if isinstance(ab, dict) else {}
            c_arm = arms_payload.get("control", {}) if isinstance(arms_payload.get("control"), dict) else {}
            t_arm = arms_payload.get("treatment", {}) if isinstance(arms_payload.get("treatment"), dict) else {}
            n1 = int(float(c_arm.get("n_orders", 0) or 0))
            n2 = int(float(t_arm.get("n_orders", 0) or 0))
            if n1 > 1 and n2 > 1:
                pooled = _sp_stats.ttest_ind_from_stats(
                    mean1=float(c_arm.get("mean_aov", 0.0) or 0.0),
                    std1=math.sqrt(max(0.0, float(c_arm.get("var_aov", 0.0) or 0.0))),
                    nobs1=n1,
                    mean2=float(t_arm.get("mean_aov", 0.0) or 0.0),
                    std2=math.sqrt(max(0.0, float(t_arm.get("var_aov", 0.0) or 0.0))),
                    nobs2=n2,
                    equal_var=True,
                )
                p_value_secondary = float(getattr(pooled, "pvalue", None))
                p_value_secondary_label = "pooled_t_test (diagnostic)"
        except Exception:
            p_value_secondary = None
        describe_like_rows: list[dict[str, Any]] = []
        for arm_name in ("control", "treatment"):
            arm_payload = ((ab or {}).get("arms", {}) or {}).get(arm_name, {}) if isinstance(ab, dict) else {}
            if not isinstance(arm_payload, dict):
                continue
            var_aov = _to_float(arm_payload.get("var_aov"))
            describe_like_rows.append(
                {
                    "arm": arm_name,
                    "n_orders": arm_payload.get("n_orders"),
                    "mean_aov": arm_payload.get("mean_aov"),
                    "std_aov": (math.sqrt(var_aov) if isinstance(var_aov, (int, float)) and var_aov >= 0 else None),
                    "var_aov": var_aov,
                    "gmv": arm_payload.get("gmv"),
                    "gp": arm_payload.get("gp"),
                    "requested_units": arm_payload.get("requested_units"),
                    "fulfilled_units": arm_payload.get("fulfilled_units"),
                }
            )
        method_map = {
            "aov": "Welch t-test",
            "gmv": "Welch t-test",
            "gp_margin": "Delta Method / Bootstrap",
            "fill_rate_units": "Delta Method / Bootstrap",
            "oos_lost_gmv_rate": "Delta Method / Bootstrap",
            "new_buyers_7d": "Bootstrap (count metric)",
            "writeoff_units": "Bootstrap (count metric)",
        }
        ab_v2_sampling = (ab_v2 or {}).get("sampling", {}) if isinstance((ab_v2 or {}).get("sampling"), dict) else {}
        sample_actual = (ab_v2_sampling.get("sample_size_actual", {}) if isinstance(ab_v2_sampling.get("sample_size_actual"), dict) else {})
        sample_req = (ab_v2_sampling.get("sample_size_required", {}) if isinstance(ab_v2_sampling.get("sample_size_required"), dict) else {})
        top_blockers: list[str] = []
        seen_blockers: set[str] = set()
        for x in [*blocked_by, *reason_lines]:
            s = str(x).strip()
            if not s:
                continue
            k = s.lower()
            if k in seen_blockers:
                continue
            seen_blockers.add(k)
            top_blockers.append(s)
            if len(top_blockers) >= 3:
                break
        ordered_changes: list[str] = []
        if measurement_state != "OBSERVABLE" or ab_status_upper in blocked_ab_statuses:
            ordered_changes.append("1) Fix measurement/assignment path so AB is observable (valid assignment log + join path + aligned primary metric).")
        else:
            ordered_changes.append("1) Measurement is observable; keep assignment/join path stable.")
        if guardrail_breach:
            ordered_changes.append("2) Fix guardrail breach first (fill_rate_units / gmv / gp_margin / oos_lost_gmv_rate) before any rollout.")
        else:
            ordered_changes.append("2) Keep guardrails within bounds (fill_rate, GMV, margin, OOS).")
        ordered_changes.append("3) Clear governance/interference blockers and keep grounded narrative review complete.")

        def _goal_status_label(goal_id: str) -> str:
            if goal_id == ab_primary_goal:
                return "PRIMARY"
            if goal_id in {"goal2", "goal3"}:
                return "SECONDARY"
            return "MONITORED"

        def _goal_method(metric_name: str) -> str:
            return method_map.get(metric_name, "Descriptive / metric-specific method")

        def _goal_rows_md(goal_id: str) -> list[str]:
            g = goal_blocks_json.get(goal_id, {}) if isinstance(goal_blocks_json, dict) else {}
            comp = g.get("comparison_row", {}) if isinstance(g.get("comparison_row"), dict) else {}
            observed_rows = g.get("observed_metrics", []) if isinstance(g.get("observed_metrics"), list) else []
            observed_dict_rows = [x for x in observed_rows if isinstance(x, dict)]
            metric_name = str(g.get("primary_metric", comp.get("metric", "missing")))
            status_label = _goal_status_label(goal_id)
            stats_allowed = not hide_ab_numbers and (goal_id == ab_primary_goal)
            p_disp = _fmt_p_value(comp.get("p_value")) if stats_allowed and comp.get("p_value") is not None else "—"
            ci_disp = _fmt_ci_pct(comp.get("ci95")) if stats_allowed else "—"
            alpha_disp = _fmt_number(comp.get("alpha"), 2) if stats_allowed else "—"
            test_method = _goal_method(metric_name) if stats_allowed else "—"
            decision_disp = str(comp.get("decision", "INVALID"))
            compact_rows: list[dict[str, Any]] = []
            seen_metrics: set[str] = set()
            for role in ("primary", "supporting", "guardrail"):
                for obs in observed_dict_rows:
                    metric = str(obs.get("metric", "")).strip()
                    if not metric or metric in seen_metrics:
                        continue
                    if str(obs.get("role", "observed")).strip() != role:
                        continue
                    compact_rows.append(obs)
                    seen_metrics.add(metric)
            for metric in ("orders_cnt", "gmv", "gp", "aov", "writeoff_units", "new_buyers_7d"):
                if metric in seen_metrics:
                    continue
                for obs in observed_dict_rows:
                    if str(obs.get("metric", "")).strip() != metric:
                        continue
                    compact_rows.append(obs)
                    seen_metrics.add(metric)
                    break
            lines = [
                f"## {goal_id.upper()} Block",
                f"- Status: `{status_label}`",
                f"- Metric: `{metric_name}`",
                f"- Plan (control) value: `{_fmt_cell(comp.get('plan'), metric_name)}`",
                f"- Fact (treatment) value: `{_fmt_cell(comp.get('treatment'), metric_name)}`",
                f"- Delta (abs + pct): `{_fmt_cell(comp.get('abs_delta'), metric_name)}` / `{_fmt_uplift_pct(comp.get('rel_delta_pct')) if comp.get('rel_delta_pct') is not None else '—'}`",
                "- Statistics:",
                f"  - test_method: `{test_method}`",
                f"  - alpha: `{alpha_disp}`",
                f"  - p_value: `{p_disp}`",
                f"  - CI_95: `{ci_disp}`",
                f"  - decision: `{decision_disp if stats_allowed else 'INVALID' if hide_ab_numbers else decision_disp}`",
                "- Guardrails table (always shown):",
                f"  - fill_rate_units (floor 90.00%): `{_fmt_metric_value(metrics, 'fill_rate_units')}`",
                f"  - gmv (floor): `{_fmt_metric_value(metrics, 'gmv')}`",
                f"  - gp_margin (floor 0.00%): `{_fmt_metric_value(metrics, 'gp_margin')}`",
                f"  - oos_lost_gmv_rate (ceiling 10.00%): `{_fmt_metric_value(metrics, 'oos_lost_gmv_rate')}`",
                "- Observed metrics in contour (compact view):",
                "| metric | role | observed |",
                "|---|---|---:|",
            ]
            for obs in compact_rows:
                lines.append(
                    f"| {obs.get('metric', 'missing')} | {obs.get('role', 'observed')} | {obs.get('display_value', 'missing')} |"
                )
            lines.append(f"- Full observed metric list: `reports/L1_ops/{run_id}/DECISION_CARD_V2.md` and `reports/L1_ops/{run_id}/AB_STAT_REPORT.md`.")
            return lines

        decision_card = [
            f"# Decision Card — {run_id}",
            "",
            "## A) Executive Header",
            f"- run_id: `{run_id}`",
            f"- decision: `{final_decision_v2}`",
            f"- evaluator_decision: `{evaluator_decision}`",
            f"- commander_decision: `{commander_decision}`",
            f"- ab_status: `{ab_status_upper}`",
            f"- measurement_state: `{measurement_state}`",
        ]
        if fatal_reasons_v2 or hide_ab_numbers:
            decision_card.extend(
                [
                    "",
                    "### ❌ FATAL",
                    f"- reasons: `{fatal_reasons_v2 or [ab_status_upper.lower()]}`",
                    (
                        "- AB uplift/CI/p-value hidden by policy (unobservable measurement)."
                        if hide_ab_numbers
                        else "- AB numbers below are diagnostic-only and MUST NOT be used for causal decision due to invalid methods."
                    ),
                    f"- measurement_fix_plan: `data/agent_reports/{run_id}_doctor_variance.json#/measurement_fix_plan`",
                ]
            )
        decision_card.extend(
            [
                "",
                "## B) Contour Context",
                f"- current_ab_goal: `{ab_primary_goal}`",
                f"- current_ab_primary_metric: `{ab_primary_metric or 'missing'}`",
                f"- current_ab_contract_metric: `{current_contract_metric or 'missing'}` (source=`{current_contract_source}`)",
                f"- current_ab_contract_alignment: `{current_alignment_status}`",
                f"- action_summary: `{top_action_summary}`",
                f"- mechanism: `{top_mechanism or 'missing'}`",
                f"- next_experiment_action_summary: `{top_action_summary}`",
                f"- next_experiment_mechanism: `{top_mechanism or 'missing'}`",
                f"- next_experiment_goal: `{hypothesis_target_goal}`",
                f"- next_experiment_target_metric: `{next_goal_metric or 'missing'}`",
                f"- next_experiment_expected_impact_range: `{expected_impact}`",
                f"- next_vs_current_ab_status: `{next_vs_current_status}`",
                "- note: current AB contour and next experiment contour may differ; this is expected when portfolio proposes the next step while current AB analyzes an already running metric.",
                "",
                "## B2) Launch Hypothesis (human)",
                f"- hypothesis: `{hypothesis_text}`",
                f"- expected_direction_primary_goal: `{'DOWN' if hypothesis_target_goal == 'goal1' else ('UP' if hypothesis_target_goal in {'goal2', 'goal3'} else 'TO_BE_DEFINED')}`",
                "- expected_direction_availability_guardrails: `NO WORSE than thresholds`",
                "- expected_direction_business_guardrails: `NO WORSE than thresholds`",
                "- practical_success_criteria (set before reading results):",
                (
                    "- ExpiryWasteRate improvement: `>= X pp` OR ExpiryWriteoff savings: `>= $Y per store-week`"
                    if hypothesis_target_goal == "goal1"
                    else f"- Improvement threshold for `{next_goal_metric or 'target_metric'}` must be pre-declared in experiment contract."
                ),
                "- expected_guardrail_bounds:",
                f"  - fill_rate_units floor: `90.00%`",
                f"  - gmv floor: `{_fmt_metric_value(metrics, 'gmv') if expected_guardrail_bounds['gmv_floor'] is None else _fmt_money(expected_guardrail_bounds['gmv_floor'])}`",
                f"  - gp_margin floor: `0.00%`",
                f"  - oos_lost_gmv_rate ceiling: `10.00%`",
                f"- H0 (null hypothesis): `no effect on {h0_metric}` (status quo = `{h0_status_quo_disp}`)",
                f"- Ha (alternative hypothesis): `effect on {h0_metric}` (value != `{h0_status_quo_disp}`)",
                f"- p-value (primary): `{_fmt_p_value(ab_p_source) if (not hide_ab_numbers and ab_p_source is not None) else '—'}`",
                f"- CI_95 (primary uplift): `{_fmt_ci_pct(ab_ci_source) if not hide_ab_numbers else '—'}`",
                f"- uplift (primary): `{_fmt_uplift_pct(ab_uplift_source) if (not hide_ab_numbers and ab_uplift_source is not None) else '—'}`",
                f"- group sizes: orders control=`{_fmt_int(ab_summary.get('n_orders_control'))}`, treatment=`{_fmt_int(ab_summary.get('n_orders_treatment'))}`; units control=`{_fmt_int(ab_summary.get('n_units_control'))}`, treatment=`{_fmt_int(ab_summary.get('n_units_treatment'))}`",
                f"- p-value (unequal groups diagnostic): `{_fmt_p_value(p_value_secondary) if (unequal_groups and not hide_ab_numbers and p_value_secondary is not None) else '—'}` (`{p_value_secondary_label if unequal_groups else 'not needed (equal sizes)'}`)",
                f"- test days + group characteristics: `days={(snapshot.get('run_config') or {}).get('horizon_days', 14) if isinstance(snapshot.get('run_config'), dict) else 14}`, unit=`{(snapshot.get('run_config') or {}).get('experiment_unit', 'unknown') if isinstance(snapshot.get('run_config'), dict) else 'unknown'}`, tested_scope=`{top_scope_disp}`",
                f"- observed effect (descriptive): control=`{_fmt_cell(ab_summary.get('primary_metric_control'), h0_metric)}`, treatment=`{_fmt_cell(ab_summary.get('primary_metric_treatment'), h0_metric)}`, delta_abs=`{_fmt_cell(ab_summary.get('primary_metric_delta_abs'), h0_metric)}`, delta_pct=`{_fmt_uplift_pct(ab_uplift_source) if (not hide_ab_numbers and ab_uplift_source is not None) else '—'}`",
                "- Before/After table (describe-like from stored aggregates; raw row-level `.describe()` is unavailable in artifact):",
                "",
                "| arm | n_orders | mean_aov | std_aov | var_aov | gmv | gp | requested_units | fulfilled_units |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
            "",
            "## C) Goal Blocks",
            f"Primary goal in current AB contour: `{ab_primary_goal}`. Other goals are tradeoff monitoring blocks.",
            "",
            ]
        )
        for row in describe_like_rows:
            decision_card.append(
                f"| {row['arm']} | {_fmt_int(row['n_orders'])} | {_fmt_money(row['mean_aov'])} | {_fmt_number(row['std_aov'],2)} | {_fmt_number(row['var_aov'],2)} | {_fmt_money(row['gmv'])} | {_fmt_money(row['gp'])} | {_fmt_int(row['requested_units'])} | {_fmt_int(row['fulfilled_units'])} |"
            )
        decision_card.append("- Note: For exact `DataFrame.describe()` and additional scipy tests on raw distributions, persist row-level AB samples (currently only arm aggregates are stored).")
        decision_card.append("")
        for gid in ("goal1", "goal2", "goal3"):
            decision_card.extend(_goal_rows_md(gid))
            decision_card.append("")
        srm_status = str(ab_v2_sampling.get("srm_status") or ab_summary.get("srm_status") or "missing").upper()
        ab_status_interpretable = ab_status_upper in {"OK", "UNDERPOWERED", "INCONCLUSIVE"}
        stats_available = (not hide_ab_numbers) and (
            (ab_p_source is not None) or (isinstance(ab_ci_source, (list, tuple)) and len(ab_ci_source) == 2)
        )
        contract_complete = bool(ab_design_contract.get("is_complete"))
        check_rows: list[tuple[str, str, str, str]] = [
            (
                "Current AB contract alignment",
                "AB metric must match the current AB contract metric to avoid wrong causal interpretation.",
                (
                    "PASS"
                    if alignment_status == "PASS_CURRENT_AB"
                    else ("FAIL" if alignment_status == "FAIL_CURRENT_AB" else "WARN")
                ),
                f"contract_metric={current_contract_metric or 'missing'} ({current_contract_source}); ab_metric={ab_primary_metric or 'missing'}; status={alignment_status}",
            ),
            (
                "Measurement observability",
                "Without observable assignment/join path, uplift cannot be trusted.",
                "PASS" if measurement_state.upper() == "OBSERVABLE" else "FAIL",
                f"measurement_state={measurement_state}; ab_status={ab_status_upper}",
            ),
            (
                "AB status interpretability",
                "Decisioning requires interpretable AB status (OK/UNDERPOWERED/INCONCLUSIVE).",
                "PASS" if ab_status_interpretable else "FAIL",
                f"ab_status={ab_status_upper}",
            ),
            (
                "SRM split sanity",
                "SRM checks randomization health; severe mismatch invalidates inference.",
                ("PASS" if srm_status == "PASS" else ("WARN" if srm_status in {"MISSING", "UNKNOWN", ""} else "FAIL")),
                f"srm_status={srm_status}",
            ),
            (
                "Guardrails",
                "Positive primary effect is rejected if guardrails are breached.",
                "PASS" if not guardrail_breach else "FAIL",
                (
                    f"fill_rate_units={_fmt_metric_value(metrics, 'fill_rate_units')}, "
                    f"gp_margin={_fmt_metric_value(metrics, 'gp_margin')}, "
                    f"oos_lost_gmv_rate={_fmt_metric_value(metrics, 'oos_lost_gmv_rate')}"
                ),
            ),
            (
                "Statistical evidence availability",
                "Need p-value and/or CI to interpret effect direction and uncertainty.",
                "PASS" if stats_available else "WARN",
                f"p_value={_fmt_p_value(ab_p_source) if (not hide_ab_numbers and ab_p_source is not None) else '—'}; CI95={_fmt_ci_pct(ab_ci_source) if not hide_ab_numbers else '—'}",
            ),
            (
                "Next contour vs current AB",
                "Next experiment proposal may differ from current AB; this is planning context, not AB method failure.",
                ("INFO" if next_vs_current_status == "DIFFERENT" else ("PASS" if next_vs_current_status == "MATCH" else "WARN")),
                f"next_goal={hypothesis_target_goal}; current_ab_goal={ab_primary_goal}; status={next_vs_current_status}",
            ),
            (
                "Design contract completeness",
                "Pre/test/wash-in/attribution fields are required for methodology traceability.",
                "PASS" if contract_complete else "WARN",
                f"is_complete={contract_complete}; coverage={ab_design_contract.get('field_coverage_ratio')}; gaps={ab_design_contract.get('design_gap_codes')}",
            ),
        ]
        decision_card.extend(
            [
                "## D) Methodology",
                f"- experiment_unit: `{(snapshot.get('run_config') or {}).get('experiment_unit', 'unknown') if isinstance(snapshot.get('run_config'), dict) else 'unknown'}`",
                "- assignment: `deterministic hash + salt`",
                f"- window_days (should be 14): `{(snapshot.get('run_config') or {}).get('horizon_days', 14) if isinstance(snapshot.get('run_config'), dict) else 14}`",
                f"- SRM status: `{ab_v2_sampling.get('srm_status') or ab_summary.get('srm_status') or 'missing'}`",
                f"- sample sizes per arm: orders control=`{sample_actual.get('orders_control', ab_summary.get('n_orders_control'))}`, treatment=`{sample_actual.get('orders_treatment', ab_summary.get('n_orders_treatment'))}`; units control=`{sample_actual.get('units_control', ab_summary.get('n_units_control'))}`, treatment=`{sample_actual.get('units_treatment', ab_summary.get('n_units_treatment'))}`",
                f"- underpowered flag + MDE: `{ab_v2_sampling.get('underpowered', 'missing')}` / `MDE={first_exp.get('mde', 'missing') if isinstance(first_exp, dict) else 'missing'}`",
                f"- design_contract_source: `{ab_design_contract.get('contract_source')}`",
                f"- design_contract_complete: `{ab_design_contract.get('is_complete')}`",
                f"- design_field_coverage_ratio: `{ab_design_contract.get('field_coverage_ratio')}`",
                f"- required_design_fields: `{ab_design_contract.get('required_design_fields')}`",
                f"- design_gap_codes: `{ab_design_contract.get('design_gap_codes')}`",
                f"- pre_period_weeks/test_period_weeks: `{ab_design_contract.get('pre_period_weeks')}` / `{ab_design_contract.get('test_period_weeks')}`",
                f"- wash_in_days: `{ab_design_contract.get('wash_in_days')}`",
                f"- attribution_window_rule: `{ab_design_contract.get('attribution_window_rule')}`",
                f"- randomization_unit_cfg/analysis_unit_realized: `{ab_design_contract.get('randomization_unit_cfg')}` / `{ab_design_contract.get('analysis_unit_realized')}`",
                f"- metric_semantics: `{ab_design_contract.get('metric_semantics')}`",
                "",
                "## D2) Check Matrix (what/why/result)",
                "| Check | Why it is checked | Result | Evidence |",
                "|---|---|---|---|",
            ]
        )
        for check_name, why_checked, result_label, evidence in check_rows:
            decision_card.append(
                f"| {check_name} | {why_checked} | {result_label} | {evidence} |"
            )
        if fatal_reasons_v2 or ab_status_upper == "INVALID_METHODS":
            decision_card.append(f"- INVALID_METHODS: `{(ab_v2 or {}).get('reason', 'reason_missing') if isinstance(ab_v2, dict) else 'reason_missing'}`")
        decision_card.extend(
            [
                "",
                "## E) Decision Why Tree",
                "- Top 3 blockers (deduped):",
            ]
        )
        if top_blockers:
            decision_card.extend([f"  - {x}" for x in top_blockers])
        else:
            decision_card.append("  - none")
        decision_card.append("- What would change decision to GO:")
        decision_card.extend([f"  - {x}" for x in ordered_changes])
        if chart_notes:
            decision_card.extend(["", "## Notes"])
            decision_card.extend([f"- {x}" for x in chart_notes])
        if report_warnings:
            decision_card.extend(["", "## Report warnings"])
            decision_card.extend([f"- {x}" for x in report_warnings])
        received_cogs_for_report = _metric(metrics, "received_cogs")
        if received_cogs_for_report is None:
            received_cogs_for_report = _to_float(goal1_summary.get("received_cogs"))
        sold_cogs_for_report = _metric(metrics, "sold_cogs")
        if sold_cogs_for_report is None:
            sold_cogs_for_report = _to_float(goal1_summary.get("sold_cogs"))
        expiry_writeoff_cogs_for_report = _metric(metrics, "expiry_writeoff_cogs")
        if expiry_writeoff_cogs_for_report is None:
            expiry_writeoff_cogs_for_report = _to_float(goal1_summary.get("expiry_writeoff_cogs"))
        sell_through_ratio = (
            sold_cogs_for_report / received_cogs_for_report
            if sold_cogs_for_report is not None and received_cogs_for_report not in {None, 0.0}
            else None
        )
        decision_card.extend(
            [
                "",
                "## 3.1 Sanity checks (invariants) — required before reading outcomes",
                f"- baseline_expiry_waste_rate_pre_period: `{(_fmt_metric_value((baseline_snapshot or {}).get('metrics', {}) if isinstance(baseline_snapshot, dict) else {}, 'writeoff_rate_vs_requested_units') if isinstance(baseline_snapshot, dict) else 'n/a')}`",
                f"- current_expiry_waste_rate: `{_fmt_metric_value(metrics, 'writeoff_rate_vs_requested_units')}`",
                f"- promo/supplier parity proxy: `rows={goal1_rows_cnt}, stores={goal1_store_cnt}, categories={goal1_category_cnt}`",
                f"- expiry_date_coverage: `{_fmt_pct(expiry_cov) if expiry_cov is not None else 'n/a'}` (threshold `>=99.00%`)",
                "",
                "## 4.4 Required segments (pre-registered; avoid p-hacking)",
                f"- category split dairy/meat: `{'PASS' if goal1_category_cnt >= 2 else ('WARN' if goal1_rows_cnt > 0 else 'FAIL')}` (categories={goal1_category_cnt})",
                f"- per-store split: `{'PASS' if goal1_store_cnt >= 2 else ('WARN' if goal1_rows_cnt > 0 else 'FAIL')}` (stores={goal1_store_cnt})",
                f"- sku-tier split top20 vs tail: `{'WARN' if goal1_rows_cnt > 0 else 'FAIL'}` (requires sku-level fact; category-level proxy loaded)",
                "",
                "## 5.3 Decomposition (required interpretation block)",
                f"- received_cogs: `{_fmt_money(received_cogs_for_report) if received_cogs_for_report is not None else 'n/a'}`",
                f"- sold_cogs: `{_fmt_money(sold_cogs_for_report) if sold_cogs_for_report is not None else 'n/a'}`",
                f"- sold_over_received_ratio: `{_fmt_pct(sell_through_ratio) if sell_through_ratio is not None else 'n/a'}`",
                f"- expiry_writeoff_cogs: `{_fmt_money(expiry_writeoff_cogs_for_report) if expiry_writeoff_cogs_for_report is not None else 'n/a'}`",
                f"- availability_fill/oos: `{_fmt_metric_value(metrics, 'fill_rate_units')}` / `{_fmt_metric_value(metrics, 'oos_lost_gmv_rate')}`",
                "",
                "## 6.4 Power / MDE planning (required, even if approximate)",
                f"- duration_days: `{(snapshot.get('run_config') or {}).get('horizon_days', 14) if isinstance(snapshot.get('run_config'), dict) else 14}`",
                f"- mde_target_contract: `{ab_design_contract.get('mde_target')}`",
                f"- sample_size_actual_orders: `control={_fmt_int(ab_summary.get('n_orders_control'))}, treatment={_fmt_int(ab_summary.get('n_orders_treatment'))}`",
                "",
                "## 7.5 Rollout ramp & post-launch monitoring (standard)",
                "- ramp_plan: `10% -> 25% -> 50% -> 100%`",
                "- kill_switches: `fill/oos/margin breaches`",
                "- post_launch_recheck: `2 weeks after full rollout`",
                "",
                "## 8.3 Effect stability over time (required in every experiment report)",
                "- per-day/per-block deltas: `missing in current aggregate artifact`",
                "- cumulative effect trend: `missing in current aggregate artifact`",
                "- action: `export time-sliced AB dataset for stability checks`",
            ]
        )
        _safe_write(out_dir / "decision_card.md", "\n".join(decision_card) + "\n")

        # Canonical-style Decision Card (based on user-provided standard template).
        guardrail_fill = _fmt_metric_value(metrics, "fill_rate_units")
        guardrail_oos = _fmt_metric_value(metrics, "oos_lost_gmv_rate")
        guardrail_gmv = _fmt_metric_value(metrics, "gmv")
        guardrail_margin = _fmt_metric_value(metrics, "gp_margin")
        primary_control = _fmt_cell(ab_summary.get("primary_metric_control"), h0_metric)
        primary_treatment = _fmt_cell(ab_summary.get("primary_metric_treatment"), h0_metric)
        primary_abs = _fmt_cell(ab_summary.get("primary_metric_delta_abs"), h0_metric)
        primary_rel = _fmt_uplift_pct(ab_uplift_source) if (not hide_ab_numbers and ab_uplift_source is not None) else "—"
        ci95_disp = _fmt_ci_pct(ab_ci_source) if not hide_ab_numbers else "—"
        p_disp = _fmt_p_value(ab_p_source) if (not hide_ab_numbers and ab_p_source is not None) else "—"
        gmv_floor_disp = _fmt_metric_value(metrics, "gmv") if expected_guardrail_bounds["gmv_floor"] is None else _fmt_money(expected_guardrail_bounds["gmv_floor"])
        stop_rollout = final_decision_v2 not in {"RUN_AB", "ROLLOUT_CANDIDATE"}
        tldr_1 = (
            f"1) **Primary ({ab_primary_metric.upper() if ab_primary_metric else 'primary'})**: эффект не подтвержден (p={p_disp}; CI={ci95_disp})."
            if p_disp != "—" or ci95_disp != "—"
            else "1) **Primary**: недостаточно статистических данных для уверенного вывода."
        )
        tldr_2 = (
            "2) **Guardrails breached (availability stress)** в тестовом окне: fill_rate и OOS proxy хуже заданных порогов."
            if guardrail_breach
            else "2) **Guardrails**: критичных нарушений по availability в текущем окне не зафиксировано."
        )
        tldr_3 = (
            "3) **Goal/metric mismatch контуров**: действие по смыслу про goal1, но текущий AB измеряет goal2."
            if next_vs_current_status == "DIFFERENT"
            else "3) **Contours aligned**: текущий AB и следующий эксперимент нацелены на одну цель."
        )
        window_start_disp = str((snapshot.get("run_config") or {}).get("start_date") if isinstance(snapshot.get("run_config"), dict) else "") or "MISSING (must be filled)"
        window_end_disp = str((snapshot.get("run_config") or {}).get("end_date") if isinstance(snapshot.get("run_config"), dict) else "") or "MISSING (must be filled)"

        decision_card_standard = [
            f"## Decision Card — {run_id} (Revised, copy-ready)",
            "",
            "## A) Executive Summary",
            f"- run_id: `{run_id}`",
            f"- experiment_id: `{experiment_id}`",
            f"- current_ab_goal: `{ab_primary_goal}`",
            f"- current_ab_primary_metric: `{ab_primary_metric.upper() if ab_primary_metric else 'missing'}`",
            f"- decision: **{'STOP_ROLLOUT' if stop_rollout else 'ROLL_OUT_CANDIDATE'}**",
            f"- ab_status: **{ab_status_upper}**",
            f"- measurement_state: `{measurement_state}`",
            "",
            "### TL;DR (why)",
            tldr_1,
            tldr_2,
            tldr_3,
            "",
            "---",
            "",
            "## B) What was tested (Context)",
            f"- action_summary: `{top_action_summary}`",
            f"- mechanism: `{top_mechanism or 'missing'}`",
            "",
            "### Note on alignment",
            f"- next_experiment_goal: `{hypothesis_target_goal}`",
            f"- next_experiment_metric: `{next_goal_metric or 'missing'}`",
            f"- current_ab_metric: `{ab_primary_metric.upper() if ab_primary_metric else 'missing'}`",
            f"- next_vs_current_ab_status: `{next_vs_current_status}`",
            "",
            "## B2) Launch Hypothesis (human)",
            f"- hypothesis: `{hypothesis_text}`",
            f"- expected_direction_primary_goal: `{'DOWN' if hypothesis_target_goal == 'goal1' else ('UP' if hypothesis_target_goal in {'goal2', 'goal3'} else 'TO_BE_DEFINED')}`",
            "- expected_direction_availability_guardrails: `NO WORSE than thresholds`",
            "- expected_direction_business_guardrails: `NO WORSE than thresholds`",
            "- practical_success_criteria (set before reading results):",
            (
                "- ExpiryWasteRate improvement: `>= X pp` OR ExpiryWriteoff savings `>= $Y per store-week`"
                if hypothesis_target_goal == "goal1"
                else f"- Improvement threshold for `{next_goal_metric or 'target_metric'}` must be pre-declared in experiment contract."
            ),
            "",
            "---",
            "",
            "## C) Metric Semantics Lock (must be consistent)",
            "- Currency: **USD**",
            "- `net_price = price - discounts`",
            "- `GMV (net) = Σ(net_price)` within test window",
            "- `AOV = GMV / orders` within test window",
            "- `GrossMargin$ = GMV - Σ(sold_cogs)` (if sold_cogs available)",
            "- Writeoffs/Waste for goal1 are COGS-based (not revenue-based)",
            "",
            "---",
            "",
            "## D) AB Design Contract (as executed)",
            f"- randomization_unit_cfg: `{ab_design_contract.get('randomization_unit_cfg')}`",
            "- assignment_method: `deterministic hash + salt + unit_id`",
            f"- test_side: `{ab_design_contract.get('test_side')}`",
            f"- alpha: `{alpha_val}`",
            f"- window_days: `{(snapshot.get('run_config') or {}).get('horizon_days', 14) if isinstance(snapshot.get('run_config'), dict) else 14}`",
            f"- pre_period_weeks: `{ab_design_contract.get('pre_period_weeks')}`",
            f"- test_period_weeks: `{ab_design_contract.get('test_period_weeks')}`",
            f"- wash_in_days: `{ab_design_contract.get('wash_in_days')}`",
            f"- attribution_window_rule: `{ab_design_contract.get('attribution_window_rule')}`",
            f"- window_start: `{window_start_disp}`",
            f"- window_end: `{window_end_disp}`",
            f"- multiple_testing_policy: `{multiple_testing_policy}`",
            f"- SRM_check: `{ab_v2_sampling.get('srm_status') or ab_summary.get('srm_status') or 'missing'}`",
            "",
            "---",
            "",
            "## E) Realized Group Sizes (must be shown)",
            "| Arm | n_customers | n_orders |",
            "|---|---:|---:|",
            f"| Control | {_fmt_int(ab_summary.get('n_units_control'))} | {_fmt_int(ab_summary.get('n_orders_control'))} |",
            f"| Treatment | {_fmt_int(ab_summary.get('n_units_treatment'))} | {_fmt_int(ab_summary.get('n_orders_treatment'))} |",
            "",
            "---",
            "",
            f"## F) Primary Result — {ab_primary_goal.upper()} ({ab_primary_metric.upper() if ab_primary_metric else 'PRIMARY'})",
            "### Result (as reported)",
            "| Metric | Control | Treatment | Δ abs | Δ rel | p-value | CI95 (rel) | Decision |",
            "|---|---:|---:|---:|---:|---:|---|---|",
            f"| {ab_primary_metric.upper() if ab_primary_metric else 'PRIMARY'} | {primary_control} | {primary_treatment} | **{primary_abs}** | **{primary_rel}** | {p_disp} | {ci95_disp} | {stat_decision_text} |",
            "",
            "---",
            "",
            "## G) Guardrails (health checks)",
            "### Configured bounds",
            "- fill_rate_units floor: `90.00%`",
            "- oos_lost_gmv_rate ceiling: `10.00%`",
            f"- gmv floor: `{gmv_floor_disp}`",
            "- gp_margin floor: `0.00%`",
            "",
            "### Observed (contour-level; not split by arm)",
            f"- fill_rate_units: `{guardrail_fill}`",
            f"- oos_lost_gmv_rate: `{guardrail_oos}`",
            f"- gmv: `{guardrail_gmv}`",
            f"- gp_margin: `{guardrail_margin}`",
            "",
            "---",
            "",
            "## H) Conclusions (what we can / can’t claim)",
            "### We CAN claim",
            f"- For `{ab_primary_metric}` there is no reliable positive effect in this run (`{ab_status_upper}`).",
            "",
            "### We CANNOT claim",
            "- Cannot claim Goal1 expiry/writeoff improvement unless Goal1 is the primary metric with valid design.",
            "",
            "---",
            "",
            "## I) Decision",
            f"**{'STOP_ROLLOUT' if stop_rollout else 'ROLL_OUT_CANDIDATE'}**",
            "",
            "---",
            "",
            "## J) Next Steps (recommended)",
            "1) Fill missing metadata and lock semantics before next readout.",
            "2) Keep current AB inference unit-consistent with randomization unit.",
            "3) For Goal1 (expiry waste), run store-time design as canonical standard requires.",
            "4) Report guardrails by arms (Control/Treatment) for causal attribution.",
            "",
            "## 3.1 Sanity checks (invariants) — required before reading outcomes",
            f"- baseline_expiry_waste_rate_pre_period: `{(_fmt_metric_value((baseline_snapshot or {}).get('metrics', {}) if isinstance(baseline_snapshot, dict) else {}, 'writeoff_rate_vs_requested_units') if isinstance(baseline_snapshot, dict) else 'n/a')}`",
            f"- current_expiry_waste_rate: `{_fmt_metric_value(metrics, 'writeoff_rate_vs_requested_units')}`",
            f"- promo/supplier parity proxy: `rows={goal1_rows_cnt}, stores={goal1_store_cnt}, categories={goal1_category_cnt}`",
            f"- expiry_date_coverage: `{_fmt_pct(expiry_cov) if expiry_cov is not None else 'n/a'}` (threshold `>=99.00%`)",
            "",
            "## 4.4 Required segments (pre-registered; avoid p-hacking)",
            f"- category_split_dairy_vs_meat: `{'PASS' if goal1_category_cnt >= 2 else ('WARN' if goal1_rows_cnt > 0 else 'FAIL')}` (categories={goal1_category_cnt})",
            f"- per_store_split: `{'PASS' if goal1_store_cnt >= 2 else ('WARN' if goal1_rows_cnt > 0 else 'FAIL')}` (stores={goal1_store_cnt})",
            f"- sku_tier_split_top20_vs_tail: `{'WARN' if goal1_rows_cnt > 0 else 'FAIL'}` (requires sku-level fact; category-level proxy loaded)",
            "",
            "## 5.3 Decomposition (required interpretation block)",
            f"- volume_received_cogs: `{_fmt_money(received_cogs_for_report) if received_cogs_for_report is not None else 'n/a'}`",
            f"- sold_cogs: `{_fmt_money(sold_cogs_for_report) if sold_cogs_for_report is not None else 'n/a'}`",
            f"- sell_through_proxy_sold_over_received: `{_fmt_pct(sell_through_ratio) if sell_through_ratio is not None else 'n/a'}`",
            f"- expiry_writeoff_cogs: `{_fmt_money(expiry_writeoff_cogs_for_report) if expiry_writeoff_cogs_for_report is not None else 'n/a'}`",
            f"- availability_fill_oos: `{_fmt_metric_value(metrics, 'fill_rate_units')}` / `{_fmt_metric_value(metrics, 'oos_lost_gmv_rate')}`",
            "",
            "## 6.4 Power / MDE planning (required, even if approximate)",
            f"- duration_days: `{(snapshot.get('run_config') or {}).get('horizon_days', 14) if isinstance(snapshot.get('run_config'), dict) else 14}`",
            f"- mde_target_contract: `{ab_design_contract.get('mde_target')}`",
            f"- sample_size_actual_orders: `control={_fmt_int(ab_summary.get('n_orders_control'))}, treatment={_fmt_int(ab_summary.get('n_orders_treatment'))}`",
            "",
            "## 7.5 Rollout ramp & post-launch monitoring (standard)",
            "- ramp_plan: `10% -> 25% -> 50% -> 100%`",
            "- kill_switches: `fill/oos/margin breaches`",
            "- post_launch_recheck: `2 weeks after full rollout`",
            "",
            "## 8.3 Effect stability over time (required in every experiment report)",
            "- daily_or_block_delta_series: `missing in current aggregate artifact`",
            "- cumulative_delta_series: `missing in current aggregate artifact`",
            "- action: `export per-day/per-block AB table for stability diagnostics`",
            "",
        ]
        _safe_write(out_dir / DECISION_CANONICAL_OUTPUT, "\n".join(decision_card_standard))

        # Non-fatal Retail MBR build (human-readable ops table).
        mbr_meta: dict[str, Any] = {}
        mbr_cmd = ["python3", "scripts/build_retail_mbr.py", "--run-id", run_id]
        mbr_res = subprocess.run(mbr_cmd, capture_output=True, text=True)
        if mbr_res.returncode != 0:
            report_warnings.append("retail_mbr_builder_failed")
            decision_card.extend(["", "## Report warnings", "- retail_mbr_builder_failed"])
            _safe_write(out_dir / "decision_card.md", "\n".join(decision_card) + "\n")
        mbr_meta_path = out_dir / "mbr_meta.json"
        if mbr_meta_path.exists():
            mbr_meta = _load_json(mbr_meta_path) or {}

        # Non-fatal deterministic AB scientific report build.
        ab_report_cmd = ["python3", "scripts/build_ab_report.py", "--run-id", run_id]
        if isinstance(ab_path, Path):
            exp_guess = ab_path.stem.replace(f"{run_id}_", "").replace("_ab", "")
            if exp_guess:
                ab_report_cmd.extend(["--experiment-id", exp_guess])
        ab_report_res = subprocess.run(ab_report_cmd, capture_output=True, text=True)
        if ab_report_res.returncode != 0:
            report_warnings.append("ab_statistical_report_builder_failed")

        # Conformance report: template structure + core methodology checks.
        goal1_metric_family = {"writeoff_rate_adj", "writeoff_units", "writeoff_cogs", "goal1_writeoff"}
        decision_template_h2 = _extract_h2_headings(_load_text(DECISION_STANDARD_TEMPLATE_PATH))
        decision_output_h2 = _extract_h2_headings(_load_text(out_dir / DECISION_CANONICAL_OUTPUT))
        ab_template_h2 = _extract_h2_headings(_load_text(AB_STANDARD_TEMPLATE_PATH))
        ab_output_h2 = _extract_h2_headings(_load_text(out_dir / AB_CANONICAL_OUTPUT))

        structure_rows: list[tuple[str, str, str]] = []
        if decision_template_h2:
            decision_output_set = {_normalize_heading(x) for x in decision_output_h2}
            for section in decision_template_h2:
                result = "PASS" if _normalize_heading(section) in decision_output_set else "FAIL"
                structure_rows.append(("DecisionCard", section, result))
        else:
            structure_rows.append(("DecisionCard", "template_headings_missing", "WARN"))
        if ab_template_h2:
            ab_output_set = {_normalize_heading(x) for x in ab_output_h2}
            for section in ab_template_h2:
                result = "PASS" if _normalize_heading(section) in ab_output_set else "FAIL"
                structure_rows.append(("ABStatReport", section, result))
        else:
            structure_rows.append(("ABStatReport", "template_headings_missing", "WARN"))
            ab_output_set = set()

        canonical_required_sections = [
            "3.1 Sanity checks (invariants) — required before reading outcomes",
            "4.4 Required segments (pre-registered; avoid p-hacking)",
            "5.3 Decomposition (required interpretation block)",
            "6.4 Power / MDE planning (required, even if approximate)",
            "7.5 Rollout ramp & post-launch monitoring (standard)",
            "8.3 Effect stability over time (required in every experiment report)",
        ]
        canonical_additions_rows: list[tuple[str, str]] = []
        for section in canonical_required_sections:
            canonical_additions_rows.append(
                (
                    section,
                    "PASS" if _normalize_heading(section) in ab_output_set else "FAIL",
                )
            )
        v3_contract_error = ""
        try:
            _ = validate_v3_contract_set()
            v3_contract_ok = True
        except Exception as exc:
            v3_contract_ok = False
            v3_contract_error = str(exc)
        gate_payloads: dict[str, dict[str, Any]] = {}
        for p in list_gate_results(run_id):
            try:
                row = load_gate_result(p)
            except Exception:
                continue
            gate_name = str(row.get("gate_name", "")).strip()
            if gate_name:
                gate_payloads[gate_name] = row
        required_v3_gates = [
            *REQUIRED_GATE_ORDER,
            "context_frame",
            "handoff_contract_guard",
            "anti_goodhart_sot",
            "quality_invariants",
            "reasoning_score_policy",
            "governance_ceiling",
        ]
        missing_v3_gates = [g for g in required_v3_gates if g not in gate_payloads]
        failed_v3_gates = [g for g in required_v3_gates if str((gate_payloads.get(g) or {}).get("status", "")).upper() != "PASS"]
        gate_order_ok = True
        gate_order_reason = "ok"
        prev_gate_ts = ""
        for gate_name in REQUIRED_GATE_ORDER:
            ts = str((gate_payloads.get(gate_name) or {}).get("generated_at", "")).strip()
            if not ts:
                gate_order_ok = False
                gate_order_reason = f"missing_generated_at:{gate_name}"
                break
            if prev_gate_ts and ts < prev_gate_ts:
                gate_order_ok = False
                gate_order_reason = f"order_violation:{gate_name}"
                break
            prev_gate_ts = ts
        governance_ceiling_payload = _load_json(Path(f"data/agent_quality/{run_id}_governance_ceiling.json")) or {}
        gov_status = str(governance_ceiling_payload.get("governance_status", "")).strip().lower()
        gov_required_actions = (
            governance_ceiling_payload.get("required_actions", [])
            if isinstance(governance_ceiling_payload.get("required_actions"), list)
            else []
        )
        gov_required_actions_ok = (gov_status != "missing_review") or bool(gov_required_actions)

        conformance_rows: list[tuple[str, str, str, str]] = [
            (
                "Primary goal is Goal1 expiry waste",
                "PASS" if ab_primary_goal == "goal1" else "FAIL",
                f"current_ab_goal={ab_primary_goal}",
                "Canonical standard v1.1 is Goal1-expiry-first.",
            ),
            (
                "Primary metric is Goal1 waste-family",
                "PASS" if (ab_primary_metric in goal1_metric_family) else "FAIL",
                f"current_ab_primary_metric={ab_primary_metric}",
                "Expected expiry waste metric family for canonical Goal1 runs.",
            ),
            (
                "Randomization unit is store-level for inventory/inbound",
                "PASS" if str(ab_design_contract.get('randomization_unit_cfg', '')).strip().lower() == "store" else "FAIL",
                f"randomization_unit_cfg={ab_design_contract.get('randomization_unit_cfg')}",
                "Canonical requires store-time grain for inbound/inventory changes.",
            ),
            (
                "Design metadata completeness",
                "PASS" if bool(ab_design_contract.get("is_complete")) else "WARN",
                f"is_complete={ab_design_contract.get('is_complete')}; gaps={ab_design_contract.get('design_gap_codes')}",
                "pre/test/wash-in/attribution should be present for auditable methodology.",
            ),
            (
                "Guardrails availability in report",
                "PASS" if all(k in metrics for k in ("fill_rate_units", "oos_lost_gmv_rate", "gp_margin")) else "WARN",
                f"fill_rate={guardrail_fill}; oos={guardrail_oos}; gp_margin={guardrail_margin}",
                "Canonical requires availability + business guardrails.",
            ),
            (
                "Current vs next contour transparency",
                "PASS" if next_vs_current_status in {"MATCH", "DIFFERENT", "UNKNOWN"} else "WARN",
                f"next_vs_current_ab_status={next_vs_current_status}",
                "Difference between current AB and next experiment must be explicit, not hidden.",
            ),
            (
                "Architecture v3 contracts integrity",
                "PASS" if v3_contract_ok else "FAIL",
                f"v3_contract_error={v3_contract_error or 'none'}",
                "All mandatory v3 contracts must be integrity-loaded in runtime.",
            ),
            (
                "Architecture v3 gate-result coverage",
                "PASS" if not missing_v3_gates else "FAIL",
                f"missing_gates={missing_v3_gates}",
                "Every mandatory gate must publish gate_result_v1.",
            ),
            (
                "Architecture v3 gate-result statuses",
                "PASS" if not failed_v3_gates else "FAIL",
                f"failed_gates={failed_v3_gates}",
                "Gate failures are fail-closed and block publication.",
            ),
            (
                "Architecture v3 gate order",
                "PASS" if gate_order_ok else "FAIL",
                f"gate_order_reason={gate_order_reason}",
                "Mandatory order: Doctor -> handoff -> Evaluator -> Commander -> acceptance -> pre_publish.",
            ),
            (
                "Anti-Goodhart single source of truth",
                "PASS" if not anti_goodhart_error else "FAIL",
                f"anti_goodhart_sot_error={anti_goodhart_error or 'none'}",
                "Consumers must use anti_goodhart_verdict_v1 only.",
            ),
            (
                "Governance missing_review required_actions",
                "PASS" if gov_required_actions_ok else "FAIL",
                f"governance_status={gov_status}; required_actions={len(gov_required_actions)}",
                "missing_review must include actionable remediation before publish.",
            ),
        ]
        conformance_md = [
            f"# STANDARD_CONFORMANCE — {run_id}",
            "",
            f"- source_of_truth: `{CANONICAL_STANDARD_PATH}`",
            f"- template_reference_ab: `{AB_STANDARD_TEMPLATE_PATH}`",
            f"- template_reference_decision: `{DECISION_STANDARD_TEMPLATE_PATH}`",
            f"- generated_decision: `reports/L1_ops/{run_id}/{DECISION_CANONICAL_OUTPUT}`",
            f"- generated_ab_stat: `reports/L1_ops/{run_id}/{AB_CANONICAL_OUTPUT}`",
            "",
            "## 1) Template Structure Coverage",
            "| Document | Template Section (H2) | Result |",
            "|---|---|---|",
        ]
        for doc_name, section_name, result in structure_rows:
            conformance_md.append(f"| {doc_name} | {section_name} | {result} |")
        conformance_md.extend(
            [
                "",
                "## 2) Methodology Alignment Checks",
                "| Check | Result | Evidence | Why it matters |",
                "|---|---|---|---|",
            ]
        )
        for check, result, evidence, why in conformance_rows:
            conformance_md.append(f"| {check} | {result} | {evidence} | {why} |")
        conformance_md.extend(
            [
                "",
                "## 3) Canonical v1.1 Additions Coverage",
                "| Required Section | Result |",
                "|---|---|",
            ]
        )
        for section, result in canonical_additions_rows:
            conformance_md.append(f"| {section} | {result} |")
        _safe_write(out_dir / "STANDARD_CONFORMANCE.md", "\n".join(conformance_md) + "\n")

        links_outputs: dict[str, Any] = {
            "decision_card": str(out_dir / "decision_card.md"),
            "decision_card_v2": str(out_dir / "DECISION_CARD_V2.md"),
            "decision_card_canonical": str(out_dir / DECISION_CANONICAL_OUTPUT),
            "decision_card_v2_json": f"data/decision_cards/{run_id}_decision_card_v2.json",
            "goal_scorecard": str(out_dir / "goal_scorecard.md"),
            "agent_scorecard": str(out_dir / "agent_scorecard.md"),
            "agent_effectiveness": str(out_dir / "agent_effectiveness.md"),
            "agent_scoreboard": str(out_dir / "AGENT_SCOREBOARD.md"),
            "agent_value_scorecard": str(out_dir / "AGENT_VALUE_SCORECARD.md"),
            "metrics_table": str(out_dir / "metrics_table.csv"),
            "index": str(out_dir / "index.md"),
            "demo_index": str(out_dir / "DEMO_INDEX.md"),
            "synthetic_bias": str(out_dir / "synthetic_bias.md"),
            "ab_statistical_report": str(out_dir / "AB_STAT_REPORT.md"),
            "ab_statistical_report_canonical": str(out_dir / AB_CANONICAL_OUTPUT),
            "standard_conformance": str(out_dir / "STANDARD_CONFORMANCE.md"),
            "charts": [
                str(charts_dir / "goal1_writeoff.png"),
                str(charts_dir / "goal2_aov.png"),
                str(charts_dir / "goal3_buyers.png"),
                str(charts_dir / "impact_chart.png"),
                str(charts_dir / "impact.png"),
                str(charts_dir / "availability_driver.png"),
            ],
        }
        mbr_md = str(mbr_meta.get("retail_mbr_md", "")).strip()
        mbr_csv = str(mbr_meta.get("mbr_kpi_csv", "")).strip()
        if mbr_md and Path(mbr_md).exists():
            links_outputs["retail_mbr_md"] = mbr_md
        elif (out_dir / "RETAIL_MBR.md").exists():
            links_outputs["retail_mbr_md"] = str(out_dir / "RETAIL_MBR.md")
        if mbr_csv and Path(mbr_csv).exists():
            links_outputs["mbr_kpi_csv"] = mbr_csv
        elif (out_dir / "mbr_kpi.csv").exists():
            links_outputs["mbr_kpi_csv"] = str(out_dir / "mbr_kpi.csv")
        mbr_summary = str(mbr_meta.get("mbr_summary_md", "")).strip()
        if mbr_summary and Path(mbr_summary).exists():
            links_outputs["mbr_summary_md"] = mbr_summary
        elif (out_dir / "MBR_SUMMARY.md").exists():
            links_outputs["mbr_summary_md"] = str(out_dir / "MBR_SUMMARY.md")
        for key, rel in {
            "agent_governance": out_dir / "agent_governance.md",
            "agent_scorecard_v2": out_dir / "AGENT_SCORECARD.md",
            "agent_quality": out_dir / "agent_quality.md",
            "agent_quality_v2_json": Path(f"data/agent_quality/{run_id}_agent_quality_v2.json"),
            "agent_effectiveness_json": Path(f"data/agent_reports/{run_id}_agent_effectiveness.json"),
            "agent_value_eval_json": Path(f"data/agent_eval/{run_id}_agent_value_eval.json"),
            "approvals_registry": Path(f"data/governance/approvals_{run_id}.json"),
            "action_trace": Path(f"data/decision_traces/{run_id}_actions.jsonl"),
            "agent_governance": Path(f"data/agent_governance/{run_id}_agent_approvals.json"),
            "adversarial_suite": Path(f"data/eval/adversarial_suite_{run_id}.json"),
            "synthetic_realism": out_dir / "synthetic_realism.md",
            "causal_explanation": out_dir / "CAUSAL_EXPLANATION.md",
            "causal_explanation_en": out_dir / "CAUSAL_EXPLANATION.en.md",
            "causal_claims_json": out_dir / "causal_claims.json",
            "causal_claims_validation": out_dir / "causal_claims_validation.json",
            "evidence_pack_md": out_dir / "evidence_pack.md",
            "evidence_pack_json": out_dir / "evidence_pack.json",
            "doctor_context": Path(f"data/agent_context/{run_id}_doctor_context.json"),
        }.items():
            if rel.exists():
                links_outputs[key] = str(rel)
        links_outputs["artifact_manifest"] = str(out_dir / "artifact_manifest.json")
        links = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "inputs": {
                "dq_report": str(dq_path),
                "captain": str(captain_path),
                "metrics_snapshot": str(metrics_path),
                "doctor": str(doctor_path),
                "evaluator": str(evaluator_path),
                "commander": str(commander_path),
                "security": str(security_path),
                "ab_report": str(ab_path) if isinstance(ab_path, Path) else None,
                "baseline_snapshot": f"data/metrics_snapshots/{baseline_id}.json" if baseline_id else None,
            },
            "outputs": links_outputs,
            "meta": {
                "plan_source": mbr_meta.get("plan_source_used"),
                "prev_run_id_used": mbr_meta.get("prev_run_id_used"),
            },
            "artifact_meta": {
                "inputs": [
                    _artifact_meta(str(dq_path)),
                    _artifact_meta(str(captain_path)),
                    _artifact_meta(str(metrics_path)),
                    _artifact_meta(str(doctor_path)),
                    _artifact_meta(str(evaluator_path)),
                    _artifact_meta(str(commander_path)),
                    _artifact_meta(str(security_path)),
                    _artifact_meta(str(ab_path) if isinstance(ab_path, Path) else None),
                ],
                "outputs": [
                    _artifact_meta(links_outputs["decision_card"]),
                    _artifact_meta(links_outputs["decision_card_v2"]),
                    _artifact_meta(links_outputs["decision_card_canonical"]),
                    _artifact_meta(links_outputs["decision_card_v2_json"]),
                    _artifact_meta(links_outputs["goal_scorecard"]),
                    _artifact_meta(links_outputs["agent_scorecard"]),
                    _artifact_meta(links_outputs["agent_effectiveness"]),
                    _artifact_meta(links_outputs["agent_scoreboard"]),
                    _artifact_meta(links_outputs["agent_value_scorecard"]),
                    _artifact_meta(links_outputs["artifact_manifest"]),
                    _artifact_meta(links_outputs["metrics_table"]),
                    _artifact_meta(links_outputs["index"]),
                    _artifact_meta(links_outputs["demo_index"]),
                    _artifact_meta(links_outputs["synthetic_bias"]),
                    _artifact_meta(links_outputs["ab_statistical_report_canonical"]),
                    _artifact_meta(links_outputs["standard_conformance"]),
                    _artifact_meta(str(out_dir / "synthetic_realism.md")),
                    _artifact_meta(str(out_dir / "agent_governance.md")),
                    _artifact_meta(str(out_dir / "AGENT_SCORECARD.md")),
                    _artifact_meta(str(out_dir / "agent_quality.md")),
                    _artifact_meta(f"data/agent_quality/{run_id}_agent_quality_v2.json"),
                    _artifact_meta(f"data/agent_reports/{run_id}_agent_effectiveness.json"),
                    _artifact_meta(f"data/governance/approvals_{run_id}.json"),
                    _artifact_meta(str(out_dir / "contract_check.md")),
                    _artifact_meta(f"data/agent_quality/{run_id}_contracts.json"),
                    _artifact_meta(str(out_dir / "RETAIL_MBR.md")),
                    _artifact_meta(str(out_dir / "MBR_SUMMARY.md")),
                    _artifact_meta(str(out_dir / "mbr_kpi.csv")),
                    _artifact_meta(str(out_dir / "CAUSAL_EXPLANATION.md")),
                    _artifact_meta(str(out_dir / "CAUSAL_EXPLANATION.en.md")),
                    _artifact_meta(str(out_dir / "causal_claims.json")),
                    _artifact_meta(str(out_dir / "causal_claims_validation.json")),
                    _artifact_meta(f"data/decision_traces/{run_id}_actions.jsonl"),
                    _artifact_meta(f"data/agent_governance/{run_id}_agent_approvals.json"),
                    _artifact_meta(f"data/eval/adversarial_suite_{run_id}.json"),
                    _artifact_meta(f"data/agent_eval/{run_id}_agent_value_eval.json"),
                    _artifact_meta(str(out_dir / "evidence_pack.md")),
                    _artifact_meta(str(out_dir / "evidence_pack.json")),
                    *[_artifact_meta(c) for c in links_outputs["charts"]],
                ],
            },
        }
        _safe_write_json(out_dir / "links.json", links)
        write_sha256_sidecar(out_dir / "links.json")
        manifest_path = out_dir / "artifact_manifest.json"
        write_json_manifest(
            manifest_path,
            _json_paths_from_links_payload(links, include=[out_dir / "links.json"]),
            run_id=run_id,
        )

        status = "PASS"
        if commander_decision in {"HOLD_NEED_DATA", "HOLD_RISK"}:
            status = "WARN"
        if commander_decision == "STOP":
            status = "FAIL"
        methodology = str(first_exp.get("methodology", "missing") or "missing")
        index_reason = reason_lines[0] if reason_lines else "no explicit reason row"
        index_lines = [
            f"# Run Index — {run_id}",
            "",
            f"- STATUS: `{status}`",
            f"- Decision (normalized): `{commander.get('normalized_decision', commander_decision)}`",
            f"- Why now (1 line): `{index_reason[:180]}`",
            f"- Hypothesis: `{hypothesis_text[:180]}`",
            f"- Methodology: `{methodology}`",
            f"- Measurement state: `{measurement_state}`",
            f"- AB design contract complete: `{ab_design_contract.get('is_complete')}`",
            f"- AB design gaps: `{ab_design_contract.get('design_gap_codes')}`",
            f"- Sample sizes (control/treat): `{actual_sample.get('control')}` / `{actual_sample.get('treatment')}`",
            f"- Primary uplift + CI: `{ab_summary.get('primary_metric_uplift')}` / `{ab_summary.get('primary_metric_uplift_ci95')}`",
            f"- Guardrails: gp_margin=`{_fmt_metric_value(metrics, 'gp_margin')}`, fill_rate=`{_fmt_metric_value(metrics, 'fill_rate_units')}`, oos=`{_fmt_metric_value(metrics, 'oos_lost_gmv_rate')}`",
            f"- Blockers: `{blocked_by[:5] if blocked_by else []}`",
            f"- Next action: `{(commander.get('top_priorities') or [{}])[0].get('title') if isinstance(commander.get('top_priorities'), list) and commander.get('top_priorities') else 'missing'}`",
            "",
            "## Links",
            "- [decision_card.md](decision_card.md)",
            "- [DECISION_CARD_V2.md](DECISION_CARD_V2.md)",
            f"- [{DECISION_CANONICAL_OUTPUT}]({DECISION_CANONICAL_OUTPUT})",
            "- [goal_scorecard.md](goal_scorecard.md)",
            "- [agent_scorecard.md](agent_scorecard.md)",
            "- [agent_effectiveness.md](agent_effectiveness.md)",
            "- [AGENT_SCOREBOARD.md](AGENT_SCOREBOARD.md)",
            "- [AGENT_SCORECARD.md](AGENT_SCORECARD.md)",
            "- [AGENT_VALUE_SCORECARD.md](AGENT_VALUE_SCORECARD.md)",
            "- [agent_governance.md](agent_governance.md)",
            "- [RETAIL_MBR.md](RETAIL_MBR.md)",
            "- [MBR_SUMMARY.md](MBR_SUMMARY.md)",
            "- [CAUSAL_EXPLANATION.md](CAUSAL_EXPLANATION.md)",
            "- [CAUSAL_EXPLANATION.en.md](CAUSAL_EXPLANATION.en.md)",
            "- [evidence_pack.md](evidence_pack.md)",
            "- [synthetic_bias.md](synthetic_bias.md)",
            "- [AB_STAT_REPORT.md](AB_STAT_REPORT.md)",
            f"- [{AB_CANONICAL_OUTPUT}]({AB_CANONICAL_OUTPUT})",
            "- [STANDARD_CONFORMANCE.md](STANDARD_CONFORMANCE.md)",
            "- [synthetic_realism.md](synthetic_realism.md)",
            "- [agent_quality.md](agent_quality.md)",
            f"- Approvals registry: `data/governance/approvals_{run_id}.json`",
            f"- Agent effectiveness JSON: `data/agent_reports/{run_id}_agent_effectiveness.json`",
            "- [charts/impact.png](charts/impact.png)",
            "- [charts/availability_driver.png](charts/availability_driver.png)",
            "- [charts/agent_pass_rate.png](charts/agent_pass_rate.png)",
            f"- AB report: `{ab_path}`",
            f"- Evaluator JSON: `{evaluator_path}`",
            f"- Doctor JSON: `{doctor_path}`",
            f"- Commander JSON: `{commander_path}`",
            "- [links.json](links.json)",
            "- [artifact_manifest.json](artifact_manifest.json)",
            "- [DEMO_INDEX.md](DEMO_INDEX.md)",
            "",
        ]
        _safe_write(out_dir / "index.md", "\n".join(index_lines))

        demo_lines = [
            f"# Demo Index — {run_id}",
            "",
            "- [decision_card.md](decision_card.md)",
            "- [DECISION_CARD_V2.md](DECISION_CARD_V2.md)",
            f"- [{DECISION_CANONICAL_OUTPUT}]({DECISION_CANONICAL_OUTPUT})",
            "- [RETAIL_MBR.md](RETAIL_MBR.md)",
            "- [CAUSAL_EXPLANATION.md](CAUSAL_EXPLANATION.md)",
            "- [AB_STAT_REPORT.md](AB_STAT_REPORT.md)",
            f"- [{AB_CANONICAL_OUTPUT}]({AB_CANONICAL_OUTPUT})",
            "- [STANDARD_CONFORMANCE.md](STANDARD_CONFORMANCE.md)",
            f"- Doctor portfolio: `data/agent_reports/{run_id}_doctor_variance.json#/hypothesis_portfolio`",
            "- Narrative validation: [causal_claims_validation.json](causal_claims_validation.json)",
            "- [AGENT_VALUE_SCORECARD.md](AGENT_VALUE_SCORECARD.md)",
            "- [synthetic_bias.md](synthetic_bias.md)",
            f"- AB report: `{ab_path}`",
            f"- Commander JSON: `{commander_path}`",
            f"- Approvals: `data/agent_governance/{run_id}_agent_approvals.json`",
            f"- Adversarial suite: `data/eval/adversarial_suite_{run_id}.json`",
            "",
        ]
        _safe_write(out_dir / "DEMO_INDEX.md", "\n".join(demo_lines))

        print(f"ok: reports built for run_id={run_id}")
    except Exception as exc:
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(_redact_text(f"{exc}\n{traceback.format_exc()}"), encoding="utf-8")
        _safe_write(
            out_dir / "build_error.md",
            "\n".join(
                [
                    f"# Build Error — {run_id}",
                    "",
                    "- report_builder: `scripts/build_reports.py`",
                    f"- error: `{exc}`",
                    f"- log: `{log_path}`",
                    "",
                ]
            ),
        )
        print(f"ok: build_reports fallback wrote {out_dir / 'build_error.md'}")


if __name__ == "__main__":
    main()
