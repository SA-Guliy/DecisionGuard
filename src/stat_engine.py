from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.architecture_v3 import load_json_with_integrity
from src.domain_template import load_domain_template

try:
    from scipy import stats as scipy_stats  # type: ignore
except Exception as exc:  # pragma: no cover - dependency gate
    raise RuntimeError(
        "scipy is required for stat_engine (install scipy before running Doctor/Commander runtime)."
    ) from exc


_RATIO_METHOD_LABELS = {"Delta Method / Bootstrap"}
_N_MIN = 30
_ALPHA = 0.05


@dataclass(frozen=True)
class MetricStat:
    metric_id: str
    metric_type: str
    ctrl_value: float | None
    trt_value: float | None
    delta: float | None
    n_ctrl: int
    n_trt: int
    method: str
    p_value: float | None
    ci_lower: float | None
    ci_upper: float | None
    power: float | None
    verdict: str
    is_guardrail_breach: bool
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StatEvidenceBundle:
    version: str
    run_id: str
    generated_at: str
    status: str
    paired_status: str
    layers_present: dict[str, bool]
    srm_flag: bool
    n_min_required: int
    metrics: list[MetricStat]
    guardrail_status_check: list[dict[str, Any]]
    error_code: str
    blocked_by: list[str]
    required_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["metrics"] = [m.to_dict() for m in self.metrics]
        return payload


def _load_method_by_metric() -> dict[str, str]:
    # Single source of truth for method-family mapping is build_ab_report.
    from scripts.build_ab_report import METHOD_BY_METRIC  # local import to avoid module import side-effects on bootstrap

    out: dict[str, str] = {}
    for k, v in METHOD_BY_METRIC.items():
        key = str(k or "").strip().lower()
        val = str(v or "").strip()
        if key and val:
            out[key] = val
    return out


def _load_metrics_dictionary(domain_template_path: str | Path) -> dict[str, Any]:
    tpl_path = Path(str(domain_template_path or "")).resolve()
    raw_tpl = load_json_with_integrity(tpl_path)
    raw_metrics = raw_tpl.get("metrics_dictionary", {}) if isinstance(raw_tpl.get("metrics_dictionary"), dict) else {}
    if raw_metrics:
        return raw_metrics

    # Fallback for legacy templates normalized through load_domain_template.
    normalized = load_domain_template(str(tpl_path))
    out: dict[str, Any] = {}
    guardrails = normalized.get("guardrails", []) if isinstance(normalized.get("guardrails"), list) else []
    for row in guardrails:
        if not isinstance(row, dict):
            continue
        metric_id = str(row.get("metric", "")).strip()
        if not metric_id:
            continue
        out[metric_id] = {
            "role": "guardrail",
            "hard_threshold_min": row.get("hard_threshold_min"),
            "hard_threshold_max": row.get("hard_threshold_max"),
        }
    metrics_block = normalized.get("metrics", {}) if isinstance(normalized.get("metrics"), dict) else {}
    for metric_id in metrics_block.get("primary", []) + metrics_block.get("secondary", []):
        mid = str(metric_id or "").strip()
        if mid and mid not in out:
            out[mid] = {"role": "supporting"}
    return out


def _to_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _std_key_candidates(metric_id: str) -> list[str]:
    m = str(metric_id or "").strip()
    candidates = [f"{m}_stddev"]
    if m == "fill_rate_units":
        candidates.append("fill_rate_stddev")
    if m.endswith("_rate"):
        candidates.append(m.replace("_rate", "_stddev"))
    return candidates


def _extract_metric_std(metrics: dict[str, Any], metric_id: str) -> float | None:
    for key in _std_key_candidates(metric_id):
        val = _to_float(metrics.get(key))
        if val is not None and val >= 0:
            return val
    return None


def _welch_ci_from_stats(
    *,
    mean_ctrl: float,
    std_ctrl: float,
    n_ctrl: int,
    mean_trt: float,
    std_trt: float,
    n_trt: int,
    alpha: float = _ALPHA,
) -> tuple[float | None, float | None]:
    if n_ctrl <= 1 or n_trt <= 1:
        return None, None
    var_ctrl = (std_ctrl ** 2) / float(n_ctrl)
    var_trt = (std_trt ** 2) / float(n_trt)
    se = math.sqrt(max(var_ctrl + var_trt, 0.0))
    if se <= 0:
        return None, None
    denom = ((var_ctrl ** 2) / max(n_ctrl - 1, 1)) + ((var_trt ** 2) / max(n_trt - 1, 1))
    if denom <= 0:
        return None, None
    df = ((var_ctrl + var_trt) ** 2) / denom
    if not math.isfinite(df) or df <= 1:
        return None, None
    t_crit = float(scipy_stats.t.ppf(1.0 - alpha / 2.0, df))
    delta = mean_trt - mean_ctrl
    margin = t_crit * se
    return float(delta - margin), float(delta + margin)


def _metric_type_for_method(method_label: str) -> str:
    if method_label == "Welch t-test":
        return "continuous"
    if method_label in _RATIO_METHOD_LABELS:
        return "ratio_or_proportion"
    if "count" in method_label.lower() or "proportion" in method_label.lower():
        return "count_or_proportion"
    return "unknown"


def _is_guardrail_breach(metric_cfg: dict[str, Any], trt_value: float | None) -> bool:
    if trt_value is None:
        return False
    min_v = _to_float(metric_cfg.get("hard_threshold_min"))
    max_v = _to_float(metric_cfg.get("hard_threshold_max"))
    if min_v is not None and trt_value < min_v:
        return True
    if max_v is not None and trt_value > max_v:
        return True
    return False


def compute_stat_evidence(
    ctrl_snapshot_path: str | Path,
    trt_snapshot_path: str | Path,
    domain_template_path: str,
    *,
    paired_status: str = "COMPLETE",
) -> StatEvidenceBundle:
    ctrl_path = Path(ctrl_snapshot_path)
    trt_path = Path(trt_snapshot_path)
    ctrl = load_json_with_integrity(ctrl_path)
    trt = load_json_with_integrity(trt_path)
    metrics_dict = _load_metrics_dictionary(domain_template_path)
    method_by_metric = _load_method_by_metric()

    ctrl_metrics = ctrl.get("metrics", {}) if isinstance(ctrl.get("metrics"), dict) else {}
    trt_metrics = trt.get("metrics", {}) if isinstance(trt.get("metrics"), dict) else {}
    run_id = str(trt.get("run_id", trt_path.stem)).strip() or trt_path.stem

    n_ctrl = int(_to_float(ctrl_metrics.get("orders_cnt")) or 0.0)
    n_trt = int(_to_float(trt_metrics.get("orders_cnt")) or 0.0)
    srm_flag = False
    if n_ctrl > 0 and n_trt > 0:
        ratio = float(n_ctrl) / float(n_trt)
        srm_flag = abs(ratio - 1.0) > 0.10

    metric_rows: list[MetricStat] = []
    guardrail_status_check: list[dict[str, Any]] = []
    blocked_by: list[str] = []
    required_actions: list[str] = []

    for metric_id in sorted(metrics_dict.keys()):
        m_cfg = metrics_dict.get(metric_id, {})
        if not isinstance(m_cfg, dict):
            continue
        method_label = method_by_metric.get(str(metric_id).strip().lower(), "Metric-specific method (see contract)")
        metric_type = _metric_type_for_method(method_label)
        ctrl_value = _to_float(ctrl_metrics.get(metric_id))
        trt_value = _to_float(trt_metrics.get(metric_id))
        delta = None
        if ctrl_value is not None and trt_value is not None:
            delta = trt_value - ctrl_value

        method = "insufficient_data"
        p_value: float | None = None
        ci_lower: float | None = None
        ci_upper: float | None = None
        power: float | None = None
        verdict = "NO_DATA"
        note = ""

        if ctrl_value is None or trt_value is None:
            verdict = "NO_DATA"
            note = "metric_missing_in_snapshot"
        elif method_label in _RATIO_METHOD_LABELS:
            method = "aggregate_only"
            verdict = "UNDERPOWERED"
            note = "ratio metric requires bootstrap or delta-method on raw unit-level samples"
        else:
            std_ctrl = _extract_metric_std(ctrl_metrics, metric_id)
            std_trt = _extract_metric_std(trt_metrics, metric_id)
            if std_ctrl is None or std_trt is None or n_ctrl < _N_MIN or n_trt < _N_MIN:
                method = "insufficient_data"
                verdict = "UNDERPOWERED"
                note = "requires stddev and n>=30 for welch_ttest_from_stats"
            else:
                method = "welch_ttest_from_stats"
                t_res = scipy_stats.ttest_ind_from_stats(
                    mean1=float(ctrl_value),
                    std1=float(std_ctrl),
                    nobs1=int(n_ctrl),
                    mean2=float(trt_value),
                    std2=float(std_trt),
                    nobs2=int(n_trt),
                    equal_var=False,
                )
                try:
                    p_value = float(t_res.pvalue)
                except Exception:
                    p_value = None
                ci_lower, ci_upper = _welch_ci_from_stats(
                    mean_ctrl=float(ctrl_value),
                    std_ctrl=float(std_ctrl),
                    n_ctrl=int(n_ctrl),
                    mean_trt=float(trt_value),
                    std_trt=float(std_trt),
                    n_trt=int(n_trt),
                )
                if p_value is None or not math.isfinite(p_value):
                    verdict = "INCONCLUSIVE"
                    note = "invalid_p_value"
                elif p_value <= _ALPHA and delta is not None:
                    verdict = "POSITIVE_SIGNIFICANT" if delta > 0 else ("NEGATIVE_SIGNIFICANT" if delta < 0 else "NO_SIGNIFICANT_EFFECT")
                else:
                    verdict = "NO_SIGNIFICANT_EFFECT"

        is_guardrail = str(m_cfg.get("role", "")).strip() == "guardrail"
        guardrail_breach = _is_guardrail_breach(m_cfg, trt_value)
        metric_rows.append(
            MetricStat(
                metric_id=str(metric_id),
                metric_type=metric_type,
                ctrl_value=ctrl_value,
                trt_value=trt_value,
                delta=delta,
                n_ctrl=max(0, n_ctrl),
                n_trt=max(0, n_trt),
                method=method,
                p_value=p_value,
                ci_lower=ci_lower,
                ci_upper=ci_upper,
                power=power,
                verdict=verdict,
                is_guardrail_breach=bool(guardrail_breach),
                note=note[:240],
            )
        )
        if is_guardrail:
            if trt_value is None:
                status = "NO_DATA"
                blocks_rollout = True
            elif guardrail_breach:
                status = "BREACH"
                blocks_rollout = True
            else:
                status = "PASS"
                blocks_rollout = False
            guardrail_status_check.append(
                {
                    "metric_id": str(metric_id),
                    "status": status,
                    "blocks_rollout": bool(blocks_rollout),
                    "evidence_ref": f"artifact:{trt_path}#/metrics/{metric_id}",
                }
            )
            if status == "NO_DATA":
                blocked_by.append(f"guardrail_missing:{metric_id}")
                required_actions.append(f"populate_guardrail_metric:{metric_id}")

    any_metrics = len(metric_rows) > 0
    pass_status = (
        any_metrics
        and len([g for g in guardrail_status_check if g.get("status") == "NO_DATA"]) == 0
    )
    error_code = "NONE" if pass_status else "METHODOLOGY_INVARIANT_BROKEN"
    layers_present = {
        "layer1_live_stats": bool(any_metrics and n_ctrl >= _N_MIN and n_trt >= _N_MIN),
        "layer2_guardrail_check": bool(len(guardrail_status_check) > 0),
        "layer3_history": True,
    }

    return StatEvidenceBundle(
        version="stat_evidence_bundle_v1",
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        status="PASS" if pass_status else "FAIL",
        paired_status=str(paired_status or "COMPLETE").strip().upper(),
        layers_present=layers_present,
        srm_flag=bool(srm_flag),
        n_min_required=_N_MIN,
        metrics=metric_rows,
        guardrail_status_check=guardrail_status_check[:40],
        error_code=error_code,
        blocked_by=sorted({x for x in blocked_by if str(x).strip()}),
        required_actions=sorted({x for x in required_actions if str(x).strip()}),
    )
