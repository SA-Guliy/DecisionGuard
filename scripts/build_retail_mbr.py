#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import traceback
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

KPI_SPECS = [
    ("Цель 3", "Покупатели (active_buyers_avg)", "active_buyers_avg"),
    ("Цель 3", "Новые покупатели 7д", "new_buyers_7d"),
    ("Цель 3", "Churn rate", "churn_rate"),
    ("Цель 3", "Rep mean", "rep_mean"),
    ("Цель 2", "Orders", "orders_cnt"),
    ("Цель 2", "GMV", "gmv"),
    ("Цель 2", "AOV", "aov"),
    ("Цель 2", "GP", "gp"),
    ("Цель 2", "GP margin", "gp_margin"),
    ("Цель 2", "GP per order", "gp_per_order"),
    ("Цель 1", "Writeoff units", "writeoff_units"),
    ("Цель 1", "Writeoff COGS", "writeoff_cogs"),
    ("Цель 1", "Writeoff rate vs requested", "writeoff_rate_vs_requested_units"),
    ("Цель 1", "Perishable GMV share", "perishable_gmv_share"),
    ("Guardrail", "Fill rate", "fill_rate_units"),
    ("Guardrail", "OOS lost GMV rate", "oos_lost_gmv_rate"),
    ("Guardrail", "Lost GMV OOS", "lost_gmv_oos"),
]


DEFAULT_DIRECTION_BY_KEY = {
    "active_buyers_avg": "higher_is_better",
    "new_buyers_7d": "higher_is_better",
    "churn_rate": "lower_is_better",
    "rep_mean": "higher_is_better",
    "orders_cnt": "higher_is_better",
    "gmv": "higher_is_better",
    "aov": "higher_is_better",
    "gp": "higher_is_better",
    "gp_margin": "higher_is_better",
    "gp_per_order": "higher_is_better",
    "writeoff_units": "lower_is_better",
    "writeoff_cogs": "lower_is_better",
    "writeoff_rate_vs_requested_units": "lower_is_better",
    "perishable_gmv_share": "lower_is_better",
    "fill_rate_units": "higher_is_better",
    "oos_lost_gmv_rate": "lower_is_better",
    "lost_gmv_oos": "lower_is_better",
}


def _redact(text: str) -> str:
    out = text
    for p, repl in REDACTION_PATTERNS:
        out = p.sub(repl, out)
    return out


def _safe_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(text), encoding="utf-8")


def _safe_write_json(path: Path, payload: dict[str, Any]) -> None:
    _safe_write(path, json.dumps(payload, ensure_ascii=False, indent=2))


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _parse_ts(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = raw.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _fmt(v: Any) -> str:
    if v is None:
        return "— (*)"
    try:
        x = float(v)
        return f"{x:.3f}"
    except Exception:
        return "— (*)"


def _delta(cur: Any, base: Any) -> str:
    try:
        c = float(cur)
        b = float(base)
    except Exception:
        return "— (*)"
    return f"{(c - b):+.3f}"


def _pct_delta(cur: Any, base: Any) -> str:
    try:
        c = float(cur)
        b = float(base)
        if b == 0:
            return "— (*)"
    except Exception:
        return "— (*)"
    return f"{((c - b) / b):+.3%}"


def _f(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _find_prev_run_id(run_id: str, current_ts: datetime | None) -> str | None:
    if current_ts is None:
        return None
    best: tuple[datetime, str] | None = None
    for p in Path("data/metrics_snapshots").glob("*.json"):
        rid = p.stem
        if rid == run_id:
            continue
        doc = _load_json(p)
        ts = _parse_ts((doc or {}).get("generated_at"))
        if ts is None or ts >= current_ts:
            continue
        if best is None or ts > best[0]:
            best = (ts, rid)
    return best[1] if best else None


def _month_suffix(ts: datetime | None) -> str:
    return ts.strftime("%Y_%m") if ts else "unknown"


def _period_label(ts: datetime | None, fallback: str) -> str:
    if ts is None:
        return f"Период: {fallback}"
    months = [
        "Январь",
        "Февраль",
        "Март",
        "Апрель",
        "Май",
        "Июнь",
        "Июль",
        "Август",
        "Сентябрь",
        "Октябрь",
        "Ноябрь",
        "Декабрь",
    ]
    return f"{months[ts.month - 1]} {ts.year}"


def _rule_explanations(metrics_fact: dict[str, Any], metrics_prev: dict[str, Any]) -> list[str]:
    out: list[str] = []
    fill_f, fill_p = metrics_fact.get("fill_rate_units"), metrics_prev.get("fill_rate_units")
    oos_f, oos_p = metrics_fact.get("oos_lost_gmv_rate"), metrics_prev.get("oos_lost_gmv_rate")
    gmv_f, gmv_p = metrics_fact.get("gmv"), metrics_prev.get("gmv")
    gm_f, gm_p = metrics_fact.get("gp_margin"), metrics_prev.get("gp_margin")
    wu_f, wu_p = metrics_fact.get("writeoff_units"), metrics_prev.get("writeoff_units")
    nb_f, nb_p = metrics_fact.get("new_buyers_7d"), metrics_prev.get("new_buyers_7d")

    try:
        if float(fill_f) < float(fill_p) and float(oos_f) > float(oos_p):
            out.append("Падение availability (OOS), вероятно under-replenishment/leadtime.")
    except Exception:
        pass
    try:
        if float(gmv_f) > float(gmv_p) and float(gm_f) < float(gm_p):
            out.append("Рост выручки при ухудшении маржинальности (price/discount pressure).")
    except Exception:
        pass
    try:
        if float(wu_f) < float(wu_p) and float(fill_f) < float(fill_p):
            out.append("Риск starvation: списание снизилось за счёт ухудшения availability (Goodhart).")
    except Exception:
        pass
    try:
        if float(nb_f) < float(nb_p):
            out.append("Слабее acquisition/промо/ассортимент относительно предыдущего периода.")
    except Exception:
        pass
    return out


def _row_explanation(
    metric_key: str,
    fact: Any,
    plan: Any,
    prev: Any,
    direction: str,
    metrics_fact: dict[str, Any],
    metrics_prev: dict[str, Any],
    metrics_plan: dict[str, Any],
    driver_tag: str,
) -> str:
    try:
        f = float(fact)
        p = float(plan)
        pr = float(prev)
    except Exception:
        return "Недостаточно данных для интерпретации KPI."

    if direction == "lower_is_better":
        vs_plan = "лучше плана" if f <= p else "хуже плана"
        vs_prev = "лучше прошлого периода" if f <= pr else "хуже прошлого периода"
    else:
        vs_plan = "лучше плана" if f >= p else "хуже плана"
        vs_prev = "лучше прошлого периода" if f >= pr else "хуже прошлого периода"

    msg = f"{vs_plan}; {vs_prev}."
    # 1% sensitivity: when movement is material, make wording explicit.
    rel_plan = (f - p) / p if p != 0 else 0.0
    rel_prev = (f - pr) / pr if pr != 0 else 0.0
    if abs(rel_plan) >= 0.01 or abs(rel_prev) >= 0.01:
        msg += (
            f" Материальное отклонение: к плану {rel_plan:+.3%}, к пред. периоду {rel_prev:+.3%}."
        )

    # Coupled signals for realism/business diagnosis.
    try:
        fill_f = float(metrics_fact.get("fill_rate_units"))
        fill_p = float(metrics_prev.get("fill_rate_units"))
        oos_f = float(metrics_fact.get("oos_lost_gmv_rate"))
        oos_p = float(metrics_prev.get("oos_lost_gmv_rate"))
        if metric_key in {"fill_rate_units", "oos_lost_gmv_rate", "lost_gmv_oos"} and fill_f < fill_p and oos_f > oos_p:
            msg += " Признаки просадки availability (fill down, OOS up)."
    except Exception:
        pass

    try:
        gmv_f = float(metrics_fact.get("gmv"))
        gmv_p = float(metrics_prev.get("gmv"))
        gm_f = float(metrics_fact.get("gp_margin"))
        gm_p = float(metrics_prev.get("gp_margin"))
        if metric_key in {"gmv", "gp_margin", "aov"} and gmv_f > gmv_p and gm_f < gm_p:
            msg += " Возможен рост выручки за счёт ценового давления на маржу."
    except Exception:
        pass
    try:
        gmv_f = float(metrics_fact.get("gmv"))
        gmv_pl = float(metrics_plan.get("gmv"))
        gm_f = float(metrics_fact.get("gp_margin"))
        gm_pl = float(metrics_plan.get("gp_margin"))
        gmv_delta_plan = (gmv_f - gmv_pl) / gmv_pl if gmv_pl else 0.0
        gm_delta_plan = (gm_f - gm_pl) / gm_pl if gm_pl else 0.0
        if metric_key in {"gmv", "gp_margin", "aov", "orders_cnt"} and gmv_delta_plan <= -0.01 and gm_delta_plan >= 0.01:
            msg += " Strategy shift: Margin optimization at the expense of Volume."
    except Exception:
        pass

    try:
        wu_f = float(metrics_fact.get("writeoff_cogs"))
        wu_p = float(metrics_prev.get("writeoff_cogs"))
        fill_f = float(metrics_fact.get("fill_rate_units"))
        fill_p = float(metrics_prev.get("fill_rate_units"))
        if metric_key in {"writeoff_cogs", "writeoff_rate_vs_requested_units"} and wu_f < wu_p and fill_f < fill_p:
            msg += " Риск Goodhart: списание снизилось при ухудшении сервиса."
    except Exception:
        pass
    if metric_key == "new_buyers_7d" and rel_plan >= 0.01:
        msg += " Successful Acquisition Campaign."

    msg += f" [{driver_tag if driver_tag else '—'}]"
    return msg


def _goal_status(metrics_fact: dict[str, Any], metrics_prev: dict[str, Any]) -> dict[str, str]:
    out = {"goal1": "YELLOW", "goal2": "YELLOW", "goal3": "YELLOW"}
    # Goal1: writeoff down without hurting availability.
    try:
        wu_f, wu_p = float(metrics_fact.get("writeoff_units")), float(metrics_prev.get("writeoff_units"))
        fill_f, fill_p = float(metrics_fact.get("fill_rate_units")), float(metrics_prev.get("fill_rate_units"))
        if wu_f <= wu_p and fill_f >= fill_p:
            out["goal1"] = "GREEN"
        elif wu_f > wu_p and fill_f < fill_p:
            out["goal1"] = "RED"
    except Exception:
        pass
    # Goal2: AOV up with stable margin.
    try:
        aov_f, aov_p = float(metrics_fact.get("aov")), float(metrics_prev.get("aov"))
        gm_f, gm_p = float(metrics_fact.get("gp_margin")), float(metrics_prev.get("gp_margin"))
        if aov_f >= aov_p and gm_f >= (gm_p - 0.002):
            out["goal2"] = "GREEN"
        elif aov_f < aov_p and gm_f < gm_p:
            out["goal2"] = "RED"
    except Exception:
        pass
    # Goal3: buyers/retention.
    try:
        nb_f, nb_p = float(metrics_fact.get("new_buyers_7d")), float(metrics_prev.get("new_buyers_7d"))
        rep_f, rep_p = float(metrics_fact.get("rep_mean")), float(metrics_prev.get("rep_mean"))
        if nb_f >= nb_p or rep_f >= rep_p:
            out["goal3"] = "GREEN"
        elif nb_f < nb_p and rep_f < rep_p:
            out["goal3"] = "RED"
    except Exception:
        pass
    return out


def _plan_value(
    metric_key: str,
    plan_source: str,
    ab: dict[str, Any] | None,
    metrics_prev: dict[str, Any],
    metrics_plan: dict[str, Any],
) -> tuple[Any, str]:
    if plan_source == "ab_control":
        if isinstance(ab, dict):
            s = ab.get("summary", {}) if isinstance(ab.get("summary"), dict) else {}
            map_ab = {
                "aov": s.get("aov_control"),
                "gp_per_order": s.get("gp_per_order_control"),
                "fill_rate_units": s.get("fill_rate_control"),
            }
            if metric_key in map_ab and map_ab[metric_key] is not None:
                return map_ab[metric_key], "ab_control"
        return metrics_prev.get(metric_key), "prev_fallback"
    if plan_source in {"prev", "plan_run", "targets"}:
        return metrics_plan.get(metric_key), plan_source
    return metrics_prev.get(metric_key), "prev_fallback"


def _targets_plan_value(targets_doc: dict[str, Any], metric_key: str, prev_value: Any) -> tuple[Any, str]:
    kpis = targets_doc.get("kpi_targets", {}) if isinstance(targets_doc.get("kpi_targets"), dict) else {}
    hit: dict[str, Any] | None = None
    for spec in kpis.values():
        if not isinstance(spec, dict):
            continue
        if str(spec.get("metric_key", "")).strip() == metric_key:
            hit = spec
            break
    if not hit:
        return None, "targets_missing_metric"

    plan = hit.get("plan", {}) if isinstance(hit.get("plan"), dict) else {}
    ptype = str(plan.get("type", "")).strip()
    pval = plan.get("value")
    try:
        pnum = float(pval)
    except Exception:
        return None, "targets_invalid_plan_value"

    if ptype == "absolute":
        return pnum, "targets_absolute"
    if ptype == "relative_to_prev":
        try:
            prev_num = float(prev_value)
        except Exception:
            return None, "targets_prev_missing"
        return prev_num * (1.0 + pnum), "targets_relative_to_prev"
    return None, "targets_invalid_plan_type"


def _activities_table(
    doctor: dict[str, Any],
    commander: dict[str, Any],
    evaluator: dict[str, Any],
    ab: dict[str, Any] | None,
    force_unobservable: bool = False,
) -> list[list[str]]:
    rows: list[list[str]] = []
    ab_status = str((ab or {}).get("status", "missing")).upper() if isinstance(ab, dict) else "missing"
    ab_summary = (ab or {}).get("summary", {}) if isinstance((ab or {}).get("summary"), dict) else {}
    ab_plan = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
    next_step = "missing"
    if isinstance(commander.get("top_priorities"), list) and commander.get("top_priorities"):
        p0 = commander["top_priorities"][0]
        if isinstance(p0, dict):
            next_step = str(p0.get("title", "missing"))

    for exp in ab_plan[:5]:
        if not isinstance(exp, dict):
            continue
        hyps = exp.get("hypotheses", []) if isinstance(exp.get("hypotheses"), list) else []
        h0 = hyps[0] if hyps and isinstance(hyps[0], dict) else {}
        measurement_bad = force_unobservable or ab_status in {"METHODOLOGY_MISMATCH", "MISSING_ASSIGNMENT", "ASSIGNMENT_RECOVERED"}
        fact = (
            "❌ Результаты недоступны (measurement blind spot)"
            if measurement_bad
            else f"uplift={ab_summary.get('primary_metric_uplift')} CI={ab_summary.get('primary_metric_uplift_ci95')}"
        )
        rows.append(
            [
                f"{exp.get('lever_type', 'missing')} / {exp.get('scope', 'missing')}",
                str(h0.get("hypothesis_statement", "missing")),
                (
                    f"unit={exp.get('unit', 'missing')}, duration={exp.get('duration_days', 'missing')}, "
                    f"freeze={exp.get('freeze_window_days', 'missing')}, primary={h0.get('primary_metric', 'missing')}"
                ),
                str(h0.get("expected_effect_range", "missing")),
                fact,
                (
                    f"evaluator={evaluator.get('decision', 'missing')}; "
                    f"commander={commander.get('normalized_decision', commander.get('decision', 'missing'))}"
                ),
                next_step,
            ]
        )
    return rows


def _dashboard_focus(metrics_fact: dict[str, Any], metrics_prev: dict[str, Any]) -> list[str]:
    focus: list[str] = []
    try:
        fill_f = float(metrics_fact.get("fill_rate_units"))
        fill_p = float(metrics_prev.get("fill_rate_units"))
        oos_f = float(metrics_fact.get("oos_lost_gmv_rate"))
        oos_p = float(metrics_prev.get("oos_lost_gmv_rate"))
        if fill_f < fill_p or oos_f > oos_p:
            focus.append("Availability dashboard: fill_rate_units + oos_lost_gmv_rate + lost_gmv_oos")
    except Exception:
        pass
    try:
        gmv_f = float(metrics_fact.get("gmv"))
        gmv_p = float(metrics_prev.get("gmv"))
        gm_f = float(metrics_fact.get("gp_margin"))
        gm_p = float(metrics_prev.get("gp_margin"))
        if gmv_f != gmv_p or gm_f != gm_p:
            focus.append("Unit economics dashboard: gmv + aov + gp_margin + gp_per_order")
    except Exception:
        pass
    try:
        w_f = float(metrics_fact.get("writeoff_cogs"))
        w_p = float(metrics_prev.get("writeoff_cogs"))
        if w_f != w_p:
            focus.append("Spoilage dashboard: writeoff_cogs + writeoff_rate_vs_requested_units + perishable_gmv_share")
    except Exception:
        pass
    if not focus:
        focus.append("Core dashboard: gmv + aov + fill_rate_units + gp_margin")
    return focus


def _driver_tags(causal_claims: dict[str, Any]) -> dict[str, str]:
    tags: dict[str, str] = {}
    drivers = causal_claims.get("drivers", []) if isinstance(causal_claims.get("drivers"), list) else []
    for d in drivers:
        if not isinstance(d, dict):
            continue
        did = d.get("driver_id")
        try:
            did_i = int(did)
        except Exception:
            continue
        impacted = d.get("impacted_metrics", [])
        if not isinstance(impacted, list):
            continue
        for m in impacted:
            key = str(m).strip()
            if key and key not in tags:
                tags[key] = f"Driver #{did_i}"
    return tags


def _material_delta(fact: Any, plan: Any, prev: Any, threshold: float = 0.01) -> bool:
    f = _f(fact)
    p = _f(plan)
    pr = _f(prev)
    if f is None:
        return False
    checks: list[float] = []
    if p not in {None, 0.0}:
        checks.append(abs((f - p) / p))
    if pr not in {None, 0.0}:
        checks.append(abs((f - pr) / pr))
    return any(x >= threshold for x in checks)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Retail MBR report (Plan vs Fact vs Prev)")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--prev-run-id", default="")
    parser.add_argument("--plan-source", choices=["ab_control", "plan_run", "prev", "targets"], default="ab_control")
    parser.add_argument("--plan-run-id", default="")
    parser.add_argument("--targets-file", default="")
    parser.add_argument("--period-label", default="")
    args = parser.parse_args()

    run_id = args.run_id
    out_dir = Path(f"reports/L1_ops/{run_id}")
    log_path = Path(f"data/logs/build_retail_mbr_{run_id}.log")
    try:
        snap = _load_json(Path(f"data/metrics_snapshots/{run_id}.json")) or {}
        doctor = _load_json(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
        evaluator = _load_json(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")) or {}
        commander = _load_json(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}
        causal_claims = _load_json(Path(f"reports/L1_ops/{run_id}/causal_claims.json")) or {}
        run_cfg = snap.get("run_config", {}) if isinstance(snap.get("run_config"), dict) else {}
        exp_id = str(run_cfg.get("experiment_id", "")).strip()
        ab = _load_json(Path(f"data/ab_reports/{run_id}_{exp_id}_ab.json")) if exp_id else None
        ab_status = str((ab or {}).get("status", "missing")).upper() if isinstance(ab, dict) else "MISSING"
        ab_notes = (ab or {}).get("notes", []) if isinstance((ab or {}).get("notes"), list) else []
        fatal_unobservable = (
            ab_status in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH"}
            or any("customer_join_unavailable_fallback_store" in str(n) for n in ab_notes)
        )

        current_ts = _parse_ts(snap.get("generated_at"))
        prev_run_id = args.prev_run_id.strip() or _find_prev_run_id(run_id, current_ts) or ""
        prev_snap = _load_json(Path(f"data/metrics_snapshots/{prev_run_id}.json")) if prev_run_id else {}

        metrics_fact = snap.get("metrics", {}) if isinstance(snap.get("metrics"), dict) else {}
        metrics_prev = prev_snap.get("metrics", {}) if isinstance(prev_snap, dict) and isinstance(prev_snap.get("metrics"), dict) else {}

        plan_source_used = args.plan_source
        metrics_plan: dict[str, Any] = {}
        targets_doc: dict[str, Any] = {}
        if args.plan_source == "plan_run":
            pr = args.plan_run_id.strip()
            pdoc = _load_json(Path(f"data/metrics_snapshots/{pr}.json")) if pr else None
            metrics_plan = pdoc.get("metrics", {}) if isinstance(pdoc, dict) and isinstance(pdoc.get("metrics"), dict) else {}
            if not metrics_plan:
                plan_source_used = "prev_fallback"
                metrics_plan = metrics_prev
        elif args.plan_source == "targets":
            targets_path = Path(args.targets_file) if args.targets_file else Path("configs/targets/targets_v1.json")
            tdoc = _load_json(targets_path)
            targets_doc = tdoc if isinstance(tdoc, dict) else {}
            if not targets_doc:
                plan_source_used = "prev_fallback"
                metrics_plan = metrics_prev
        else:
            metrics_plan = metrics_prev

        blocked_by_data: list[str] = []
        csv_rows: list[list[str]] = []
        md_rows: list[str] = [
            "| Блок | KPI | План | Факт | Пред. период | Δ к плану | Δ к пред. | Пояснение |",
            "|---|---|---:|---:|---:|---:|---:|---|",
        ]
        planned_values: dict[str, Any] = {}
        planned_origin: dict[str, str] = {}
        for _, _, key in KPI_SPECS:
            prev_val = metrics_prev.get(key)
            if args.plan_source == "targets" and targets_doc:
                pval, porigin = _targets_plan_value(targets_doc, key, prev_val)
                if pval is None:
                    pval = prev_val
                    porigin = "targets_fallback_prev" if prev_val is not None else f"{porigin}_fallback_missing"
            else:
                pval, porigin = _plan_value(key, args.plan_source, ab, metrics_prev, metrics_plan)
            planned_values[key] = pval
            planned_origin[key] = porigin

        metric_claims = causal_claims.get("metric_claims", {}) if isinstance(causal_claims.get("metric_claims"), dict) else {}
        driver_tags = _driver_tags(causal_claims)
        causal_chains = causal_claims.get("causal_chains", []) if isinstance(causal_claims.get("causal_chains"), list) else []
        chain_map: dict[str, dict[str, Any]] = {}
        for ch in causal_chains:
            if not isinstance(ch, dict):
                continue
            mk = str(ch.get("metric", "")).strip()
            if mk and mk not in chain_map:
                chain_map[mk] = ch
        used_explanations: list[str] = []
        duplicate_explanations: list[str] = []
        for block, kpi_name, key in KPI_SPECS:
            fact = metrics_fact.get(key)
            prev = metrics_prev.get(key)
            direction = DEFAULT_DIRECTION_BY_KEY.get(key, "higher_is_better")
            if targets_doc:
                kpis = targets_doc.get("kpi_targets", {}) if isinstance(targets_doc.get("kpi_targets"), dict) else {}
                for spec in kpis.values():
                    if not isinstance(spec, dict):
                        continue
                    if str(spec.get("metric_key", "")).strip() == key:
                        direction = str(spec.get("direction", direction))
                        break
            plan = planned_values.get(key)
            plan_origin = planned_origin.get(key, "unknown")
            if fact is None:
                blocked_by_data.append(f"{key}: missing in fact metrics snapshot")
            if prev is None:
                blocked_by_data.append(f"{key}: missing in previous period snapshot")
            if plan is None:
                blocked_by_data.append(f"{key}: missing in plan source ({plan_origin})")
            if _material_delta(fact, plan, prev, threshold=0.01):
                chain = chain_map.get(key, {})
                claim = metric_claims.get(key, {}) if isinstance(metric_claims.get(key), dict) else {}
                rank = int(chain.get("driver_rank", 0) or 0) if isinstance(chain, dict) else 0
                if rank > 0:
                    expl = f"Driver #{rank} (see [CAUSAL_EXPLANATION](CAUSAL_EXPLANATION.md#driver-{rank}))."
                else:
                    expl = "— (*) BLOCKED_BY_DATA: no grounded driver for this KPI."
                    blocked_by_data.append(f"{key}: missing_grounded_driver")
            else:
                expl = "— [—]"
            if expl in used_explanations and expl not in duplicate_explanations:
                duplicate_explanations.append(expl)
            used_explanations.append(expl)
            md_rows.append(
                f"| {block} | {kpi_name} | {_fmt(plan)} | {_fmt(fact)} | {_fmt(prev)} | {_delta(fact, plan)} | {_delta(fact, prev)} | {expl} |"
            )
            csv_rows.append(
                [
                    block,
                    kpi_name,
                    _fmt(plan),
                    _fmt(fact),
                    _fmt(prev),
                    _delta(fact, plan),
                    _pct_delta(fact, plan),
                    _delta(fact, prev),
                    _pct_delta(fact, prev),
                    plan_origin,
                    expl,
                ]
            )

        explanations = []
        for ch in causal_chains[:3]:
            if not isinstance(ch, dict):
                continue
            cid = str(ch.get("claim_id", "")).strip()
            metric = str(ch.get("metric", "")).strip()
            root = str(ch.get("root_cause", "")).strip()
            if cid and metric and root:
                explanations.append(f"{cid}: {metric} -> {root}. See CAUSAL_EXPLANATION.md.")
        tl = _goal_status(metrics_fact, metrics_prev)
        dashboard_focus = _dashboard_focus(metrics_fact, metrics_prev)
        activities = _activities_table(doctor, commander, evaluator, ab, force_unobservable=fatal_unobservable)

        period_label = args.period_label.strip() or _period_label(current_ts, run_id)
        month_suffix = _month_suffix(current_ts)
        mbr_name = f"RETAIL_MBR_{month_suffix}.md" if month_suffix != "unknown" else "RETAIL_MBR.md"

        lines = [
            f"# Retail MBR — {period_label}",
            "",
            f"- run_id: `{run_id}`",
            f"- plan_source_requested: `{args.plan_source}`",
            f"- plan_source_used: `{plan_source_used}`",
            f"- prev_run_id_used: `{prev_run_id or 'missing'}`",
            "",
        ]
        if fatal_unobservable:
            lines.extend(
                [
                    "## ❌ FATAL",
                    "Experiment unobservable: cannot compute uplift. Fix assignment/join.",
                    f"- ab_status: `{ab_status}`",
                    "",
                ]
            )
        lines.extend(
            [
            "## KPI (Plan vs Fact vs Prev)",
            *md_rows,
            "",
            "## Пояснение (Narrative Analyst + evidence)",
            *([f"- {x}" for x in explanations] if explanations else ["- — (*) BLOCKED_BY_DATA: narrative drivers missing; see CAUSAL_EXPLANATION.md."]),
            "",
            ]
        )
        if duplicate_explanations:
            lines.extend(
                [
                    "## WARN",
                    "Найдены дублирующиеся пояснения в KPI-таблице:",
                    *[f"- {x}" for x in duplicate_explanations[:10]],
                    "",
                ]
            )
        lines.extend(
            [
            "## Мероприятия и гипотезы",
            "| Мероприятие | Гипотеза | Методология | Ожидаемый эффект | Факт | Решение | Следующий шаг |",
            "|---|---|---|---|---|---|---|",
            ]
        )
        if activities:
            for r in activities:
                lines.append("| " + " | ".join(str(x).replace("\n", " ") for x in r) + " |")
        else:
            lines.append("| — (*) | — (*) | — (*) | — (*) | — (*) | — (*) | — (*) |")
            lines.append("")
            lines.append("Примечание: гипотезы/тесты отсутствуют в этом run, потому что decision-gating остановил запуск (например HOLD_NEED_DATA/STOP).")

        lines.extend(["", "## BLOCKED_BY_DATA"])
        if blocked_by_data:
            for b in sorted(set(blocked_by_data)):
                lines.append(f"- {b}")
        else:
            lines.append("- none")
        lines.extend(
            [
                "",
                "## 4. Дашборды",
                "![Impact Chart](charts/impact.png)",
                "![Agent Pass Rate](charts/agent_pass_rate.png)",
                "![Goal 1 Writeoff](charts/goal1_writeoff.png)",
                "![Goal 2 AOV](charts/goal2_aov.png)",
                "![Goal 3 Buyers](charts/goal3_buyers.png)",
                "![Availability Driver](charts/availability_driver.png)",
                "",
                "📌 Detailed reasoning: [CAUSAL_EXPLANATION.md](CAUSAL_EXPLANATION.md)",
            ]
        )

        out_dir.mkdir(parents=True, exist_ok=True)
        _safe_write(out_dir / mbr_name, "\n".join(lines) + "\n")
        _safe_write(out_dir / "RETAIL_MBR.md", "\n".join(lines) + "\n")

        summary_lines = [
            f"# MBR Summary — {period_label}",
            "",
            f"- run_id: `{run_id}`",
            f"- plan_source_used: `{plan_source_used}`",
            f"- prev_run_id_used: `{prev_run_id or 'missing'}`",
            f"- decision: `{commander.get('normalized_decision', commander.get('decision', 'missing'))}`",
            f"- ab_status: `{str((ab or {}).get('status', 'missing')) if isinstance(ab, dict) else 'missing'}`",
            "",
            "## Traffic Light (3 Goals)",
            f"- Goal1 (Writeoff/Availability): `{tl['goal1']}`",
            f"- Goal2 (AOV/Margin): `{tl['goal2']}`",
            f"- Goal3 (Buyers/Retention): `{tl['goal3']}`",
            "",
            "## KPI Highlights",
            f"- GMV: plan `{_fmt(_plan_value('gmv', args.plan_source, ab, metrics_prev, metrics_plan)[0])}` -> fact `{_fmt(metrics_fact.get('gmv'))}`",
            f"- AOV: plan `{_fmt(_plan_value('aov', args.plan_source, ab, metrics_prev, metrics_plan)[0])}` -> fact `{_fmt(metrics_fact.get('aov'))}`",
            f"- Fill rate: prev `{_fmt(metrics_prev.get('fill_rate_units'))}` -> fact `{_fmt(metrics_fact.get('fill_rate_units'))}`",
            f"- OOS lost GMV rate: prev `{_fmt(metrics_prev.get('oos_lost_gmv_rate'))}` -> fact `{_fmt(metrics_fact.get('oos_lost_gmv_rate'))}`",
            "",
            "## Dashboard Focus (auto-selected)",
            *([f"- {x}" for x in dashboard_focus] if dashboard_focus else ["- Core dashboard"]),
            "- L1 charts: `charts/impact.png`, `charts/goal1_writeoff.png`, `charts/goal2_aov.png`, `charts/goal3_buyers.png`",
            "",
            "## Why (rule-based)",
            *([f"- {x}" for x in explanations[:3]] if explanations else ["- Нет уверенных rule-based сигналов."]),
            "",
            "## Data Gaps",
            *([f"- {x}" for x in sorted(set(blocked_by_data))[:8]] if blocked_by_data else ["- none"]),
            "",
            "## Next Step",
            (
                f"- {str(((commander.get('top_priorities') or [{}])[0] if isinstance(commander.get('top_priorities'), list) and commander.get('top_priorities') else {}).get('title', 'missing'))}"
            ),
            "",
        ]
        _safe_write(out_dir / "MBR_SUMMARY.md", "\n".join(summary_lines))

        csv_path = out_dir / "mbr_kpi.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "block",
                    "kpi",
                    "plan",
                    "fact",
                    "prev",
                    "delta_plan_abs",
                    "delta_plan_pct",
                    "delta_prev_abs",
                    "delta_prev_pct",
                    "plan_origin",
                    "explanation",
                ]
            )
            w.writerows(csv_rows)

        meta = {
            "run_id": run_id,
            "period_label": period_label,
            "plan_source_requested": args.plan_source,
            "plan_source_used": plan_source_used,
            "prev_run_id_used": prev_run_id or None,
            "retail_mbr_md": str(out_dir / mbr_name),
            "retail_mbr_latest_md": str(out_dir / "RETAIL_MBR.md"),
            "mbr_summary_md": str(out_dir / "MBR_SUMMARY.md"),
            "mbr_kpi_csv": str(csv_path),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        _safe_write_json(out_dir / "mbr_meta.json", meta)
        print(f"ok: retail mbr written for run_id={run_id}")
    except Exception as exc:
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(_redact(traceback.format_exc()), encoding="utf-8")
        _safe_write(
            out_dir / "RETAIL_MBR_ERROR.md",
            "\n".join(
                [
                    f"# Retail MBR Build Error — {run_id}",
                    "",
                    f"- error: `{exc}`",
                    f"- log: `{log_path}`",
                    "",
                ]
            ),
        )
        print(f"ok: retail mbr fallback wrote {out_dir / 'RETAIL_MBR_ERROR.md'}")


if __name__ == "__main__":
    main()
