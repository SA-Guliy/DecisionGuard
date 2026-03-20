#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from run_ab_analysis import (  # noqa: E402
    _assert_local_dsn,
    _assert_safe_dynamic_relation_name,
    _detect_assignment_source,
    _detect_order_source,
    _read_experiment_from_registry,
    _read_run_config,
    _resolve_dsn,
    _table_has_column,
)
from src.client_db_config import client_db_service


DEFAULT_SERVICE = client_db_service("app")


def _safe_write(path: Path, text_value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text_value, encoding="utf-8")


def _safe_write_json(path: Path, payload: dict[str, Any]) -> None:
    _safe_write(path, json.dumps(payload, ensure_ascii=False, indent=2))


def _quantile_breaks(values: list[float], probs: list[float]) -> list[float]:
    if not values:
        return []
    xs = sorted(values)
    out: list[float] = []
    for p in probs:
        if p <= 0:
            out.append(xs[0])
            continue
        if p >= 1:
            out.append(xs[-1])
            continue
        idx = p * (len(xs) - 1)
        lo = int(math.floor(idx))
        hi = int(math.ceil(idx))
        if lo == hi:
            out.append(xs[lo])
        else:
            w = idx - lo
            out.append(xs[lo] * (1.0 - w) + xs[hi] * w)
    return out


def _spend_bucket(gmv: float, q1: float, q2: float, q3: float) -> str:
    if gmv <= q1:
        return "Q1_low"
    if gmv <= q2:
        return "Q2_midlow"
    if gmv <= q3:
        return "Q3_midhigh"
    return "Q4_high"


def _frequency_bucket(orders_cnt: int) -> str:
    if orders_cnt <= 1:
        return "1"
    if orders_cnt <= 3:
        return "2_3"
    return "4_plus"


def _fmt_num(v: Any, nd: int = 4) -> str:
    try:
        return f"{float(v):.{nd}f}"
    except Exception:
        return "null"


def _aggregate_cut_rows(customer_rows: list[dict[str, Any]], dim_key: str) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"n_customers": 0, "orders_cnt_sum": 0.0, "gmv_sum": 0.0, "gp_sum": 0.0, "req_sum": 0.0, "ful_sum": 0.0}
    )
    for r in customer_rows:
        arm = str(r.get("arm", "")).strip()
        bucket = str(r.get(dim_key, "")).strip() or "unknown"
        if arm not in {"control", "treatment"}:
            continue
        s = buckets[(bucket, arm)]
        s["n_customers"] += 1
        s["orders_cnt_sum"] += float(r.get("orders_cnt", 0.0) or 0.0)
        s["gmv_sum"] += float(r.get("gmv", 0.0) or 0.0)
        s["gp_sum"] += float(r.get("gp", 0.0) or 0.0)
        s["req_sum"] += float(r.get("requested_units", 0.0) or 0.0)
        s["ful_sum"] += float(r.get("fulfilled_units", 0.0) or 0.0)

    out: list[dict[str, Any]] = []
    for (bucket, arm), s in sorted(buckets.items(), key=lambda x: (x[0][0], x[0][1])):
        n = int(s["n_customers"])
        out.append(
            {
                "bucket": bucket,
                "arm": arm,
                "n_customers": n,
                "mean_orders_cnt": (s["orders_cnt_sum"] / n) if n else None,
                "mean_gmv": (s["gmv_sum"] / n) if n else None,
                "mean_gp": (s["gp_sum"] / n) if n else None,
                "mean_aov_proxy": ((s["gmv_sum"] / s["orders_cnt_sum"]) if s["orders_cnt_sum"] > 0 else None),
                "fill_rate_units": ((s["ful_sum"] / s["req_sum"]) if s["req_sum"] > 0 else None),
                "gp_margin_proxy": ((s["gp_sum"] / s["gmv_sum"]) if s["gmv_sum"] > 0 else None),
            }
        )
    return out


def _cut_summary(rows: list[dict[str, Any]], metric: str = "mean_gmv") -> dict[str, Any]:
    by_bucket: dict[str, dict[str, float | None]] = defaultdict(dict)
    for r in rows:
        by_bucket[str(r.get("bucket", ""))][str(r.get("arm", ""))] = r.get(metric) if isinstance(r.get(metric), (int, float)) else None
    max_abs_delta_pct = None
    for _bucket, arms in by_bucket.items():
        c = arms.get("control")
        t = arms.get("treatment")
        if c is None or t is None:
            continue
        if float(c) == 0:
            continue
        d = abs((float(t) - float(c)) / float(c))
        max_abs_delta_pct = d if max_abs_delta_pct is None else max(max_abs_delta_pct, d)
    return {
        "buckets_with_both_arms": sum(1 for arms in by_bucket.values() if "control" in arms and "treatment" in arms),
        "max_abs_delta_pct_on_mean_gmv": max_abs_delta_pct,
    }


def _fetch_customer_window_rows(
    conn,
    *,
    run_id: str,
    experiment_id: str,
    orders_table: str,
    assignment_source: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    orders_table = _assert_safe_dynamic_relation_name(orders_table)
    assignment_source = _assert_safe_dynamic_relation_name(assignment_source)
    has_customer_col = _table_has_column(conn, orders_table, "customer_id")
    join_raw = ""
    customer_expr = "o.customer_id"
    provenance = {
        "orders_table": orders_table,
        "assignment_source": assignment_source,
        "customer_id_source": f"{orders_table}.customer_id" if has_customer_col else "raw.raw_orders_stream.customer_id",
        "used_raw_join_for_customer_id": (not has_customer_col),
    }
    if not has_customer_col:
        join_raw = (
            "JOIN raw.raw_orders_stream os "
            "ON os.order_id = o.order_id AND os.store_id = o.store_id AND os.date = o.date "
        )
        customer_expr = "os.customer_id"

    rows = conn.execute(
        text(
            f"""
            SELECT
              a.arm,
              {customer_expr}::text AS customer_id,
              COUNT(*)::bigint AS orders_cnt,
              SUM(o.order_gmv)::double precision AS gmv,
              SUM(o.order_gp)::double precision AS gp,
              SUM(o.requested_units)::double precision AS requested_units,
              SUM(o.fulfilled_units)::double precision AS fulfilled_units
            FROM {orders_table} o
            {join_raw}
            JOIN {assignment_source} a
              ON a.run_id = o.run_id
             AND a.experiment_id = :experiment_id
             AND a.unit_type = 'customer'
             AND a.unit_id = {customer_expr}
            WHERE o.run_id = :run_id
              AND o.experiment_id = :experiment_id
              AND {customer_expr} IS NOT NULL
            GROUP BY a.arm, {customer_expr}
            ORDER BY a.arm, {customer_expr}
            """
        ),
        {"run_id": run_id, "experiment_id": experiment_id},
    ).mappings().all()
    return [dict(r) for r in rows], provenance


def _build_payload(
    *,
    run_id: str,
    experiment_id: str,
    requested_unit: str,
    customer_rows: list[dict[str, Any]],
    query_provenance: dict[str, Any],
    notes: list[str],
) -> dict[str, Any]:
    gmv_values = [float(r.get("gmv", 0.0) or 0.0) for r in customer_rows]
    q1, q2, q3 = (_quantile_breaks(gmv_values, [0.25, 0.5, 0.75]) or [0.0, 0.0, 0.0])[:3]

    enriched_rows: list[dict[str, Any]] = []
    for r in customer_rows:
        gmv = float(r.get("gmv", 0.0) or 0.0)
        orders_cnt = int(r.get("orders_cnt", 0) or 0)
        rr = dict(r)
        rr["spend_bucket"] = _spend_bucket(gmv, q1, q2, q3)
        rr["frequency_bucket"] = _frequency_bucket(orders_cnt)
        rr["mean_order_value"] = (gmv / orders_cnt) if orders_cnt > 0 else None
        enriched_rows.append(rr)

    spend_rows = _aggregate_cut_rows(enriched_rows, "spend_bucket")
    freq_rows = _aggregate_cut_rows(enriched_rows, "frequency_bucket")
    cuts = [
        {
            "cut_name": "spend_bucket",
            "bucket_definition": "Experiment-window customer GMV quartiles (Q1-Q4) for this run/experiment",
            "rows": spend_rows,
            "summary": _cut_summary(spend_rows),
        },
        {
            "cut_name": "frequency_bucket",
            "bucket_definition": "Experiment-window orders per customer buckets: 1, 2-3, 4+",
            "rows": freq_rows,
            "summary": _cut_summary(freq_rows),
        },
    ]
    return {
        "run_id": run_id,
        "experiment_id": experiment_id,
        "requested_unit": requested_unit,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "READY" if cuts and any(c.get("rows") for c in cuts) else "BLOCKED_BY_DATA",
        "error_family": "NONE" if cuts and any(c.get("rows") for c in cuts) else "DATA_JOIN",
        "error_code": "NONE" if cuts and any(c.get("rows") for c in cuts) else "COHORT_CUSTOMER_GRAIN_EMPTY",
        "notes": notes,
        "query_provenance": query_provenance,
        "customer_window_stats": {
            "n_customers": len(enriched_rows),
            "arms": sorted(list({str(r.get('arm', '')) for r in enriched_rows if str(r.get('arm', '')).strip()})),
            "spend_quantiles_gmv": {"q25": q1, "q50": q2, "q75": q3},
        },
        "cuts": cuts,
        "version": "cohort_evidence_pack.v1",
    }


def _render_md(payload: dict[str, Any]) -> str:
    lines = [
        f"# Cohort Evidence Pack — {payload.get('run_id')} / {payload.get('experiment_id')}",
        "",
        f"- status: `{payload.get('status')}`",
        f"- error_family: `{payload.get('error_family')}`",
        f"- error_code: `{payload.get('error_code')}`",
        f"- requested_unit: `{payload.get('requested_unit')}`",
        f"- n_customers: `{((payload.get('customer_window_stats') or {}).get('n_customers'))}`",
        f"- customer_id_source: `{((payload.get('query_provenance') or {}).get('customer_id_source'))}`",
        f"- used_raw_join_for_customer_id: `{((payload.get('query_provenance') or {}).get('used_raw_join_for_customer_id'))}`",
        "",
    ]
    notes = payload.get("notes", [])
    if isinstance(notes, list) and notes:
        lines.append("## Notes")
        for n in notes[:8]:
            lines.append(f"- {n}")
        lines.append("")
    for cut in payload.get("cuts", []) if isinstance(payload.get("cuts"), list) else []:
        if not isinstance(cut, dict):
            continue
        lines.append(f"## Cut: {cut.get('cut_name')}")
        lines.append(f"- definition: {cut.get('bucket_definition')}")
        s = cut.get("summary", {}) if isinstance(cut.get("summary"), dict) else {}
        lines.append(f"- buckets_with_both_arms: `{s.get('buckets_with_both_arms')}`")
        lines.append(f"- max_abs_delta_pct_on_mean_gmv: `{_fmt_num(s.get('max_abs_delta_pct_on_mean_gmv'))}`")
        lines.append("")
        lines.append("| bucket | arm | n_customers | mean_orders_cnt | mean_gmv | mean_aov_proxy | fill_rate_units | gp_margin_proxy |")
        lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
        rows = cut.get("rows", []) if isinstance(cut.get("rows"), list) else []
        if not rows:
            lines.append("| none | none | 0 | null | null | null | null | null |")
        for r in rows[:40]:
            if not isinstance(r, dict):
                continue
            lines.append(
                "| {bucket} | {arm} | {n_customers} | {mean_orders_cnt} | {mean_gmv} | {mean_aov_proxy} | {fill_rate_units} | {gp_margin_proxy} |".format(
                    bucket=str(r.get("bucket", "")),
                    arm=str(r.get("arm", "")),
                    n_customers=str(r.get("n_customers", "")),
                    mean_orders_cnt=_fmt_num(r.get("mean_orders_cnt")),
                    mean_gmv=_fmt_num(r.get("mean_gmv")),
                    mean_aov_proxy=_fmt_num(r.get("mean_aov_proxy")),
                    fill_rate_units=_fmt_num(r.get("fill_rate_units")),
                    gp_margin_proxy=_fmt_num(r.get("gp_margin_proxy")),
                )
            )
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build cohort evidence pack (customer spend/frequency cohorts) in read-only mode")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--pgservice", default=DEFAULT_SERVICE)
    args = parser.parse_args()

    run_id = args.run_id
    dsn = _resolve_dsn(args.pgservice)
    _assert_local_dsn(dsn)
    log_path = Path(f"data/logs/build_cohort_evidence_pack_{run_id}.log")
    out_json = Path(f"reports/L1_ops/{run_id}/cohort_evidence_pack.json")
    out_md = Path(f"reports/L1_ops/{run_id}/cohort_evidence_pack.md")

    try:
        engine = create_engine(dsn)
        with engine.begin() as conn:
            conn.execute(text("SET LOCAL statement_timeout = '20s';"))
            conn.execute(text("SET TRANSACTION READ ONLY;"))
            exp_id = str(args.experiment_id or "").strip()
            reg_exp_id, reg_unit = (None, None)
            if not exp_id:
                reg_exp_id, reg_unit = _read_experiment_from_registry(conn, run_id)
            run_cfg = _read_run_config(conn, run_id)
            if not exp_id:
                exp_id = reg_exp_id or ""
            requested_unit = str(reg_unit or run_cfg.get("experiment_unit") or "customer").strip().lower()
            if not exp_id:
                payload = {
                    "run_id": run_id,
                    "experiment_id": "missing",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "status": "BLOCKED_BY_DATA",
                    "error_family": "CONTRACT",
                    "error_code": "CONTRACT_EXPERIMENT_ID_MISSING",
                    "requested_unit": requested_unit,
                    "notes": ["experiment_id missing; cannot build cohort evidence pack"],
                    "cuts": [],
                    "version": "cohort_evidence_pack.v1",
                }
                _safe_write_json(out_json, payload)
                _safe_write(out_md, _render_md(payload) + "\n")
                print(f"ok: cohort evidence pack written for run_id={run_id}")
                return
            if requested_unit != "customer":
                payload = {
                    "run_id": run_id,
                    "experiment_id": exp_id,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "status": "BLOCKED_BY_DATA",
                    "error_family": "METHOD",
                    "error_code": "COHORT_PACK_REQUIRES_CUSTOMER_UNIT",
                    "requested_unit": requested_unit,
                    "notes": ["Current cohort evidence pack v1 supports only customer-randomized experiments."],
                    "cuts": [],
                    "version": "cohort_evidence_pack.v1",
                }
                _safe_write_json(out_json, payload)
                _safe_write(out_md, _render_md(payload) + "\n")
                print(f"ok: cohort evidence pack written for run_id={run_id}")
                return

            orders_table = _detect_order_source(conn)
            assignment_source = _detect_assignment_source(conn)
            notes: list[str] = []
            customer_rows, provenance = _fetch_customer_window_rows(
                conn,
                run_id=run_id,
                experiment_id=exp_id,
                orders_table=orders_table,
                assignment_source=assignment_source,
            )
            if not customer_rows:
                notes.append("No customer rows produced after assignment join.")
            payload = _build_payload(
                run_id=run_id,
                experiment_id=exp_id,
                requested_unit=requested_unit,
                customer_rows=customer_rows,
                query_provenance=provenance,
                notes=notes,
            )
            _safe_write_json(out_json, payload)
            _safe_write(out_md, _render_md(payload) + "\n")
            print(f"ok: cohort evidence pack written for run_id={run_id}")
    except Exception as exc:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(f"{exc}\n{traceback.format_exc()}", encoding="utf-8")
        payload = {
            "run_id": run_id,
            "experiment_id": str(args.experiment_id or "unknown"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "FAIL",
            "error_family": "RUNTIME",
            "error_code": "COHORT_EVIDENCE_PACK_RUNTIME_ERROR",
            "requested_unit": "unknown",
            "notes": [f"See log: {log_path}"],
            "cuts": [],
            "version": "cohort_evidence_pack.v1",
        }
        _safe_write_json(out_json, payload)
        _safe_write(out_md, _render_md(payload) + "\n")
        print(f"ok: cohort evidence pack written for run_id={run_id} (fallback)")


if __name__ == "__main__":
    main()
