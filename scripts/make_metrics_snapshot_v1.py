#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import traceback

from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.client_db_config import client_db_service, resolve_pg_url
from src.domain_template import ConfigurationError, domain_data_mapping_rules, set_domain_template_override
from src.security_utils import enforce_service_dsn_policy, redact_text, write_sha256_sidecar
SOURCE_SET_VIEWS = {
    "orders": "step1.vw_valid_orders",
    "items": "step1.vw_valid_order_items",
    "daily": "step1.vw_valid_customer_daily",
}
SOURCE_SET_BASE = {
    "orders": "step1.step1_orders",
    "items": "step1.step1_order_items",
    "daily": "step1.step1_customer_daily",
}
ALLOWED_SOURCES = {tuple(sorted(SOURCE_SET_VIEWS.items())), tuple(sorted(SOURCE_SET_BASE.items()))}
REALISM_TARGETS = {
    "fill_rate_mean_target_min": 0.93,
    "fill_rate_mean_target_max": 0.97,
    "fill_rate_p95_max": 0.99,
}


def _assert_local_dsn(pg_url: str) -> None:
    if os.getenv("ALLOW_NONLOCALHOST", "0") == "1":
        return
    if "service=" in pg_url:
        return
    if "@localhost" in pg_url or "@127.0.0.1" in pg_url or "@::1" in pg_url:
        return
    raise SystemExit("Refusing non-localhost DSN. Set ALLOW_NONLOCALHOST=1 to override.")


def _get_engine(pg_url: str):
    return create_engine(pg_url)


def _resolve_pg_url(arg_pg_url: str | None) -> str:
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        enforce_service_dsn_policy(database_url, "DATABASE_URL")
    service = os.getenv("PGSERVICE")
    pg_url = os.getenv("PG_DSN") or arg_pg_url or database_url
    if not pg_url and service:
        pg_url = f"postgresql:///?service={service}"
    if not pg_url:
        pg_url = resolve_pg_url(role="app", fallback_service=client_db_service("app"))
    enforce_service_dsn_policy(pg_url, "PG_DSN/DATABASE_URL/--pg-url")
    return pg_url


def _detect_sources(conn) -> dict[str, str]:
    exists = {k: conn.execute(text("SELECT to_regclass(:n)"), {"n": v}).scalar() is not None for k, v in SOURCE_SET_VIEWS.items()}
    if all(exists.values()):
        return SOURCE_SET_VIEWS
    return SOURCE_SET_BASE


def _assert_allowed_sources(sources: dict[str, str]) -> None:
    if tuple(sorted(sources.items())) not in ALLOWED_SOURCES:
        raise RuntimeError("Unexpected source table set")


def _is_view_sources(sources: dict[str, str]) -> bool:
    return sources["orders"].startswith("step1.vw_")


_COLUMN_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]*$")
_RELATION_RE = re.compile(r"^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$")


def _load_mapping_rules(domain_template_path: str) -> tuple[dict[str, Any], str]:
    set_domain_template_override(domain_template_path)
    rules = domain_data_mapping_rules(domain_template_path)
    if not rules:
        raise ConfigurationError("Missing Domain Template data_mapping_rules")
    if bool(rules.get("forbid_implicit_fallback")) is not True:
        raise ConfigurationError("Domain Template data_mapping_rules.forbid_implicit_fallback must be true")
    if str(rules.get("on_mismatch_action", "")).strip().upper() != "HOLD_NEED_DATA":
        raise ConfigurationError("Domain Template data_mapping_rules.on_mismatch_action must be HOLD_NEED_DATA")
    reason_col = str(rules.get("writeoff_reason_column", "")).strip()
    if not _COLUMN_NAME_RE.fullmatch(reason_col):
        raise ConfigurationError("Domain Template data_mapping_rules.writeoff_reason_column is invalid")
    required_sources = rules.get("required_sources")
    if not isinstance(required_sources, dict) or not required_sources:
        raise ConfigurationError("Domain Template data_mapping_rules.required_sources is missing")
    return rules, reason_col


def _list_relation_columns(conn, relation: str) -> set[str]:
    if not _RELATION_RE.fullmatch(relation):
        raise RuntimeError(f"HOLD_NEED_DATA:data_mapping_mismatch:invalid_relation:{relation}")
    schema_name, table_name = relation.split(".", 1)
    rows = conn.execute(
        text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = :schema_name
              AND table_name = :table_name
            """
        ),
        {"schema_name": schema_name, "table_name": table_name},
    ).scalars().all()
    return {str(x).strip() for x in rows if str(x).strip()}


def _assert_mapping_alignment(conn, rules: dict[str, Any]) -> None:
    required_sources = rules.get("required_sources") if isinstance(rules.get("required_sources"), dict) else {}
    if not required_sources:
        raise RuntimeError("HOLD_NEED_DATA:data_mapping_mismatch:required_sources_missing")
    for relation, cfg in required_sources.items():
        rel = str(relation).strip()
        if not rel:
            continue
        if not isinstance(cfg, dict):
            raise RuntimeError(f"HOLD_NEED_DATA:data_mapping_mismatch:invalid_source_config:{rel}")
        columns = _list_relation_columns(conn, rel)
        if not columns:
            raise RuntimeError(f"HOLD_NEED_DATA:data_mapping_mismatch:missing_relation:{rel}")
        required_cols = [str(x).strip() for x in cfg.get("required_columns", []) if str(x).strip()]
        missing = sorted(c for c in required_cols if c not in columns)
        if missing:
            raise RuntimeError(
                f"HOLD_NEED_DATA:data_mapping_mismatch:missing_columns:{rel}:{','.join(missing[:10])}"
            )
        enforce_allowed = bool(cfg.get("enforce_allowed_columns", False))
        allowed_cols = {str(x).strip() for x in cfg.get("allowed_columns", []) if str(x).strip()}
        if enforce_allowed and allowed_cols:
            unexpected = sorted(c for c in columns if c not in allowed_cols)
            if unexpected:
                raise RuntimeError(
                    f"HOLD_NEED_DATA:data_mapping_mismatch:unexpected_columns:{rel}:{','.join(unexpected[:10])}"
                )


def _to_iso_week(value: Any) -> str:
    if value is None:
        return ""
    try:
        dt = value if hasattr(value, "isocalendar") else None
        if dt is None:
            return str(value)
        iso = dt.isocalendar()
        return f"{iso.year}-W{iso.week:02d}"
    except Exception:
        return str(value)


def _realism_score_and_hint(fill_rate_mean: float | None, fill_rate_p95: float | None) -> tuple[float | None, str]:
    if fill_rate_mean is None or fill_rate_p95 is None:
        return None, "insufficient metrics for realism recommendation"

    mean_min = REALISM_TARGETS["fill_rate_mean_target_min"]
    mean_max = REALISM_TARGETS["fill_rate_mean_target_max"]
    p95_max = REALISM_TARGETS["fill_rate_p95_max"]

    penalty = 0.0
    if fill_rate_mean > mean_max:
        penalty += min(1.0, (fill_rate_mean - mean_max) / 0.05)
    elif fill_rate_mean < mean_min:
        penalty += min(1.0, (mean_min - fill_rate_mean) / 0.05)
    if fill_rate_p95 > p95_max:
        penalty += min(1.0, (fill_rate_p95 - p95_max) / 0.03)

    score = max(0.0, 1.0 - penalty)
    if fill_rate_mean > mean_max:
        recommendation = "decrease capacity_mult by 0.03 or supplier_fill_rate by 0.02"
    elif fill_rate_mean < mean_min:
        recommendation = "increase capacity_mult by 0.03 or supplier_fill_rate by 0.02"
    elif fill_rate_p95 > p95_max:
        recommendation = "reduce shock_mult_range upper or shock_prob slightly"
    else:
        recommendation = "realism within target range; keep defaults"
    return score, recommendation


def _build_metrics(conn, run_id: str, sources: dict[str, str], *, writeoff_reason_column: str) -> dict[str, Any]:
    def _r2(v: Any) -> float | None:
        try:
            return round(float(v), 2)
        except Exception:
            return None

    def _r5(v: Any) -> float | None:
        try:
            return round(float(v), 5)
        except Exception:
            return None

    orders = sources["orders"]
    items = sources["items"]
    daily = sources["daily"]
    use_views = _is_view_sources(sources)

    totals = conn.execute(
        text(
            f"""
            SELECT
              COUNT(*)::bigint AS orders_cnt,
              COALESCE(SUM(order_gmv),0)::double precision AS gmv,
              COALESCE(SUM(order_gp),0)::double precision AS gp,
              COALESCE(SUM(requested_units),0)::bigint AS requested_units,
              COALESCE(SUM(fulfilled_units),0)::bigint AS fulfilled_units,
              COALESCE(SUM(order_lost_gmv_oos),0)::double precision AS lost_gmv_oos
            FROM {orders}
            WHERE run_id = :run_id
            """
        ),
        {"run_id": run_id},
    ).mappings().first()

    if totals is None:
        raise RuntimeError("Failed to compute totals")

    orders_cnt = int(totals["orders_cnt"])
    gmv = float(totals["gmv"])
    gp = float(totals["gp"])
    requested_units = int(totals["requested_units"])
    fulfilled_units = int(totals["fulfilled_units"])
    lost_gmv_oos = float(totals["lost_gmv_oos"])

    gp_margin = (gp / gmv) if gmv > 0 else None
    aov = (gmv / orders_cnt) if orders_cnt > 0 else None
    gp_per_order = (gp / orders_cnt) if orders_cnt > 0 else None
    fill_rate_units = (fulfilled_units / requested_units) if requested_units > 0 else None
    oos_lost_gmv_rate = (lost_gmv_oos / gmv) if gmv > 0 else None
    fill_dist_row = conn.execute(
        text(
            f"""
            SELECT
              AVG(order_fill_rate_units)::double precision AS fill_rate_mean,
              STDDEV_SAMP(order_fill_rate_units)::double precision AS fill_rate_stddev,
              PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY order_fill_rate_units) AS fill_rate_p50,
              PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY order_fill_rate_units) AS fill_rate_p95,
              STDDEV_SAMP(order_gmv)::double precision AS aov_stddev
            FROM {orders}
            WHERE run_id = :run_id
            """
        ),
        {"run_id": run_id},
    ).mappings().first()
    fill_rate_mean = float(fill_dist_row["fill_rate_mean"]) if fill_dist_row and fill_dist_row["fill_rate_mean"] is not None else None
    fill_rate_stddev = float(fill_dist_row["fill_rate_stddev"]) if fill_dist_row and fill_dist_row["fill_rate_stddev"] is not None else None
    fill_rate_p50 = float(fill_dist_row["fill_rate_p50"]) if fill_dist_row and fill_dist_row["fill_rate_p50"] is not None else None
    fill_rate_p95 = float(fill_dist_row["fill_rate_p95"]) if fill_dist_row and fill_dist_row["fill_rate_p95"] is not None else None
    aov_stddev = float(fill_dist_row["aov_stddev"]) if fill_dist_row and fill_dist_row["aov_stddev"] is not None else None

    new_buyers_7d = conn.execute(
        text(
            f"""
            WITH ordered AS (
              SELECT o.order_id, o.date, os.customer_id
              FROM {orders} o
              JOIN raw.raw_orders_stream os ON os.order_id = o.order_id
              WHERE o.run_id = :run_id
            ), bounds AS (
              SELECT MIN(date) AS start_date FROM ordered
            ), first_buy AS (
              SELECT customer_id, MIN(date) AS first_date FROM ordered GROUP BY customer_id
            )
            SELECT COUNT(*)::bigint AS new_buyers_7d
            FROM first_buy, bounds
            WHERE bounds.start_date IS NOT NULL
              AND first_date BETWEEN bounds.start_date AND (bounds.start_date + INTERVAL '6 day')
            """
        ),
        {"run_id": run_id},
    ).scalar()

    notes: list[str] = []
    customer_metrics: dict[str, Any] = {
        "active_buyers_avg": None,
        "churn_rate": None,
        "rep_mean": None,
        "churn_prob_mean": None,
    }
    try:
        daily_row = conn.execute(
            text(
                f"""
                SELECT
                  AVG(active_cnt)::double precision AS active_buyers_avg,
                  CASE WHEN SUM(active_cnt) > 0
                       THEN SUM(churned_today)::double precision / SUM(active_cnt)
                       ELSE NULL END AS churn_rate,
                  AVG(rep)::double precision AS rep_mean,
                  AVG(churn_prob)::double precision AS churn_prob_mean
                FROM {daily}
                WHERE run_id = :run_id
                """
            ),
            {"run_id": run_id},
        ).mappings().first()
        if daily_row:
            customer_metrics = {
                "active_buyers_avg": float(daily_row["active_buyers_avg"]) if daily_row["active_buyers_avg"] is not None else None,
                "churn_rate": float(daily_row["churn_rate"]) if daily_row["churn_rate"] is not None else None,
                "rep_mean": float(daily_row["rep_mean"]) if daily_row["rep_mean"] is not None else None,
                "churn_prob_mean": float(daily_row["churn_prob_mean"]) if daily_row["churn_prob_mean"] is not None else None,
            }
    except Exception as exc:
        notes.append(f"customer_daily_metrics_unavailable: {exc.__class__.__name__}")

    perishable = conn.execute(
        text(
            f"""
            SELECT
              CASE WHEN SUM(ful_gmv) > 0
                   THEN SUM(CASE WHEN p.is_perishable = 1 THEN ful_gmv ELSE 0 END) / SUM(ful_gmv)
                   ELSE NULL END AS perishable_gmv_share
            FROM (
              SELECT
                i.product_id,
                {('i.calc_line_gmv_fulfilled' if use_views else 'i.line_gmv_fulfilled')}::double precision AS ful_gmv
              FROM {items} i
              WHERE i.run_id = :run_id
            ) x
            JOIN raw.raw_products p ON p.product_id = x.product_id
            """
        ),
        {"run_id": run_id},
    ).scalar()

    writeoff_row = conn.execute(
        text(
            """
            SELECT
              COALESCE(SUM(qty_writeoff),0)::double precision AS writeoff_units,
              COALESCE(SUM(writeoff_cogs),0)::double precision AS writeoff_cogs
            FROM step1.step1_writeoff_log
            WHERE run_id = :run_id
            """
        ),
        {"run_id": run_id},
    ).mappings().first()
    writeoff_units = float(writeoff_row["writeoff_units"]) if writeoff_row else 0.0
    writeoff_cogs = float(writeoff_row["writeoff_cogs"]) if writeoff_row else 0.0
    writeoff_rate_vs_requested_units = (writeoff_units / requested_units) if requested_units > 0 else None
    sold_cogs = conn.execute(
        text(
            """
            SELECT COALESCE(SUM(fulfilled_qty * unit_cogs),0)::double precision
            FROM step1.step1_order_items
            WHERE run_id = :run_id
            """
        ),
        {"run_id": run_id},
    ).scalar()
    sold_cogs = float(sold_cogs or 0.0)
    received_cogs = conn.execute(
        text(
            """
            SELECT COALESCE(SUM(r.qty_added * p.unit_cogs),0)::double precision
            FROM step1.step1_replenishment_log r
            JOIN raw.raw_products p ON p.product_id = r.product_id
            WHERE r.run_id = :run_id
            """
        ),
        {"run_id": run_id},
    ).scalar()
    received_cogs = float(received_cogs or 0.0)

    reason_expr = writeoff_reason_column
    expiry_writeoff_cogs = conn.execute(
        text(
            f"""
            SELECT COALESCE(SUM(writeoff_cogs),0)::double precision
            FROM step1.step1_writeoff_log
            WHERE run_id = :run_id
              AND LOWER(COALESCE({reason_expr}, '')) IN ('expiry','pull_before_expiry','expired')
            """
        ),
        {"run_id": run_id},
    ).scalar()
    expiry_writeoff_cogs = float(expiry_writeoff_cogs or 0.0)
    expiry_waste_rate_cogs = (expiry_writeoff_cogs / received_cogs) if received_cogs > 0 else None

    competitor_row = conn.execute(
        text(
            """
            SELECT
              AVG(competitor_price_index)::double precision AS competitor_index_mean,
              AVG(promo_flag)::double precision AS competitor_promo_share
            FROM step1.step1_competitor_daily
            WHERE run_id = :run_id
            """
        ),
        {"run_id": run_id},
    ).mappings().first()
    competitor_index_mean = (
        float(competitor_row["competitor_index_mean"])
        if competitor_row and competitor_row["competitor_index_mean"] is not None
        else None
    )
    competitor_promo_share = (
        float(competitor_row["competitor_promo_share"])
        if competitor_row and competitor_row["competitor_promo_share"] is not None
        else None
    )

    supplier_fill_rate_mean = None
    replen_capacity_mult_mean = None
    leadtime_days_mean = None
    try:
        supply_row = conn.execute(
            text(
                """
                SELECT
                  AVG(supplier_fill_rate)::double precision AS supplier_fill_rate_mean,
                  AVG(capacity_mult)::double precision AS replen_capacity_mult_mean,
                  AVG(leadtime_days)::double precision AS leadtime_days_mean
                FROM step1.step1_supply_daily
                WHERE run_id = :run_id
                """
            ),
            {"run_id": run_id},
        ).mappings().first()
        if supply_row:
            supplier_fill_rate_mean = (
                float(supply_row["supplier_fill_rate_mean"]) if supply_row["supplier_fill_rate_mean"] is not None else None
            )
            replen_capacity_mult_mean = (
                float(supply_row["replen_capacity_mult_mean"]) if supply_row["replen_capacity_mult_mean"] is not None else None
            )
            leadtime_days_mean = float(supply_row["leadtime_days_mean"]) if supply_row["leadtime_days_mean"] is not None else None
    except Exception as exc:
        notes.append(f"supply_realism_metrics_unavailable: {exc.__class__.__name__}")

    shrink_units_rate = None
    try:
        ops_shrink_units = conn.execute(
            text(
                """
                SELECT COALESCE(SUM(shrink_units),0)::double precision
                FROM step1.step1_ops_daily
                WHERE run_id = :run_id
                """
            ),
            {"run_id": run_id},
        ).scalar()
        if requested_units > 0:
            shrink_units_rate = float(ops_shrink_units or 0.0) / float(requested_units)
    except Exception as exc:
        notes.append(f"ops_realism_metrics_unavailable: {exc.__class__.__name__}")

    shock_days_share = None
    try:
        shock_days_share = conn.execute(
            text(
                """
                SELECT AVG(is_shock::double precision)
                FROM step1.step1_demand_shocks_daily
                WHERE run_id = :run_id
                """
            ),
            {"run_id": run_id},
        ).scalar()
        if shock_days_share is not None:
            shock_days_share = float(shock_days_share)
    except Exception as exc:
        notes.append(f"demand_shock_metrics_unavailable: {exc.__class__.__name__}")

    # Keep business KPIs compact (2 decimals) and statistical diagnostics at 5 decimals.
    return {
        "orders_cnt": orders_cnt,
        "gmv": _r2(gmv),
        "gp": _r2(gp),
        "gp_margin": _r2(gp_margin),
        "aov": _r2(aov),
        "gp_per_order": _r2(gp_per_order),
        "requested_units": requested_units,
        "fulfilled_units": fulfilled_units,
        "fill_rate_units": _r2(fill_rate_units),
        "fill_rate_mean": _r5(fill_rate_mean),
        "fill_rate_stddev": _r5(fill_rate_stddev),
        "fill_rate_p50": _r5(fill_rate_p50),
        "fill_rate_p95": _r5(fill_rate_p95),
        "aov_stddev": _r5(aov_stddev),
        "lost_gmv_oos": _r2(lost_gmv_oos),
        "oos_lost_gmv_rate": _r2(oos_lost_gmv_rate),
        "new_buyers_7d": int(new_buyers_7d or 0),
        "active_buyers_avg": _r2(customer_metrics["active_buyers_avg"]),
        "churn_rate": _r2(customer_metrics["churn_rate"]),
        "rep_mean": _r2(customer_metrics["rep_mean"]),
        "churn_prob_mean": _r5(customer_metrics["churn_prob_mean"]),
        "perishable_gmv_share": _r2(float(perishable) if perishable is not None else None),
        "writeoff_units": _r2(writeoff_units),
        "writeoff_cogs": _r2(writeoff_cogs),
        "received_cogs": _r2(received_cogs),
        "sold_cogs": _r2(sold_cogs),
        "expiry_writeoff_cogs": _r2(expiry_writeoff_cogs),
        "expiry_waste_rate_cogs": _r5(expiry_waste_rate_cogs),
        "writeoff_rate_vs_requested_units": _r2(writeoff_rate_vs_requested_units),
        "competitor_index_mean": _r5(competitor_index_mean),
        "competitor_promo_share": _r5(competitor_promo_share),
        "supplier_fill_rate_mean": _r5(supplier_fill_rate_mean),
        "replen_capacity_mult_mean": _r5(replen_capacity_mult_mean),
        "leadtime_days_mean": _r5(leadtime_days_mean),
        "shrink_units_rate": _r5(shrink_units_rate),
        "shock_days_share": _r5(shock_days_share),
        "_notes": notes,
    }


def _compute_goal1_contract_completeness(
    conn,
    run_id: str,
    metrics: dict[str, Any],
    *,
    writeoff_reason_column: str,
) -> dict[str, Any]:
    reason_expr = writeoff_reason_column

    writeoff_cov = conn.execute(
        text(
            f"""
            SELECT
              COUNT(*)::bigint AS total_rows,
              AVG(CASE WHEN {reason_expr} IS NOT NULL AND BTRIM({reason_expr}) <> '' THEN 1.0 ELSE 0.0 END)::double precision AS reason_cov,
              AVG(CASE WHEN lot_expiry_date IS NOT NULL THEN 1.0 ELSE 0.0 END)::double precision AS expiry_cov,
              AVG(CASE WHEN batch_id IS NOT NULL AND BTRIM(batch_id) <> '' THEN 1.0 ELSE 0.0 END)::double precision AS batch_cov
            FROM step1.step1_writeoff_log
            WHERE run_id = :run_id
            """
        ),
        {"run_id": run_id},
    ).mappings().first()
    total_rows = int(writeoff_cov["total_rows"]) if writeoff_cov and writeoff_cov["total_rows"] is not None else 0
    reason_cov = float(writeoff_cov["reason_cov"]) if writeoff_cov and writeoff_cov["reason_cov"] is not None else 0.0
    expiry_cov = float(writeoff_cov["expiry_cov"]) if writeoff_cov and writeoff_cov["expiry_cov"] is not None else 0.0
    batch_cov = float(writeoff_cov["batch_cov"]) if writeoff_cov and writeoff_cov["batch_cov"] is not None else 0.0

    required_non_negative = [
        float(metrics.get("writeoff_units") or 0.0),
        float(metrics.get("writeoff_cogs") or 0.0),
        float(metrics.get("received_cogs") or 0.0),
        float(metrics.get("sold_cogs") or 0.0),
    ]
    non_negative_pass = all(v >= 0.0 for v in required_non_negative)
    reason_pass = reason_cov >= 0.99 if total_rows > 0 else False
    expiry_pass = expiry_cov >= 0.99 if total_rows > 0 else False
    batch_pass = batch_cov >= 0.95 if total_rows > 0 else False

    checks = {
        "writeoff_reason_coverage": {"value": round(reason_cov, 5), "threshold": 0.99, "status": "PASS" if reason_pass else "FAIL"},
        "expiry_date_coverage": {"value": round(expiry_cov, 5), "threshold": 0.99, "status": "PASS" if expiry_pass else "FAIL"},
        "batch_join_coverage": {"value": round(batch_cov, 5), "threshold": 0.95, "status": "PASS" if batch_pass else "FAIL"},
        "non_negative_checks": {"status": "PASS" if non_negative_pass else "FAIL"},
    }
    missing_fields: list[str] = []
    if not batch_pass:
        missing_fields.append("batch_id")
    if not reason_pass:
        missing_fields.append("writeoff_reason")
    if not expiry_pass:
        missing_fields.append("expiry_date")

    return {
        "goal1_contract_ready": bool(reason_pass and expiry_pass and batch_pass and non_negative_pass),
        "checks": checks,
        "missing_or_weak_fields": missing_fields,
        "writeoff_rows": total_rows,
        "required_fields": [
            "store_id",
            "product_id",
            "date",
            "received_units",
            "received_cogs",
            "sold_units",
            "sold_cogs",
            "writeoff_units",
            "writeoff_cogs",
            "writeoff_reason",
            "expiry_date",
            "batch_id",
        ],
        "preferred_fields": ["supplier_id", "purchase_order_id", "category_id"],
    }


def _build_goal1_store_week_category(conn, run_id: str, *, writeoff_reason_column: str) -> list[dict[str, Any]]:
    reason_expr = f"w.{writeoff_reason_column}"
    rows = conn.execute(
        text(
            f"""
            WITH repl AS (
              SELECT
                DATE_TRUNC('week', r.date)::date AS week_start,
                r.store_id,
                p.category_id,
                COALESCE(SUM(r.qty_added),0)::double precision AS received_units,
                COALESCE(SUM(r.qty_added * p.unit_cogs),0)::double precision AS received_cogs
              FROM step1.step1_replenishment_log r
              JOIN raw.raw_products p ON p.product_id = r.product_id
              WHERE r.run_id = :run_id
              GROUP BY 1,2,3
            ),
            sold AS (
              SELECT
                DATE_TRUNC('week', i.date)::date AS week_start,
                i.store_id,
                i.category_id,
                COALESCE(SUM(i.fulfilled_qty),0)::double precision AS sold_units,
                COALESCE(SUM(i.fulfilled_qty * i.unit_cogs),0)::double precision AS sold_cogs
              FROM step1.step1_order_items i
              WHERE i.run_id = :run_id
              GROUP BY 1,2,3
            ),
            wr AS (
              SELECT
                DATE_TRUNC('week', w.date)::date AS week_start,
                w.store_id,
                p.category_id,
                COALESCE(SUM(w.qty_writeoff),0)::double precision AS writeoff_units,
                COALESCE(SUM(w.writeoff_cogs),0)::double precision AS writeoff_cogs,
                COALESCE(SUM(CASE WHEN LOWER(COALESCE({reason_expr}, '')) IN ('expiry','pull_before_expiry','expired') THEN w.writeoff_cogs ELSE 0 END),0)::double precision AS expiry_writeoff_cogs
              FROM step1.step1_writeoff_log w
              JOIN raw.raw_products p ON p.product_id = w.product_id
              WHERE w.run_id = :run_id
              GROUP BY 1,2,3
            )
            SELECT
              COALESCE(r.week_start, s.week_start, w.week_start) AS week_start,
              COALESCE(r.store_id, s.store_id, w.store_id) AS store_id,
              COALESCE(r.category_id, s.category_id, w.category_id) AS category_id,
              COALESCE(r.received_units,0)::double precision AS received_units,
              COALESCE(r.received_cogs,0)::double precision AS received_cogs,
              COALESCE(s.sold_units,0)::double precision AS sold_units,
              COALESCE(s.sold_cogs,0)::double precision AS sold_cogs,
              COALESCE(w.writeoff_units,0)::double precision AS writeoff_units,
              COALESCE(w.writeoff_cogs,0)::double precision AS writeoff_cogs,
              COALESCE(w.expiry_writeoff_cogs,0)::double precision AS expiry_writeoff_cogs
            FROM repl r
            FULL OUTER JOIN sold s
              ON s.week_start = r.week_start AND s.store_id = r.store_id AND s.category_id = r.category_id
            FULL OUTER JOIN wr w
              ON w.week_start = COALESCE(r.week_start, s.week_start)
             AND w.store_id = COALESCE(r.store_id, s.store_id)
             AND w.category_id = COALESCE(r.category_id, s.category_id)
            ORDER BY 1,2,3
            """
        ),
        {"run_id": run_id},
    ).mappings().all()
    out: list[dict[str, Any]] = []
    for r in rows:
        received_cogs = float(r["received_cogs"] or 0.0)
        expiry_writeoff_cogs = float(r["expiry_writeoff_cogs"] or 0.0)
        out.append(
            {
                "iso_week": _to_iso_week(r["week_start"]),
                "week_start": str(r["week_start"]),
                "store_id": str(r["store_id"]),
                "category_id": str(r["category_id"]),
                "received_units": round(float(r["received_units"] or 0.0), 2),
                "received_cogs": round(received_cogs, 2),
                "sold_units": round(float(r["sold_units"] or 0.0), 2),
                "sold_cogs": round(float(r["sold_cogs"] or 0.0), 2),
                "writeoff_units": round(float(r["writeoff_units"] or 0.0), 2),
                "writeoff_cogs": round(float(r["writeoff_cogs"] or 0.0), 2),
                "expiry_writeoff_cogs": round(expiry_writeoff_cogs, 2),
                "expiry_waste_rate_cogs": round((expiry_writeoff_cogs / received_cogs), 5) if received_cogs > 0 else None,
            }
        )
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Build metrics snapshot v1 for a run_id")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--pg-url", default=None, help="DB URL or service-based connection (no password in args)")
    parser.add_argument("--domain-template", default="", help="Path to domain template JSON")
    args = parser.parse_args()

    try:
        mapping_rules, writeoff_reason_column = _load_mapping_rules(args.domain_template)
    except ConfigurationError as exc:
        raise SystemExit(f"ConfigurationError: {exc}")

    pg_url = _resolve_pg_url(args.pg_url)
    _assert_local_dsn(pg_url)

    log_path = Path(f"data/logs/metrics_snapshot_{args.run_id}.log")
    try:
        engine = _get_engine(pg_url)
        with engine.begin() as conn:
            conn.execute(text("SET LOCAL statement_timeout = '15s';"))
            conn.execute(text("SET LOCAL idle_in_transaction_session_timeout = '15s';"))
            conn.execute(text("SET TRANSACTION READ ONLY;"))

            _assert_mapping_alignment(conn, mapping_rules)
            sources = _detect_sources(conn)
            _assert_allowed_sources(sources)
            metrics = _build_metrics(conn, args.run_id, sources, writeoff_reason_column=writeoff_reason_column)
            run_cfg_row = conn.execute(
                text(
                    """
                    SELECT
                      mode_tag,
                      config_json AS config_json,
                      config_json->>'assignment_status' AS assignment_status,
                      config_json->>'experiment_id' AS experiment_id,
                      config_json->>'experiment_unit' AS experiment_unit,
                      config_json->>'experiment_treat_pct' AS experiment_treat_pct,
                      config_json->>'experiment_salt' AS experiment_salt,
                      config_json->>'enable_supply_realism' AS enable_supply_realism,
                      config_json->>'enable_ops_noise' AS enable_ops_noise,
                      config_json->>'enable_demand_shocks' AS enable_demand_shocks,
                      config_json->>'enable_competitor_prices' AS enable_competitor_prices,
                      config_json->>'competitor_reactive_mode' AS competitor_reactive_mode,
                      config_json->>'replenishment_leadtime_days' AS replenishment_leadtime_days,
                      config_json->>'replenishment_capacity_mult' AS replenishment_capacity_mult,
                      config_json->>'supplier_fill_rate' AS supplier_fill_rate,
                      config_json->>'demand_shock_prob' AS demand_shock_prob,
                      config_json->>'picking_error_rate' AS picking_error_rate,
                      config_json->>'shrink_rate_daily' AS shrink_rate_daily,
                      config_json->>'perishable_remove_buffer_days' AS perishable_remove_buffer_days
                    FROM step1.step1_run_registry
                    WHERE run_id = :run_id
                    """
                ),
                {"run_id": args.run_id},
            ).mappings().first()
            realism_score, realism_recommendation = _realism_score_and_hint(
                metrics.get("fill_rate_mean"),
                metrics.get("fill_rate_p95"),
            )
            goal1_contract_completeness = _compute_goal1_contract_completeness(
                conn,
                args.run_id,
                metrics,
                writeoff_reason_column=writeoff_reason_column,
            )
            goal1_store_week_category = _build_goal1_store_week_category(
                conn,
                args.run_id,
                writeoff_reason_column=writeoff_reason_column,
            )

        out_dir = Path("data/metrics_snapshots")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{args.run_id}.json"
        goal1_fact_path = out_dir / f"{args.run_id}_goal1_store_week_category.json"
        cfg_obj = run_cfg_row["config_json"] if run_cfg_row and isinstance(run_cfg_row.get("config_json"), dict) else {}
        data_source_type = str(cfg_obj.get("data_source_type", "")).strip().lower()
        if data_source_type not in {"synthetic", "real", "mixed"}:
            data_source_type = "unknown"

        payload = {
            "run_id": args.run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_tables": sources,
            "data_source_type": data_source_type,
            "metrics": {k: v for k, v in metrics.items() if k != "_notes"},
            "contract_completeness": goal1_contract_completeness,
            "goal1_store_week_category_ref": str(goal1_fact_path),
            "realism_targets": REALISM_TARGETS,
            "realism_score": realism_score,
            "realism_recommendation": realism_recommendation,
            "realism_summary": {
                "status": ("known" if run_cfg_row is not None else "unknown"),
                "fill_rate_mean": metrics.get("fill_rate_mean"),
                "fill_rate_p95": metrics.get("fill_rate_p95"),
                "supplier_fill_rate_mean": metrics.get("supplier_fill_rate_mean"),
                "replen_capacity_mult_mean": metrics.get("replen_capacity_mult_mean"),
                "leadtime_days_mean": metrics.get("leadtime_days_mean"),
                "shrink_units_rate": metrics.get("shrink_units_rate"),
                "shock_days_share": metrics.get("shock_days_share"),
                "knobs": {
                    "enable_supply_realism": (run_cfg_row["enable_supply_realism"] if run_cfg_row else None),
                    "enable_ops_noise": (run_cfg_row["enable_ops_noise"] if run_cfg_row else None),
                    "enable_demand_shocks": (run_cfg_row["enable_demand_shocks"] if run_cfg_row else None),
                    "enable_competitor_prices": (run_cfg_row["enable_competitor_prices"] if run_cfg_row else None),
                    "competitor_reactive_mode": (run_cfg_row["competitor_reactive_mode"] if run_cfg_row else None),
                    "replenishment_leadtime_days": (run_cfg_row["replenishment_leadtime_days"] if run_cfg_row else None),
                    "replenishment_capacity_mult": (run_cfg_row["replenishment_capacity_mult"] if run_cfg_row else None),
                    "supplier_fill_rate": (run_cfg_row["supplier_fill_rate"] if run_cfg_row else None),
                    "demand_shock_prob": (run_cfg_row["demand_shock_prob"] if run_cfg_row else None),
                    "picking_error_rate": (run_cfg_row["picking_error_rate"] if run_cfg_row else None),
                    "shrink_rate_daily": (run_cfg_row["shrink_rate_daily"] if run_cfg_row else None),
                    "perishable_remove_buffer_days": (run_cfg_row["perishable_remove_buffer_days"] if run_cfg_row else None),
                },
            },
            "notes": metrics.get("_notes", []),
            "run_config": {
                "mode_tag": (run_cfg_row["mode_tag"] if run_cfg_row else None),
                "assignment_status": (run_cfg_row["assignment_status"] if run_cfg_row else None),
                "experiment_id": (run_cfg_row["experiment_id"] if run_cfg_row else None),
                "experiment_unit": (run_cfg_row["experiment_unit"] if run_cfg_row else None),
                "experiment_treat_pct": (run_cfg_row["experiment_treat_pct"] if run_cfg_row else None),
                "experiment_salt": (run_cfg_row["experiment_salt"] if run_cfg_row else None),
                "enable_supply_realism": (run_cfg_row["enable_supply_realism"] if run_cfg_row else None),
                "enable_ops_noise": (run_cfg_row["enable_ops_noise"] if run_cfg_row else None),
                "enable_demand_shocks": (run_cfg_row["enable_demand_shocks"] if run_cfg_row else None),
                "enable_competitor_prices": (run_cfg_row["enable_competitor_prices"] if run_cfg_row else None),
                "competitor_reactive_mode": (run_cfg_row["competitor_reactive_mode"] if run_cfg_row else None),
            },
            "blocked_by_data": [
                "doi",
                "inventory_turnover",
                "days_to_expiry_dist",
                "aged_inventory_share",
                "writeoff_rate_vs_received_units",
            ],
        }
        goal1_fact_payload = {
            "run_id": args.run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_source_type": data_source_type,
            "rows": goal1_store_week_category,
        }
        goal1_fact_path.write_text(json.dumps(goal1_fact_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(goal1_fact_path)
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(out_path)
        print(f"ok: metrics snapshot written to {out_path}")
    except RuntimeError as exc:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(redact_text(traceback.format_exc()), encoding="utf-8")
        reason = str(exc) or "runtime_error"
        if "HOLD_NEED_DATA:data_mapping_mismatch" in reason:
            raise SystemExit(f"HOLD_NEED_DATA: {reason}. See {log_path}")
        raise SystemExit(f"metrics snapshot failed. See {log_path}")
    except Exception:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(redact_text(traceback.format_exc()), encoding="utf-8")
        raise SystemExit(f"metrics snapshot failed. See {log_path}")


if __name__ == "__main__":
    main()
