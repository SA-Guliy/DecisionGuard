#!/usr/bin/env python3
"""
Step 1 simulation: fulfillment + OOS + baseline replenishment.
"""
from __future__ import annotations

import argparse
import math
import os
import re
from collections import defaultdict, deque
from datetime import date, timedelta
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
from pathlib import Path
from typing import Any

import pandas as pd
import numpy as np
from sqlalchemy import create_engine, text

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")

# Realism defaults are centralized here for deterministic, low-noise tuning.
DEFAULT_ENABLE_SUPPLY_REALISM = 1
DEFAULT_REPLENISHMENT_LEADTIME_DAYS = 1
DEFAULT_REPLENISHMENT_CAPACITY_MULT = 0.90
DEFAULT_REPLENISHMENT_NOISE_SIGMA = 0.10
DEFAULT_SUPPLIER_FILL_RATE = 0.95
DEFAULT_ENABLE_OPS_NOISE = 1
DEFAULT_PICKING_ERROR_RATE = 0.005
DEFAULT_SHRINK_RATE_DAILY = 0.001
DEFAULT_ENABLE_DEMAND_SHOCKS = 1
DEFAULT_DEMAND_SHOCK_PROB = 0.08
DEFAULT_DEMAND_SHOCK_MULT_RANGE = "1.1,1.6"
GLOBAL_SIM_SEED = 0
MONEY_Q = Decimal("0.01")
_TABLE_COLUMNS_CACHE: dict[tuple[str, str], set[str]] = {}
WRITEOFF_REASON_CANONICAL_MAP = {
    "pull_before_expiry": "expiry",
    "expiry": "expiry",
    "expired": "expiry",
    "damage": "damage",
    "damaged": "damage",
    "quality": "quality_issue",
    "quality_issue": "quality_issue",
    "unknown": "other",
}


def _money_round(value: Decimal | float | int) -> Decimal:
    return Decimal(value).quantize(MONEY_Q, rounding=ROUND_HALF_UP)


def _stable_batch_id(run_id: str, store_id: str, product_id: str, lot_date: date, seed_hint: str = "") -> str:
    payload = f"{run_id}|{store_id}|{product_id}|{lot_date.isoformat()}|{seed_hint}"
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]
    return f"batch_{digest}"


def _canonical_writeoff_reason(reason: str) -> str:
    key = str(reason or "").strip().lower()
    return WRITEOFF_REASON_CANONICAL_MAP.get(key, "other")


def _table_columns(conn, schema_name: str, table_name: str) -> set[str]:
    key = (schema_name, table_name)
    cached = _TABLE_COLUMNS_CACHE.get(key)
    if cached is not None:
        return cached
    rows = conn.execute(
        text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = :schema_name AND table_name = :table_name
            """
        ),
        {"schema_name": schema_name, "table_name": table_name},
    ).fetchall()
    out = {str(r[0]) for r in rows}
    _TABLE_COLUMNS_CACHE[key] = out
    return out


def _assert_safe_ident(name: str, what: str) -> str:
    if not _IDENT.match(name):
        raise SystemExit(f"Unsafe {what}: {name}")
    return name


def _qualified_name(schema_name: str, table_name: str) -> str:
    safe_schema = _assert_safe_ident(schema_name, "schema")
    safe_table = _assert_safe_ident(table_name, "table")
    return f"{safe_schema}.{safe_table}"


def _assert_expected_db(conn, expected: str) -> None:
    db = conn.execute(text("SELECT current_database();")).scalar()
    if db != expected:
        raise SystemExit(f"Refusing to modify DB '{db}'. Expected '{expected}'. Check PG_DSN/PG_EXPECTED_DB.")


def _assert_local_dsn(pg_url: str) -> None:
    allow_nonlocal = os.getenv("ALLOW_NONLOCALHOST", "0") == "1"
    if allow_nonlocal:
        return
    if "service=" in pg_url:
        return
    if "@localhost" not in pg_url and "@127.0.0.1" not in pg_url and "@::1" not in pg_url:
        raise SystemExit("Refusing non-localhost DSN. Set ALLOW_NONLOCALHOST=1 to override.")


def _get_engine(pg_url: str):
    return create_engine(pg_url)


def _resolve_pg_url(arg_pg_url: str | None) -> str:
    service = os.getenv("PGSERVICE")
    pg_url = os.getenv("PG_DSN") or arg_pg_url
    if not pg_url and service:
        pg_url = f"postgresql:///?service={service}"
    if not pg_url:
        raise SystemExit("Missing PG_DSN / PGSERVICE env or --pg-url (NO password; use ~/.pgpass, chmod 600)")
    return pg_url


def _lot_expiry(received_date: date, is_perishable: int, expiry_days: int | None) -> date | None:
    if int(is_perishable) != 1:
        return None
    if expiry_days is None or int(expiry_days) <= 0:
        return None
    return received_date + timedelta(days=int(expiry_days))


def _on_hand_qty(lots_by_key: dict[tuple[str, str], list[dict[str, Any]]], key: tuple[str, str]) -> int:
    return int(sum(int(lot["qty"]) for lot in lots_by_key.get(key, [])))


def _cleanup_lots(lots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [lot for lot in lots if int(lot["qty"]) > 0]


def _consume_lots(
    lots: list[dict[str, Any]],
    requested_qty: int,
    is_perishable: int,
) -> tuple[list[dict[str, Any]], int]:
    if requested_qty <= 0:
        return _cleanup_lots(lots), 0

    available = _cleanup_lots(lots)
    if not available:
        return [], 0

    if int(is_perishable) == 1:
        available.sort(
            key=lambda lot: (
                lot["expiry_date"] if lot["expiry_date"] is not None else date.max,
                lot["received_date"],
            )
        )
    else:
        available.sort(key=lambda lot: lot["received_date"])

    remain = int(requested_qty)
    fulfilled = 0
    for lot in available:
        if remain <= 0:
            break
        lot_qty = int(lot["qty"])
        take = min(lot_qty, remain)
        lot["qty"] = lot_qty - take
        remain -= take
        fulfilled += take

    return _cleanup_lots(available), fulfilled


def _apply_pull_writeoff(
    run_id: str,
    d: date,
    store_id: str,
    lots_by_key: dict[tuple[str, str], list[dict[str, Any]]],
    product_meta: dict[str, dict[str, Any]],
    remove_buffer_days: int,
    writeoff_rows: list[dict[str, Any]],
) -> None:
    for (s_id, pid), lots in list(lots_by_key.items()):
        if s_id != store_id:
            continue
        meta = product_meta.get(pid)
        if not meta:
            continue
        if int(meta["is_perishable"]) != 1:
            continue
        kept: list[dict[str, Any]] = []
        for lot in lots:
            qty = int(lot["qty"])
            if qty <= 0:
                continue
            expiry_date = lot["expiry_date"]
            if expiry_date is None:
                kept.append(lot)
                continue
            pull_date = expiry_date - timedelta(days=max(0, int(remove_buffer_days)))
            if d >= pull_date:
                unit_cogs = Decimal(str(meta["unit_cogs"]))
                writeoff_rows.append(
                    {
                        "run_id": run_id,
                        "date": d,
                        "store_id": store_id,
                        "product_id": pid,
                        "batch_id": lot.get("batch_id"),
                        "supplier_id": lot.get("supplier_id"),
                        "purchase_order_id": lot.get("purchase_order_id"),
                        "lot_received_date": lot["received_date"],
                        "lot_expiry_date": expiry_date,
                        "pull_date": pull_date,
                        "qty_writeoff": qty,
                        "unit_cogs": meta["unit_cogs"],
                        "writeoff_cogs": unit_cogs * qty,
                        "reason": "pull_before_expiry",
                        "writeoff_reason_norm": _canonical_writeoff_reason("pull_before_expiry"),
                    }
                )
            else:
                kept.append(lot)
        lots_by_key[(s_id, pid)] = _cleanup_lots(kept)


def _build_competitor_daily_map(
    conn,
    raw_schema: str,
    run_id: str,
    enabled: int,
    shared_across_stores: int,
    competitor_seed: int,
    ar: float,
    noise_sigma: float,
    promo_prob: float,
    promo_min: float,
    promo_max: float,
    reactive_mode: int,
    reactive_beta: float,
    reactive_lag_days: int,
    date_range: tuple[date, date] | None,
) -> tuple[dict[tuple[date, str, str | None], dict[str, Any]], list[dict[str, Any]]]:
    if enabled != 1:
        return {}, []
    if date_range is None:
        date_rows = conn.execute(
            text(
                f"""
                SELECT DISTINCT date
                FROM {raw_schema}.raw_order_items
                ORDER BY date
                """
            )
        ).fetchall()
    else:
        start_d, end_d = date_range
        date_rows = conn.execute(
            text(
                f"""
                SELECT DISTINCT date
                FROM {raw_schema}.raw_order_items
                WHERE date BETWEEN :start_d AND :end_d
                ORDER BY date
                """
            ),
            {"start_d": start_d, "end_d": end_d},
        ).fetchall()
    dates = [r[0] for r in date_rows]
    if not dates:
        return {}, []

    category_rows = conn.execute(
        text(f"SELECT DISTINCT category_id FROM {raw_schema}.raw_products ORDER BY category_id")
    ).fetchall()
    categories = [r[0] for r in category_rows]
    if not categories:
        return {}, []

    category_floor_index: dict[str, float] = {}
    floor_rows = conn.execute(
        text(
            f"""
            SELECT
              category_id,
              AVG(COALESCE(list_price, 0))::double precision AS avg_price,
              AVG(COALESCE(unit_cogs, 0))::double precision AS avg_cogs
            FROM {raw_schema}.raw_products
            GROUP BY category_id
            """
        )
    ).fetchall()
    for r in floor_rows:
        avg_price = float(r[1] or 0.0)
        avg_cogs = float(r[2] or 0.0)
        if avg_price > 0.0:
            category_floor_index[str(r[0])] = max(0.70, min(1.30, (avg_cogs * 1.05) / avg_price))
        else:
            category_floor_index[str(r[0])] = 0.70

    own_discount_by_key: dict[tuple[date, str, str], float] = {}
    own_discount_all_by_key: dict[tuple[date, str], float] = {}
    if int(reactive_mode) == 1:
        if date_range is None:
            discount_rows = conn.execute(
                text(
                    f"""
                    SELECT date, store_id, category_id, AVG(discount_pct)::double precision AS avg_discount
                    FROM {raw_schema}.raw_order_items
                    GROUP BY date, store_id, category_id
                    """
                )
            ).fetchall()
        else:
            start_d, end_d = date_range
            discount_rows = conn.execute(
                text(
                    f"""
                    SELECT date, store_id, category_id, AVG(discount_pct)::double precision AS avg_discount
                    FROM {raw_schema}.raw_order_items
                    WHERE date BETWEEN :start_d AND :end_d
                    GROUP BY date, store_id, category_id
                    """
                ),
                {"start_d": start_d, "end_d": end_d},
            ).fetchall()
        for row in discount_rows:
            own_discount_by_key[(row[0], row[1], row[2])] = float(row[3] or 0.0)
        if date_range is None:
            all_rows = conn.execute(
                text(
                    f"""
                    SELECT date, category_id, AVG(discount_pct)::double precision AS avg_discount
                    FROM {raw_schema}.raw_order_items
                    GROUP BY date, category_id
                    """
                )
            ).fetchall()
        else:
            start_d, end_d = date_range
            all_rows = conn.execute(
                text(
                    f"""
                    SELECT date, category_id, AVG(discount_pct)::double precision AS avg_discount
                    FROM {raw_schema}.raw_order_items
                    WHERE date BETWEEN :start_d AND :end_d
                    GROUP BY date, category_id
                    """
                ),
                {"start_d": start_d, "end_d": end_d},
            ).fetchall()
        for row in all_rows:
            own_discount_all_by_key[(row[0], row[1])] = float(row[2] or 0.0)

    stores: list[str | None]
    if int(shared_across_stores) == 1:
        stores = [None]
    else:
        store_rows = conn.execute(
            text(f"SELECT DISTINCT store_id FROM {raw_schema}.raw_order_items ORDER BY store_id")
        ).fetchall()
        stores = [r[0] for r in store_rows]

    rng_seed = competitor_seed if competitor_seed != 0 else _seed_from_run_id(run_id + "_competitor")
    comp_map: dict[tuple[date, str, str | None], dict[str, Any]] = {}
    comp_rows: list[dict[str, Any]] = []

    for category_id in categories:
        for store_id in stores:
            seed_key = f"{rng_seed}:{category_id}:{store_id if store_id is not None else 'ALL'}"
            local_seed = _seed_from_run_id(seed_key)
            rng = np.random.default_rng(local_seed)
            shock = 0.0
            for d in dates:
                shock = (ar * shock) + float(rng.normal(0.0, noise_sigma))
                promo_flag = int(rng.random() < promo_prob)
                promo_depth = float(rng.uniform(promo_min, promo_max)) if promo_flag == 1 else 0.0
                price_index = (1.0 + shock) * (1.0 - promo_depth)
                if int(reactive_mode) == 1:
                    lag_date = d - timedelta(days=max(1, int(reactive_lag_days)))
                    if store_id is None:
                        own_disc = own_discount_all_by_key.get((lag_date, category_id), 0.0)
                    else:
                        own_disc = own_discount_by_key.get((lag_date, store_id, category_id), 0.0)
                    reaction = max(-0.2, min(0.2, float(reactive_beta) * float(own_disc)))
                    price_index *= (1.0 - reaction)
                floor_idx = float(category_floor_index.get(str(category_id), 0.70))
                price_index = max(floor_idx, min(price_index, 1.30))
                key = (d, category_id, store_id)
                comp_map[key] = {
                    "competitor_price_index": price_index,
                    "promo_flag": promo_flag,
                    "promo_depth": promo_depth,
                }
                comp_rows.append(
                    {
                        "run_id": run_id,
                        "date": d,
                        "store_id": store_id if store_id is not None else "ALL",
                        "category_id": category_id,
                        "competitor_price_index": price_index,
                        "promo_flag": promo_flag,
                        "promo_depth": promo_depth,
                    }
                )
    return comp_map, comp_rows


def _build_demand_shock_daily_map(
    conn,
    raw_schema: str,
    run_id: str,
    enabled: int,
    shock_prob: float,
    shock_min: float,
    shock_max: float,
    date_range: tuple[date, date] | None,
) -> tuple[dict[tuple[date, str, str], float], list[dict[str, Any]]]:
    if int(enabled) != 1:
        return {}, []
    if date_range is None:
        rows = conn.execute(
            text(
                f"""
                SELECT DISTINCT date, store_id, category_id
                FROM {raw_schema}.raw_order_items
                ORDER BY date, store_id, category_id
                """
            )
        ).fetchall()
    else:
        start_d, end_d = date_range
        rows = conn.execute(
            text(
                f"""
                SELECT DISTINCT date, store_id, category_id
                FROM {raw_schema}.raw_order_items
                WHERE date BETWEEN :start_d AND :end_d
                ORDER BY date, store_id, category_id
                """
            ),
            {"start_d": start_d, "end_d": end_d},
        ).fetchall()

    shock_map: dict[tuple[date, str, str], float] = {}
    shock_rows: list[dict[str, Any]] = []
    for d, store_id, category_id in rows:
        rng = np.random.default_rng(_seed_from_parts(run_id, "demand_shock", d.isoformat(), store_id, category_id))
        is_shock = int(float(rng.random()) < max(0.0, min(1.0, float(shock_prob))))
        shock_mult = float(rng.uniform(shock_min, shock_max)) if is_shock == 1 else 1.0
        shock_map[(d, store_id, category_id)] = shock_mult
        shock_rows.append(
            {
                "run_id": run_id,
                "date": d,
                "store_id": store_id,
                "category_id": category_id,
                "shock_mult": shock_mult,
                "is_shock": is_shock,
            }
        )
    return shock_map, shock_rows


def _load_initial_inventory(conn, raw_schema: str, perish_factor: float, nonperish_factor: float):
    inventory_cols = _table_columns(conn, raw_schema, "raw_initial_inventory")
    has_batch_id = "batch_id" in inventory_cols
    has_supplier_id = "supplier_id" in inventory_cols
    has_purchase_order_id = "purchase_order_id" in inventory_cols

    rows = conn.execute(
        text(
            f"""
            SELECT
                i.store_id,
                i.product_id,
                i.as_of_date,
                i.initial_qty,
                p.is_perishable,
                p.expiry_days,
                p.unit_cogs,
                p.category_id,
                {('i.batch_id' if has_batch_id else 'NULL::text AS batch_id')},
                {('i.supplier_id' if has_supplier_id else 'NULL::text AS supplier_id')},
                {('i.purchase_order_id' if has_purchase_order_id else 'NULL::text AS purchase_order_id')}
            FROM {raw_schema}.raw_initial_inventory i
            JOIN {raw_schema}.raw_products p ON p.product_id = i.product_id
            """
        )
    ).fetchall()

    lots_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    targets_by_store: dict[str, dict[str, int]] = {}
    product_meta: dict[str, dict[str, Any]] = {}
    for (
        store_id,
        product_id,
        as_of_date,
        initial_qty,
        is_perishable,
        expiry_days,
        unit_cogs,
        category_id,
        batch_id,
        supplier_id,
        purchase_order_id,
    ) in rows:
        base = int(initial_qty)
        if int(is_perishable) == 1:
            target = int(round(base * perish_factor))
        else:
            target = int(round(base * nonperish_factor))
        target = max(0, target)
        expiry_date = _lot_expiry(as_of_date, int(is_perishable), expiry_days)
        lots_by_key[(store_id, product_id)] = [
            {
                "qty": base,
                "received_date": as_of_date,
                "expiry_date": expiry_date,
                "batch_id": str(batch_id).strip() if batch_id is not None and str(batch_id).strip() else _stable_batch_id("initial", store_id, product_id, as_of_date),
                "supplier_id": str(supplier_id).strip() if supplier_id is not None and str(supplier_id).strip() else f"supplier_{_seed_from_parts(store_id, product_id) % 17:02d}",
                "purchase_order_id": (
                    str(purchase_order_id).strip()
                    if purchase_order_id is not None and str(purchase_order_id).strip()
                    else f"po_init_{store_id}_{product_id}_{as_of_date.strftime('%Y%m%d')}"
                ),
            }
        ]
        targets_by_store.setdefault(store_id, {})[product_id] = target
        product_meta[product_id] = {
            "is_perishable": int(is_perishable),
            "expiry_days": int(expiry_days) if expiry_days is not None else None,
            "unit_cogs": float(unit_cogs),
            "category_id": category_id,
        }
    return lots_by_key, targets_by_store, product_meta


def _seed_from_run_id(run_id: str) -> int:
    h = hashlib.sha256(run_id.encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big") ^ int(GLOBAL_SIM_SEED)


def _seed_from_parts(*parts: Any) -> int:
    payload = str(GLOBAL_SIM_SEED) + "|" + "|".join(str(p) for p in parts)
    h = hashlib.sha256(payload.encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big")


def _deterministic_binomial(n: int, p: float, *parts: Any) -> int:
    if n <= 0:
        return 0
    p = max(0.0, min(1.0, float(p)))
    if p <= 0.0:
        return 0
    if p >= 1.0:
        return int(n)
    rng = np.random.default_rng(_seed_from_parts(*parts))
    return int(rng.binomial(int(n), p))


def _deterministic_noise_mult(sigma: float, *parts: Any) -> float:
    sigma = max(0.0, float(sigma))
    if sigma == 0.0:
        return 1.0
    rng = np.random.default_rng(_seed_from_parts(*parts))
    return max(0.0, 1.0 + float(rng.normal(0.0, sigma)))


def _assignment_hash_bucket(experiment_id: str, unit_id: str, salt: str) -> int:
    payload = f"{experiment_id}:{unit_id}:{salt}".encode("utf-8")
    digest = hashlib.sha1(payload).hexdigest()
    # Keep deterministic hash in signed int32 range to match DB INT column.
    raw = int(digest[:8], 16)
    return raw - (2**32) if raw >= 2**31 else raw


def _assignment_arm(experiment_id: str, unit_id: str, treat_pct: int, salt: str) -> tuple[str, int]:
    h = _assignment_hash_bucket(experiment_id, unit_id, salt)
    bucket = h % 100
    arm = "treatment" if bucket < int(treat_pct) else "control"
    return arm, h


def _ensure_run_registry(conn, run_id: str, mode_tag: str, feature_flags: dict[str, Any], config_json: dict[str, Any]) -> None:
    exists = conn.execute(text("SELECT to_regclass('step1.step1_run_registry')")).scalar()
    if not exists:
        raise SystemExit(
            "step1_run_registry not installed. Run: psql -d darkstore -f v1/sql/run_registry.sql (admin)"
        )
    conn.execute(
        text(
            """
            INSERT INTO step1.step1_run_registry (run_id, mode_tag, feature_flags, config_json)
            VALUES (:run_id, :mode_tag, CAST(:feature_flags AS jsonb), CAST(:config_json AS jsonb))
            ON CONFLICT (run_id)
            DO UPDATE SET
                mode_tag = EXCLUDED.mode_tag,
                feature_flags = EXCLUDED.feature_flags,
                config_json = EXCLUDED.config_json;
            """
        ),
        {
            "run_id": run_id,
            "mode_tag": mode_tag,
            "feature_flags": json.dumps(feature_flags),
            "config_json": json.dumps(config_json),
        },
    )


class CustomerDynamicsManager:
    def __init__(
        self,
        customers_df: pd.DataFrame,
        home_store_by_customer: dict[str, str],
        rep_alpha: float,
        base_churn_prob: float,
        churn_sensitivity: float,
        segment_churn_multiplier: dict[str, float],
        max_churn_per_day: int,
        max_new_per_day: int,
        min_active_floor: int,
        enable_acquisition: bool,
        acq_fill_threshold: float,
        dynamics_seed: int,
    ) -> None:
        self.rep_alpha = rep_alpha
        self.base_churn_prob = base_churn_prob
        self.churn_sensitivity = churn_sensitivity
        self.segment_churn_multiplier = segment_churn_multiplier
        self.max_churn_per_day = max_churn_per_day
        self.max_new_per_day = max_new_per_day
        self.min_active_floor = min_active_floor
        self.enable_acquisition = enable_acquisition
        self.acq_fill_threshold = acq_fill_threshold
        self.rng = np.random.default_rng(dynamics_seed)

        self.status_by_customer: dict[str, str] = {}
        self.segment_by_customer: dict[str, str] = {}
        self.activity_by_customer: dict[str, float] = {}
        self.home_store_by_customer: dict[str, str] = {}
        self.active_set_by_store: dict[str, set[str]] = defaultdict(set)
        self.reserve_queue_by_store: dict[str, deque[str]] = defaultdict(deque)
        self.rep_by_store: dict[str, float] = defaultdict(lambda: 1.0)

        for row in customers_df.itertuples(index=False):
            cid = row.customer_id
            status = getattr(row, "initial_status", "active")
            seg = row.customer_segment
            act_w = float(row.activity_weight)
            store = home_store_by_customer.get(cid, "A")

            self.status_by_customer[cid] = status
            self.segment_by_customer[cid] = seg
            self.activity_by_customer[cid] = act_w
            self.home_store_by_customer[cid] = store

            if status == "active":
                self.active_set_by_store[store].add(cid)
            else:
                self.reserve_queue_by_store[store].append(cid)

    def is_active(self, store_id: str, customer_id: str) -> bool:
        return customer_id in self.active_set_by_store.get(store_id, set())

    def end_of_day(
        self,
        store_id: str,
        d: date,
        daily_fill_rate: float,
        run_id: str,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        rep_prev = self.rep_by_store[store_id]
        rep = (1.0 - self.rep_alpha) * rep_prev + self.rep_alpha * daily_fill_rate
        self.rep_by_store[store_id] = rep

        churn_prob = self.base_churn_prob + self.churn_sensitivity * max(0.0, 1.0 - rep)
        active_ids = sorted(self.active_set_by_store.get(store_id, set()))
        churn_candidates: list[str] = []
        for cid in active_ids:
            seg = self.segment_by_customer.get(cid, "mid")
            mult = self.segment_churn_multiplier.get(seg, 1.0)
            p = churn_prob * mult
            if self.rng.random() < p:
                churn_candidates.append(cid)
        if len(churn_candidates) > self.max_churn_per_day:
            churned_today = list(self.rng.choice(churn_candidates, size=self.max_churn_per_day, replace=False))
        else:
            churned_today = churn_candidates

        if len(active_ids) - len(churned_today) < self.min_active_floor:
            allowed = max(0, len(active_ids) - self.min_active_floor)
            if allowed < len(churned_today):
                churned_today = list(self.rng.choice(churned_today, size=allowed, replace=False))

        events: list[dict[str, Any]] = []
        for cid in churned_today:
            self.active_set_by_store[store_id].discard(cid)
            self.status_by_customer[cid] = "churned"
            events.append({
                "run_id": run_id,
                "date": d,
                "store_id": store_id,
                "customer_id": cid,
                "event_type": "churn",
                "reason": "rep_update",
                "value": rep,
                "value2": churn_prob,
            })

        activated_today: list[str] = []
        if self.enable_acquisition and rep >= self.acq_fill_threshold:
            q = self.reserve_queue_by_store.get(store_id, deque())
            for _ in range(min(self.max_new_per_day, len(q))):
                cid = q.popleft()
                self.active_set_by_store[store_id].add(cid)
                self.status_by_customer[cid] = "active"
                activated_today.append(cid)
                events.append({
                    "run_id": run_id,
                    "date": d,
                    "store_id": store_id,
                    "customer_id": cid,
                    "event_type": "activate",
                    "reason": "rep_high",
                    "value": rep,
                    "value2": churn_prob,
                })

        daily = {
            "run_id": run_id,
            "date": d,
            "store_id": store_id,
            "rep": rep,
            "daily_fill_rate": daily_fill_rate,
            "churn_prob": churn_prob,
            "active_cnt": len(self.active_set_by_store.get(store_id, set())),
            "reserve_cnt": len(self.reserve_queue_by_store.get(store_id, deque())),
            "churned_today": len(churned_today),
            "activated_today": len(activated_today),
        }
        return events, daily


def _ensure_step1_schema(
    conn,
    step1_schema: str,
    run_id: str,
    allow_overwrite_run: int,
    overwrite_reason: str,
    require_assignment_table: bool,
) -> None:
    required = [
        "step1_order_items",
        "step1_replenishment_log",
        "step1_orders",
        "step1_customer_daily",
        "step1_customer_events",
        "step1_writeoff_log",
        "step1_competitor_daily",
        "step1_supply_daily",
        "step1_ops_daily",
        "step1_demand_shocks_daily",
        "step1_run_registry",
    ]
    optional_required: list[str] = []
    if require_assignment_table:
        optional_required.append("step1_experiment_assignment_log")
    missing = []
    for t in required + optional_required:
        exists = conn.execute(
            text("SELECT to_regclass(format('%I.%I', :schema_name, :table_name))"),
            {"schema_name": step1_schema, "table_name": t},
        ).scalar()
        if not exists:
            missing.append(t)
    if missing:
        raise SystemExit(
            "Step1 schema not installed. Run: psql -d darkstore -f v1/sql/schema_step1.sql (admin)"
        )

    target_tables = [
        "step1_order_items",
        "step1_replenishment_log",
        "step1_orders",
        "step1_customer_daily",
        "step1_customer_events",
        "step1_writeoff_log",
        "step1_competitor_daily",
        "step1_supply_daily",
        "step1_ops_daily",
        "step1_demand_shocks_daily",
    ]
    assignment_exists = conn.execute(
        text("SELECT to_regclass(format('%I.%I', :schema_name, :table_name))"),
        {"schema_name": step1_schema, "table_name": "step1_experiment_assignment_log"},
    ).scalar() is not None
    if assignment_exists:
        target_tables.append("step1_experiment_assignment_log")
    key_tables = [
        "step1_order_items",
        "step1_orders",
        "step1_customer_daily",
        "step1_writeoff_log",
        "step1_competitor_daily",
        "step1_supply_daily",
        "step1_ops_daily",
        "step1_demand_shocks_daily",
        "step1_run_registry",
    ]
    if assignment_exists:
        key_tables.append("step1_experiment_assignment_log")
    existing_rows = 0
    for table_name in key_tables:
        existing_rows += int(
            conn.execute(
                text("SELECT COUNT(*) FROM " + _qualified_name(step1_schema, table_name) + " WHERE run_id = :r"),
                {"r": run_id},
            ).scalar()
            or 0
        )

    if existing_rows > 0 and int(allow_overwrite_run) != 1:
        raise SystemExit(
            f"Run id '{run_id}' already exists ({existing_rows} rows). "
            "Refusing overwrite. Re-run with --allow-overwrite-run 1 to replace this run."
        )

    # Never delete unless overwrite is explicitly enabled.
    if int(allow_overwrite_run) != 1 or existing_rows == 0:
        return

    reason = (overwrite_reason or "").strip()
    if not reason:
        raise SystemExit(
            "Overwrite requested but --overwrite-reason is empty. "
            "Provide non-empty reason to audit overwrite."
        )

    priv_missing: list[str] = []
    for table_name in target_tables:
        fq_name = _qualified_name(step1_schema, table_name)
        can_delete = conn.execute(
            text("SELECT has_table_privilege(current_user, :tbl, 'DELETE')"),
            {"tbl": fq_name},
        ).scalar()
        if not can_delete:
            priv_missing.append(fq_name)

    if priv_missing:
        raise SystemExit(
            "Missing DELETE privileges on Step1 tables: "
            + ", ".join(priv_missing)
            + ". Run admin grants: psql -d darkstore -f v1/sql/bootstrap_privileges.sql "
              "and psql -d darkstore -f v1/sql/migrations/002_step1_lot_competitor_upgrade.sql "
              "and psql -d darkstore -f v1/sql/migrations/004_step1_realism_upgrade.sql "
              "and psql -d darkstore -f v1/sql/migrations/005_step1_assignment_log.sql "
              "and psql -d darkstore -f v1/sql/migrations/008_step1_goal1_contract_upgrade.sql"
        )

    actor = conn.execute(text("SELECT current_user")).scalar()
    conn.execute(
        text(
            """
            UPDATE step1.step1_run_registry
            SET overwrite_count = COALESCE(overwrite_count, 0) + 1,
                last_overwrite_at = now(),
                last_overwrite_by = :actor,
                last_overwrite_reason = :reason
            WHERE run_id = :run_id
            """
        ),
        {"actor": actor, "reason": reason, "run_id": run_id},
    )

    for table_name in target_tables:
        conn.execute(
            text("DELETE FROM " + _qualified_name(step1_schema, table_name) + " WHERE run_id = :r"),
            {"r": run_id},
        )

    # Indexes are created by admin via v1/sql/schema_step1.sql


def _apply_supply_shrink_for_day(
    run_id: str,
    d: date,
    store_id: str,
    lots_by_key: dict[tuple[str, str], list[dict[str, Any]]],
    product_meta: dict[str, dict[str, Any]],
    shrink_rate_daily: float,
) -> int:
    total_shrink = 0
    for (s_id, pid), lots in list(lots_by_key.items()):
        if s_id != store_id:
            continue
        on_hand = _on_hand_qty(lots_by_key, (s_id, pid))
        if on_hand <= 0:
            continue
        shrink_units = _deterministic_binomial(on_hand, shrink_rate_daily, run_id, "shrink", store_id, pid, d.isoformat())
        if shrink_units <= 0:
            continue
        is_perishable = int(product_meta.get(pid, {}).get("is_perishable", 0))
        next_lots, _ = _consume_lots(lots, shrink_units, is_perishable)
        lots_by_key[(s_id, pid)] = next_lots
        total_shrink += int(shrink_units)
    return total_shrink


def _apply_supply_receipts_for_day(
    run_id: str,
    d: date,
    store_id: str,
    lots_by_key: dict[tuple[str, str], list[dict[str, Any]]],
    product_meta: dict[str, dict[str, Any]],
    pending_receipts: dict[tuple[str, str], list[dict[str, Any]]],
    replenishment_rows: list[dict[str, Any]],
    supply_daily_rows: list[dict[str, Any]],
) -> None:
    for (s_id, pid), queue in list(pending_receipts.items()):
        if s_id != store_id:
            continue
        remain: list[dict[str, Any]] = []
        for rec in queue:
            if rec["arrival_date"] != d:
                remain.append(rec)
                continue
            recv_qty = int(rec["received_replen_units"])
            if recv_qty > 0:
                meta = product_meta.get(pid, {})
                expiry_date = _lot_expiry(
                    d,
                    int(meta.get("is_perishable", 0)),
                    meta.get("expiry_days"),
                )
                lots_by_key.setdefault((store_id, pid), []).append(
                    {
                        "qty": recv_qty,
                        "received_date": d,
                        "expiry_date": expiry_date,
                        "batch_id": str(rec.get("batch_id") or _stable_batch_id(run_id, store_id, pid, d, str(rec.get("purchase_order_id") or ""))),
                        "supplier_id": rec.get("supplier_id"),
                        "purchase_order_id": rec.get("purchase_order_id"),
                    }
                )
            replenishment_rows.append(
                {
                    "run_id": run_id,
                    "date": d,
                    "store_id": store_id,
                    "product_id": pid,
                    "batch_id": rec.get("batch_id"),
                    "supplier_id": rec.get("supplier_id"),
                    "purchase_order_id": rec.get("purchase_order_id"),
                    "qty_added": recv_qty,
                    "inventory_after": _on_hand_qty(lots_by_key, (store_id, pid)),
                }
            )
            supply_daily_rows.append(
                {
                    "run_id": run_id,
                    "date": d,
                    "store_id": store_id,
                    "product_id": pid,
                    "requested_replen_units": int(rec["requested_replen_units"]),
                    "received_replen_units": recv_qty,
                    "leadtime_days": int(rec["leadtime_days"]),
                    "supplier_fill_rate": float(rec["supplier_fill_rate"]),
                    "capacity_mult": float(rec["capacity_mult"]),
                    "noise_mult": float(rec["noise_mult"]),
                }
            )
        pending_receipts[(s_id, pid)] = remain


def _schedule_supply_for_day(
    run_id: str,
    d: date,
    store_id: str,
    lots_by_key: dict[tuple[str, str], list[dict[str, Any]]],
    targets_by_store: dict[str, dict[str, int]],
    pending_receipts: dict[tuple[str, str], list[dict[str, Any]]],
    enable_supply_realism: int,
    leadtime_days: int,
    capacity_mult: float,
    supplier_fill_rate: float,
    noise_sigma: float,
) -> None:
    targets = targets_by_store.get(store_id, {})
    for pid, target in targets.items():
        key = (store_id, pid)
        on_hand = _on_hand_qty(lots_by_key, key)
        queued = sum(int(x["received_replen_units"]) for x in pending_receipts.get(key, []))
        need_qty = int(target) - int(on_hand) - int(queued)
        if need_qty <= 0:
            continue
        supplier_id = f"supplier_{_seed_from_parts(run_id, store_id, pid, 'supplier') % 17:02d}"
        purchase_order_id = f"po_{run_id}_{store_id}_{pid}_{d.strftime('%Y%m%d')}"
        if int(enable_supply_realism) == 1:
            noise_mult = _deterministic_noise_mult(noise_sigma, run_id, "supply", store_id, pid, d.isoformat())
            gross_mult = max(0.0, float(capacity_mult)) * max(0.0, float(supplier_fill_rate)) * noise_mult
            recv_qty = int(math.floor(need_qty * gross_mult))
            arrival_date = d + timedelta(days=max(0, int(leadtime_days)))
            batch_id = _stable_batch_id(run_id, store_id, pid, arrival_date, purchase_order_id)
            pending_receipts.setdefault(key, []).append(
                {
                    "arrival_date": arrival_date,
                    "requested_replen_units": need_qty,
                    "received_replen_units": recv_qty,
                    "leadtime_days": int(leadtime_days),
                    "supplier_fill_rate": float(supplier_fill_rate),
                    "capacity_mult": float(capacity_mult),
                    "noise_mult": float(noise_mult),
                    "batch_id": batch_id,
                    "supplier_id": supplier_id,
                    "purchase_order_id": purchase_order_id,
                }
            )
        else:
            batch_id = _stable_batch_id(run_id, store_id, pid, d, purchase_order_id)
            pending_receipts.setdefault(key, []).append(
                {
                    "arrival_date": d,
                    "requested_replen_units": need_qty,
                    "received_replen_units": need_qty,
                    "leadtime_days": 0,
                    "supplier_fill_rate": 1.0,
                    "capacity_mult": 1.0,
                    "noise_mult": 1.0,
                    "batch_id": batch_id,
                    "supplier_id": supplier_id,
                    "purchase_order_id": purchase_order_id,
                }
            )


def _flush_df(df: pd.DataFrame, engine, schema: str, table: str) -> None:
    if df.empty:
        return
    with engine.begin() as conn:
        target_cols = _table_columns(conn, schema, table)
    keep_cols = [c for c in df.columns if c in target_cols]
    if not keep_cols:
        raise SystemExit(f"No compatible columns for {schema}.{table}; check schema migration state")
    if len(keep_cols) < len(df.columns):
        dropped = [c for c in df.columns if c not in target_cols]
        print(f"WARN: dropping non-schema columns for {schema}.{table}: {dropped}")
    df[keep_cols].to_sql(table, engine, schema=schema, if_exists="append", index=False, method="multi", chunksize=20000)


def main() -> None:
    parser = argparse.ArgumentParser(description="Step 1 simulation: fulfillment + replenishment")
    parser.add_argument(
        "--pg-url",
        default=None,
        help="Database URL or service-based connection (no password in args; use ~/.pgpass)",
    )
    parser.add_argument("--raw-schema", default="raw", help="Source schema for RAW tables")
    parser.add_argument("--step1-schema", default="step1", help="Target schema for Step 1 tables")
    parser.add_argument("--run-id", default="run_v1", help="Run ID written to step1 tables")
    parser.add_argument("--perish-factor", type=float, default=0.6, help="Target stock factor for perishables")
    parser.add_argument("--nonperish-factor", type=float, default=1.0, help="Target stock factor for non-perishables")
    parser.add_argument("--chunk-size", type=int, default=50000, help="Rows per batch insert")
    parser.add_argument("--enable-customer-dynamics", type=int, default=0, help="Enable V1.1-lite customer dynamics (0/1)")
    parser.add_argument("--enable-acquisition", type=int, default=0, help="Enable acquisition (0/1)")
    parser.add_argument("--rep-alpha", type=float, default=0.2)
    parser.add_argument("--base-churn-prob", type=float, default=0.001)
    parser.add_argument("--churn-sensitivity", type=float, default=0.05)
    parser.add_argument("--segment-churn-mult-low", type=float, default=1.2)
    parser.add_argument("--segment-churn-mult-mid", type=float, default=1.0)
    parser.add_argument("--segment-churn-mult-high", type=float, default=0.8)
    parser.add_argument("--max-churn-per-day", type=int, default=15)
    parser.add_argument("--max-new-per-day", type=int, default=15)
    parser.add_argument("--min-active-floor", type=int, default=400)
    parser.add_argument("--acq-fill-threshold", type=float, default=0.9)
    parser.add_argument("--dynamics-seed", type=int, default=0, help="Seed for customer dynamics (0 = derived from run_id)")
    parser.add_argument("--mode-tag", default="default", help="Run mode tag for step1_run_registry")
    parser.add_argument("--enable-elasticity", type=int, default=0, help="Enable elasticity uplift (0/1)")
    parser.add_argument("--elasticity-model", choices=["linear", "none"], default="linear")
    parser.add_argument("--elasticity-k-base", type=float, default=0.0)
    parser.add_argument("--elasticity-k-low", type=float, default=None)
    parser.add_argument("--elasticity-k-mid", type=float, default=None)
    parser.add_argument("--elasticity-k-high", type=float, default=None)
    parser.add_argument("--elasticity-cap-mult", type=float, default=2.0)
    parser.add_argument("--elasticity-min-mult", type=float, default=1.0)
    parser.add_argument(
        "--horizon-days",
        type=int,
        default=7,
        help="Process only first N days from raw_order_items min(date); 0 = full history",
    )
    parser.add_argument("--enable-supply-realism", type=int, default=DEFAULT_ENABLE_SUPPLY_REALISM, choices=[0, 1], help="Enable supply leadtime/capacity realism (0/1)")
    parser.add_argument("--replenishment-leadtime-days", type=int, default=DEFAULT_REPLENISHMENT_LEADTIME_DAYS, help="Lead time in days for replenishment arrivals")
    parser.add_argument("--replenishment-capacity-mult", type=float, default=DEFAULT_REPLENISHMENT_CAPACITY_MULT, help="Capacity multiplier for replenishment")
    parser.add_argument("--replenishment-noise-sigma", type=float, default=DEFAULT_REPLENISHMENT_NOISE_SIGMA, help="Noise sigma for replenishment variability")
    parser.add_argument("--supplier-fill-rate", type=float, default=DEFAULT_SUPPLIER_FILL_RATE, help="Supplier fill rate for replenishment")
    parser.add_argument("--enable-ops-noise", type=int, default=DEFAULT_ENABLE_OPS_NOISE, choices=[0, 1], help="Enable operational loss noise (0/1)")
    parser.add_argument("--picking-error-rate", type=float, default=DEFAULT_PICKING_ERROR_RATE, help="Picking error rate applied to fulfilled units")
    parser.add_argument("--shrink-rate-daily", type=float, default=DEFAULT_SHRINK_RATE_DAILY, help="Daily shrink loss rate applied to on-hand stock")
    parser.add_argument("--enable-demand-shocks", type=int, default=DEFAULT_ENABLE_DEMAND_SHOCKS, choices=[0, 1], help="Enable deterministic demand shocks (0/1)")
    parser.add_argument("--demand-shock-prob", type=float, default=DEFAULT_DEMAND_SHOCK_PROB, help="Store-day-category shock probability")
    parser.add_argument("--demand-shock-mult-range", default=DEFAULT_DEMAND_SHOCK_MULT_RANGE, help="Shock multiplier range min,max")
    parser.add_argument("--perishable-remove-buffer-days", type=int, default=1, help="Days before expiry when perishable lot is pulled from sale")
    parser.add_argument("--enable-competitor-prices", type=int, default=0, help="Enable deterministic competitor price simulation (0/1)")
    parser.add_argument("--competitor-seed", type=int, default=0, help="Seed for competitor process (0 = derived from run_id)")
    parser.add_argument("--competitor-ar", type=float, default=0.8, help="AR coefficient for competitor daily shocks")
    parser.add_argument("--competitor-noise-sigma", type=float, default=0.03, help="Noise sigma for competitor daily shocks")
    parser.add_argument("--competitor-promo-prob", type=float, default=0.04, help="Daily promo probability in competitor process")
    parser.add_argument("--competitor-promo-min", type=float, default=0.05, help="Min promo depth")
    parser.add_argument("--competitor-promo-max", type=float, default=0.15, help="Max promo depth")
    parser.add_argument("--competitor-demand-k", type=float, default=0.6, help="Demand sensitivity to competitor relative index")
    parser.add_argument("--competitor-min-mult", type=float, default=0.7, help="Lower bound for competitor demand multiplier")
    parser.add_argument("--competitor-max-mult", type=float, default=1.3, help="Upper bound for competitor demand multiplier")
    parser.add_argument("--competitor-shared-across-stores", type=int, default=1, help="Use same competitor process across stores (0/1)")
    parser.add_argument("--competitor-reaction-mode", choices=["exogenous", "reactive"], default="exogenous", help="Competitor mode: exogenous or reactive")
    parser.add_argument("--competitor-reactive-mode", type=int, default=0, choices=[0, 1], help="Enable lagged competitor response to own discounts")
    parser.add_argument("--competitor-reactive-beta", type=float, default=0.5, help="Reaction amplitude to own discount in reactive mode")
    parser.add_argument("--competitor-reactive-lag-days", type=int, default=1, help="Lag in days for competitor reaction")
    parser.add_argument("--allow-overwrite-run", type=int, default=0, choices=[0, 1], help="Allow replacing existing rows for this run_id")
    parser.add_argument("--overwrite-reason", default="", help="Required audit reason when --allow-overwrite-run=1 and run_id exists")
    parser.add_argument("--seed", type=int, default=0, help="Deterministic simulation seed")
    parser.add_argument("--experiment-id", default="", help="Optional active experiment id for assignment logging")
    parser.add_argument("--experiment-unit", choices=["customer", "store"], default="customer")
    parser.add_argument("--experiment-treat-pct", type=int, default=50, help="Treatment share in percent for deterministic assignment")
    parser.add_argument("--experiment-salt", default="", help="Optional assignment salt; default uses run_id")
    args = parser.parse_args()

    if args.experiment_treat_pct < 0 or args.experiment_treat_pct > 100:
        raise SystemExit("--experiment-treat-pct must be in [0,100]")
    experiment_salt = str(args.experiment_salt or "").strip() or str(args.run_id)
    competitor_reactive_enabled = (
        1
        if (str(args.competitor_reaction_mode).strip().lower() == "reactive" or int(args.competitor_reactive_mode) == 1)
        else 0
    )
    global GLOBAL_SIM_SEED
    GLOBAL_SIM_SEED = int(args.seed or 0)

    try:
        shock_min_s, shock_max_s = [x.strip() for x in str(args.demand_shock_mult_range).split(",", 1)]
        shock_min = float(shock_min_s)
        shock_max = float(shock_max_s)
    except Exception:
        raise SystemExit("Invalid --demand-shock-mult-range; expected 'min,max' numeric values")
    if shock_min <= 0 or shock_max <= 0 or shock_max < shock_min:
        raise SystemExit("Invalid demand shock multiplier range; require 0 < min <= max")
    print(
        "REALISM_DEFAULTS "
        f"capacity_mult={args.replenishment_capacity_mult} "
        f"supplier_fill_rate={args.supplier_fill_rate} "
        f"leadtime={args.replenishment_leadtime_days} "
        f"shock_prob={args.demand_shock_prob} "
        f"shrink={args.shrink_rate_daily} "
        f"picking={args.picking_error_rate}"
    )

    if args.pg_url:
        print(
            "INFO: Use ~/.pg_service.conf + ~/.pgpass for passwordless local DSNs.",
            flush=True,
        )
    pg_url = _resolve_pg_url(args.pg_url)
    _assert_local_dsn(pg_url)

    raw_schema = _assert_safe_ident(args.raw_schema, "raw schema")
    step1_schema = _assert_safe_ident(args.step1_schema, "step1 schema")
    expected_db = os.getenv("PG_EXPECTED_DB", "darkstore")

    engine = _get_engine(pg_url)
    experiment_enabled = bool(str(args.experiment_id or "").strip())

    with engine.begin() as conn:
        _assert_expected_db(conn, expected_db)
        feature_flags = {
            "enable_customer_dynamics": args.enable_customer_dynamics,
            "enable_acquisition": args.enable_acquisition,
            "enable_elasticity": args.enable_elasticity,
            "enable_competitor_prices": args.enable_competitor_prices,
            "enable_competitor_reactive_mode": competitor_reactive_enabled,
            "enable_supply_realism": args.enable_supply_realism,
            "enable_ops_noise": args.enable_ops_noise,
            "enable_demand_shocks": args.enable_demand_shocks,
        }
        config_json = vars(args).copy()
        config_json.pop("pg_url", None)
        config_json["realism_knobs"] = {
            "enable_supply_realism": int(args.enable_supply_realism),
            "replenishment_leadtime_days": int(args.replenishment_leadtime_days),
            "replenishment_capacity_mult": float(args.replenishment_capacity_mult),
            "replenishment_noise_sigma": float(args.replenishment_noise_sigma),
            "supplier_fill_rate": float(args.supplier_fill_rate),
            "enable_ops_noise": int(args.enable_ops_noise),
            "picking_error_rate": float(args.picking_error_rate),
            "shrink_rate_daily": float(args.shrink_rate_daily),
            "enable_demand_shocks": int(args.enable_demand_shocks),
            "demand_shock_prob": float(args.demand_shock_prob),
            "demand_shock_mult_range": str(args.demand_shock_mult_range),
            "enable_competitor_prices": int(args.enable_competitor_prices),
            "competitor_reactive_mode": competitor_reactive_enabled,
            "competitor_reaction_mode": str(args.competitor_reaction_mode),
            "competitor_shared_across_stores": int(args.competitor_shared_across_stores),
            "perishable_remove_buffer_days": int(args.perishable_remove_buffer_days),
        }
        config_json["assignment_status"] = "missing"
        config_json["experiment_id"] = str(args.experiment_id or "").strip()
        config_json["experiment_unit"] = args.experiment_unit
        config_json["experiment_treat_pct"] = int(args.experiment_treat_pct)
        config_json["experiment_salt"] = experiment_salt
        _ensure_step1_schema(
            conn,
            step1_schema,
            args.run_id,
            args.allow_overwrite_run,
            args.overwrite_reason,
            experiment_enabled,
        )
        _ensure_run_registry(conn, args.run_id, args.mode_tag, feature_flags, config_json)

    with engine.begin() as conn:
        _assert_expected_db(conn, expected_db)
        lots_by_key, targets_by_store, product_meta = _load_initial_inventory(
            conn, raw_schema, args.perish_factor, args.nonperish_factor
        )

    dynamics_manager: CustomerDynamicsManager | None = None
    if args.enable_customer_dynamics == 1:
        with engine.begin() as conn:
            _assert_expected_db(conn, expected_db)
            customers_df = pd.read_sql_query(
                text(
                    f"""
                    SELECT customer_id, customer_segment, activity_weight, initial_status, home_store_id
                    FROM {raw_schema}.raw_customers
                    """
                ),
                conn,
            )
        home_store_map = dict(zip(customers_df["customer_id"], customers_df["home_store_id"]))
        dyn_seed = args.dynamics_seed or _seed_from_run_id(args.run_id)
        dynamics_manager = CustomerDynamicsManager(
            customers_df=customers_df,
            home_store_by_customer=home_store_map,
            rep_alpha=args.rep_alpha,
            base_churn_prob=args.base_churn_prob,
            churn_sensitivity=args.churn_sensitivity,
            segment_churn_multiplier={
                "low": args.segment_churn_mult_low,
                "mid": args.segment_churn_mult_mid,
                "high": args.segment_churn_mult_high,
            },
            max_churn_per_day=args.max_churn_per_day,
            max_new_per_day=args.max_new_per_day,
            min_active_floor=args.min_active_floor,
            enable_acquisition=(args.enable_acquisition == 1),
            acq_fill_threshold=args.acq_fill_threshold,
            dynamics_seed=dyn_seed,
        )

    query_params: dict[str, Any] = {"start_date": None, "end_date": None}
    if args.horizon_days > 0:
        with engine.begin() as conn:
            _assert_expected_db(conn, expected_db)
            start_date = conn.execute(
                text("SELECT MIN(date) FROM " + _qualified_name(raw_schema, "raw_order_items"))
            ).scalar()
        if start_date is not None:
            end_date = (pd.Timestamp(start_date) + pd.Timedelta(days=args.horizon_days - 1)).date()
            query_params = {"start_date": start_date, "end_date": end_date}
            print(f"INFO: horizon_days={args.horizon_days} ({start_date}..{end_date})")
        else:
            print(f"INFO: horizon_days={args.horizon_days} (no data in raw_order_items)")
    else:
        print("INFO: horizon_days=0 (full history)")

    date_range: tuple[date, date] | None = None
    if query_params.get("start_date") is not None and query_params.get("end_date") is not None:
        date_range = (query_params["start_date"], query_params["end_date"])

    query = f"""
        SELECT
            oi.order_id,
            oi.store_id,
            oi.ts_minute,
            oi.date,
            oi.product_id,
            oi.category_id,
            oi.is_perishable,
            oi.requested_qty,
            oi.list_price,
            oi.unit_cogs,
            oi.discount_pct,
            oi.unit_price,
            oi.line_gmv_requested,
            oi.line_gp_requested,
            os.customer_segment,
            os.customer_id
        FROM {raw_schema}.raw_order_items oi
        JOIN {raw_schema}.raw_orders_stream os ON os.order_id = oi.order_id
        WHERE (:start_date IS NULL OR oi.date BETWEEN :start_date AND :end_date)
        ORDER BY oi.store_id, oi.ts_minute, oi.order_id, oi.product_id
    """

    last_date_by_store: dict[str, date] = {}
    daily_req_by_store: dict[str, int] = defaultdict(int)
    daily_ful_by_store: dict[str, int] = defaultdict(int)
    items_rows: list[dict[str, Any]] = []
    replenishment_rows: list[dict[str, Any]] = []
    supply_daily_rows: list[dict[str, Any]] = []
    ops_daily_rows: list[dict[str, Any]] = []
    writeoff_rows: list[dict[str, Any]] = []
    demand_shock_rows: list[dict[str, Any]] = []
    customer_daily_rows: list[dict[str, Any]] = []
    customer_event_rows: list[dict[str, Any]] = []
    assignment_rows_by_unit: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    assignment_effective_unit = args.experiment_unit
    assignment_fallback_used = False
    pending_receipts: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    day_ops: dict[tuple[str, date], dict[str, int]] = defaultdict(lambda: {"shrink_units": 0, "picking_loss_units": 0})
    with engine.begin() as conn:
        _assert_expected_db(conn, expected_db)
        competitor_map, competitor_daily_rows = _build_competitor_daily_map(
            conn=conn,
            raw_schema=raw_schema,
            run_id=args.run_id,
            enabled=args.enable_competitor_prices,
            shared_across_stores=args.competitor_shared_across_stores,
            competitor_seed=args.competitor_seed,
            ar=args.competitor_ar,
            noise_sigma=args.competitor_noise_sigma,
            promo_prob=args.competitor_promo_prob,
            promo_min=args.competitor_promo_min,
            promo_max=args.competitor_promo_max,
            reactive_mode=competitor_reactive_enabled,
            reactive_beta=args.competitor_reactive_beta,
            reactive_lag_days=args.competitor_reactive_lag_days,
            date_range=date_range,
        )
        demand_shock_map, demand_shock_rows = _build_demand_shock_daily_map(
            conn=conn,
            raw_schema=raw_schema,
            run_id=args.run_id,
            enabled=args.enable_demand_shocks,
            shock_prob=args.demand_shock_prob,
            shock_min=shock_min,
            shock_max=shock_max,
            date_range=date_range,
        )
    _flush_df(pd.DataFrame(competitor_daily_rows), engine, step1_schema, "step1_competitor_daily")
    _flush_df(pd.DataFrame(demand_shock_rows), engine, step1_schema, "step1_demand_shocks_daily")

    for chunk in pd.read_sql_query(text(query), engine, params=query_params, chunksize=args.chunk_size):
        for row in chunk.itertuples(index=False):
            store_id = row.store_id
            d = row.date
            if store_id not in last_date_by_store or last_date_by_store[store_id] != d:
                if dynamics_manager is not None and store_id in last_date_by_store:
                    prev_date = last_date_by_store[store_id]
                    req = daily_req_by_store.get(store_id, 0)
                    ful = daily_ful_by_store.get(store_id, 0)
                    daily_fill = (ful / req) if req > 0 else 1.0
                    events, daily = dynamics_manager.end_of_day(store_id, prev_date, daily_fill, args.run_id)
                    customer_event_rows.extend(events)
                    customer_daily_rows.append(daily)
                    daily_req_by_store[store_id] = 0
                    daily_ful_by_store[store_id] = 0
                if store_id in last_date_by_store:
                    prev_date = last_date_by_store[store_id]
                    prev_payload = day_ops.get((store_id, prev_date))
                    if prev_payload is not None:
                        ops_daily_rows.append(
                            {
                                "run_id": args.run_id,
                                "date": prev_date,
                                "store_id": store_id,
                                "shrink_units": int(prev_payload["shrink_units"]),
                                "picking_loss_units": int(prev_payload["picking_loss_units"]),
                            }
                        )
                        del day_ops[(store_id, prev_date)]
                if int(args.enable_ops_noise) == 1:
                    shrink_units = _apply_supply_shrink_for_day(
                        run_id=args.run_id,
                        d=d,
                        store_id=store_id,
                        lots_by_key=lots_by_key,
                        product_meta=product_meta,
                        shrink_rate_daily=args.shrink_rate_daily,
                    )
                    day_ops[(store_id, d)]["shrink_units"] += int(shrink_units)
                _apply_supply_receipts_for_day(
                    run_id=args.run_id,
                    d=d,
                    store_id=store_id,
                    lots_by_key=lots_by_key,
                    product_meta=product_meta,
                    pending_receipts=pending_receipts,
                    replenishment_rows=replenishment_rows,
                    supply_daily_rows=supply_daily_rows,
                )
                _schedule_supply_for_day(
                    run_id=args.run_id,
                    d=d,
                    store_id=store_id,
                    lots_by_key=lots_by_key,
                    targets_by_store=targets_by_store,
                    pending_receipts=pending_receipts,
                    enable_supply_realism=args.enable_supply_realism,
                    leadtime_days=args.replenishment_leadtime_days,
                    capacity_mult=args.replenishment_capacity_mult,
                    supplier_fill_rate=args.supplier_fill_rate,
                    noise_sigma=args.replenishment_noise_sigma,
                )
                _apply_pull_writeoff(
                    run_id=args.run_id,
                    d=d,
                    store_id=store_id,
                    lots_by_key=lots_by_key,
                    product_meta=product_meta,
                    remove_buffer_days=args.perishable_remove_buffer_days,
                    writeoff_rows=writeoff_rows,
                )
                last_date_by_store[store_id] = d

            if dynamics_manager is not None and not dynamics_manager.is_active(store_id, row.customer_id):
                continue

            row_experiment_id = None
            row_arm = None
            if experiment_enabled:
                unit_type = args.experiment_unit
                unit_id: str | None = None
                if unit_type == "customer":
                    raw_customer = getattr(row, "customer_id", None)
                    if raw_customer is not None and str(raw_customer).strip():
                        unit_id = str(raw_customer).strip()
                    else:
                        unit_type = "store"
                        unit_id = str(store_id)
                        assignment_fallback_used = True
                else:
                    unit_id = str(store_id)

                if unit_type != args.experiment_unit:
                    assignment_effective_unit = unit_type
                assignment_key = (args.run_id, str(args.experiment_id).strip(), unit_type, str(unit_id))
                if assignment_key not in assignment_rows_by_unit:
                    arm, hval = _assignment_arm(
                        experiment_id=str(args.experiment_id).strip(),
                        unit_id=str(unit_id),
                        treat_pct=int(args.experiment_treat_pct),
                        salt=experiment_salt,
                    )
                    assignment_rows_by_unit[assignment_key] = {
                        "run_id": args.run_id,
                        "experiment_id": str(args.experiment_id).strip(),
                        "unit_type": unit_type,
                        "unit_id": str(unit_id),
                        "arm": arm,
                        "split_pct": int(args.experiment_treat_pct),
                        "start_date": d,
                        "end_date": d + timedelta(days=max(1, int(args.horizon_days if args.horizon_days > 0 else 14)) - 1),
                        "assigned_at": d,
                        "assignment_hash": int(hval),
                        "assignment_salt": experiment_salt,
                        "assignment_version": "v1",
                    }
                row_experiment_id = str(args.experiment_id).strip()
                row_arm = str(assignment_rows_by_unit[assignment_key]["arm"])

            key = (store_id, row.product_id)
            on_hand = _on_hand_qty(lots_by_key, key)
            requested_base = int(row.requested_qty)

            k_segment = args.elasticity_k_base
            if row.customer_segment == "low" and args.elasticity_k_low is not None:
                k_segment = args.elasticity_k_low
            elif row.customer_segment == "mid" and args.elasticity_k_mid is not None:
                k_segment = args.elasticity_k_mid
            elif row.customer_segment == "high" and args.elasticity_k_high is not None:
                k_segment = args.elasticity_k_high

            discount = float(row.discount_pct or 0.0)
            discount = max(0.0, min(discount, 0.9))
            if args.enable_elasticity == 1 and args.elasticity_model == "linear" and k_segment > 0.0:
                mult = 1.0 + k_segment * discount
            else:
                mult = 1.0
                k_segment = 0.0 if args.enable_elasticity == 0 or args.elasticity_model == "none" else k_segment
            mult = max(args.elasticity_min_mult, min(mult, args.elasticity_cap_mult))
            competitor_key = (
                d,
                row.category_id,
                None if args.competitor_shared_across_stores == 1 else store_id,
            )
            competitor_point = competitor_map.get(
                competitor_key,
                {"competitor_price_index": 1.0, "promo_flag": 0, "promo_depth": 0.0},
            )
            competitor_index = float(competitor_point["competitor_price_index"])
            competitor_mult = 1.0
            if args.enable_competitor_prices == 1:
                competitor_mult = 1.0 + (args.competitor_demand_k * (competitor_index - 1.0))
                competitor_mult = max(args.competitor_min_mult, min(competitor_mult, args.competitor_max_mult))
            demand_shock_mult = demand_shock_map.get((d, store_id, row.category_id), 1.0)

            requested_adj = int(math.ceil(requested_base * mult * competitor_mult * demand_shock_mult))
            if requested_adj < 0:
                requested_adj = 0
            if args.enable_competitor_prices == 0 and requested_adj < requested_base:
                requested_adj = requested_base

            requested = requested_adj
            consumed_lots, fulfilled = _consume_lots(
                lots_by_key.get(key, []),
                requested_qty=requested,
                is_perishable=int(row.is_perishable),
            )
            lots_by_key[key] = consumed_lots
            picking_loss = 0
            if int(args.enable_ops_noise) == 1 and fulfilled > 0:
                picking_loss = _deterministic_binomial(
                    fulfilled,
                    args.picking_error_rate,
                    args.run_id,
                    "picking_loss",
                    row.order_id,
                    row.product_id,
                )
                if picking_loss > fulfilled:
                    picking_loss = fulfilled
                fulfilled = fulfilled - picking_loss
                day_ops[(store_id, d)]["picking_loss_units"] += int(picking_loss)
            lost = requested - fulfilled
            is_oos = 1 if lost > 0 else 0
            daily_req_by_store[store_id] += requested
            daily_ful_by_store[store_id] += fulfilled

            unit_price = Decimal(str(row.unit_price))
            unit_cogs = Decimal(str(row.unit_cogs))
            line_gmv_fulfilled = _money_round(unit_price * fulfilled)
            line_gp_fulfilled = _money_round((unit_price - unit_cogs) * fulfilled)
            lost_gmv_oos = _money_round(unit_price * lost)

            items_rows.append(
                {
                    "run_id": args.run_id,
                    "order_id": row.order_id,
                    "store_id": store_id,
                    "ts_minute": row.ts_minute,
                    "date": d,
                    "product_id": row.product_id,
                    "category_id": row.category_id,
                    "is_perishable": int(row.is_perishable),
                    "requested_qty_base": requested_base,
                    "requested_qty_adj": requested_adj,
                    "elasticity_mult": mult * competitor_mult * demand_shock_mult,
                    "elasticity_k": k_segment,
                    "requested_qty": requested,
                    "fulfilled_qty": fulfilled,
                    "lost_qty": lost,
                    "is_oos": is_oos,
                    "competitor_price_index": competitor_index,
                    "competitor_mult": competitor_mult,
                    "list_price": float(_money_round(Decimal(str(row.list_price)))),
                    "unit_cogs": float(_money_round(unit_cogs)),
                    "discount_pct": row.discount_pct,
                    "unit_price": float(_money_round(unit_price)),
                    "line_gmv_requested": float(_money_round(Decimal(str(row.line_gmv_requested)))),
                    "line_gp_requested": float(_money_round(Decimal(str(row.line_gp_requested)))),
                    "line_gmv_fulfilled": float(line_gmv_fulfilled),
                    "line_gp_fulfilled": float(line_gp_fulfilled),
                    "lost_gmv_oos": float(lost_gmv_oos),
                    "customer_segment": row.customer_segment,
                    "experiment_id": row_experiment_id,
                    "arm": row_arm,
                }
            )

        if len(items_rows) >= args.chunk_size:
            _flush_df(pd.DataFrame(items_rows), engine, step1_schema, "step1_order_items")
            items_rows = []
        if len(replenishment_rows) >= args.chunk_size:
            _flush_df(pd.DataFrame(replenishment_rows), engine, step1_schema, "step1_replenishment_log")
            replenishment_rows = []
        if len(supply_daily_rows) >= args.chunk_size:
            _flush_df(pd.DataFrame(supply_daily_rows), engine, step1_schema, "step1_supply_daily")
            supply_daily_rows = []
        if len(ops_daily_rows) >= args.chunk_size:
            _flush_df(pd.DataFrame(ops_daily_rows), engine, step1_schema, "step1_ops_daily")
            ops_daily_rows = []
        if len(writeoff_rows) >= args.chunk_size:
            _flush_df(pd.DataFrame(writeoff_rows), engine, step1_schema, "step1_writeoff_log")
            writeoff_rows = []
        if len(customer_daily_rows) >= args.chunk_size:
            _flush_df(pd.DataFrame(customer_daily_rows), engine, step1_schema, "step1_customer_daily")
            customer_daily_rows = []
        if len(customer_event_rows) >= args.chunk_size:
            _flush_df(pd.DataFrame(customer_event_rows), engine, step1_schema, "step1_customer_events")
            customer_event_rows = []

    _flush_df(pd.DataFrame(items_rows), engine, step1_schema, "step1_order_items")
    _flush_df(pd.DataFrame(replenishment_rows), engine, step1_schema, "step1_replenishment_log")
    _flush_df(pd.DataFrame(supply_daily_rows), engine, step1_schema, "step1_supply_daily")
    _flush_df(pd.DataFrame(writeoff_rows), engine, step1_schema, "step1_writeoff_log")
    _flush_df(pd.DataFrame(customer_daily_rows), engine, step1_schema, "step1_customer_daily")
    _flush_df(pd.DataFrame(customer_event_rows), engine, step1_schema, "step1_customer_events")
    assignment_rows = []
    if experiment_enabled:
        assignment_rows = list(assignment_rows_by_unit.values())
        if assignment_rows:
            with engine.begin() as conn:
                existing = conn.execute(
                    text(
                        f"""
                        SELECT unit_type, unit_id
                        FROM {step1_schema}.step1_experiment_assignment_log
                        WHERE run_id = :run_id AND experiment_id = :experiment_id
                        """
                    ),
                    {"run_id": args.run_id, "experiment_id": str(args.experiment_id).strip()},
                ).fetchall()
            existing_keys = {(str(r[0]), str(r[1])) for r in existing}
            assignment_rows = [
                r for r in assignment_rows if (str(r["unit_type"]), str(r["unit_id"])) not in existing_keys
            ]
        _flush_df(
            pd.DataFrame(assignment_rows),
            engine,
            step1_schema,
            "step1_experiment_assignment_log",
        )

    if dynamics_manager is not None:
        for store_id, prev_date in last_date_by_store.items():
            req = daily_req_by_store.get(store_id, 0)
            ful = daily_ful_by_store.get(store_id, 0)
            daily_fill = (ful / req) if req > 0 else 1.0
            events, daily = dynamics_manager.end_of_day(store_id, prev_date, daily_fill, args.run_id)
            _flush_df(pd.DataFrame(events), engine, step1_schema, "step1_customer_events")
            _flush_df(pd.DataFrame([daily]), engine, step1_schema, "step1_customer_daily")

    for (ops_store, ops_date), payload in list(day_ops.items()):
        ops_daily_rows.append(
            {
                "run_id": args.run_id,
                "date": ops_date,
                "store_id": ops_store,
                "shrink_units": int(payload["shrink_units"]),
                "picking_loss_units": int(payload["picking_loss_units"]),
            }
        )
        del day_ops[(ops_store, ops_date)]
    _flush_df(pd.DataFrame(ops_daily_rows), engine, step1_schema, "step1_ops_daily")

    with engine.begin() as conn:
        _assert_expected_db(conn, expected_db)
        conn.execute(
            text(
                f"""
                INSERT INTO {step1_schema}.step1_orders (
                    run_id,
                    order_id,
                    store_id,
                    date,
                    customer_id,
                    customer_segment,
                    order_gmv,
                    order_gp,
                    requested_units_base,
                    requested_units,
                    elasticity_units_uplift,
                    fulfilled_units,
                    order_fill_rate_units,
                    order_lost_gmv_oos,
                    experiment_id,
                    arm
                )
                SELECT
                    oi.run_id,
                    oi.order_id,
                    oi.store_id,
                    oi.date,
                    MAX(os.customer_id) AS customer_id,
                    oi.customer_segment,
                    ROUND(SUM(oi.line_gmv_fulfilled)::numeric, 2) AS order_gmv,
                    ROUND(SUM(oi.line_gp_fulfilled)::numeric, 2) AS order_gp,
                    SUM(oi.requested_qty_base) AS requested_units_base,
                    SUM(oi.requested_qty) AS requested_units,
                    (SUM(oi.requested_qty) - SUM(oi.requested_qty_base)) AS elasticity_units_uplift,
                    SUM(oi.fulfilled_qty) AS fulfilled_units,
                    CASE WHEN SUM(oi.requested_qty) > 0
                        THEN SUM(oi.fulfilled_qty)::DOUBLE PRECISION / SUM(oi.requested_qty)
                        ELSE 1.0
                    END AS order_fill_rate_units,
                    ROUND(SUM(oi.lost_gmv_oos)::numeric, 2) AS order_lost_gmv_oos,
                    MAX(oi.experiment_id) AS experiment_id,
                    MAX(oi.arm) AS arm
                FROM {step1_schema}.step1_order_items oi
                LEFT JOIN raw.raw_orders_stream os
                  ON os.order_id = oi.order_id
                 AND os.store_id = oi.store_id
                 AND os.date = oi.date
                WHERE oi.run_id = :r
                GROUP BY oi.run_id, oi.order_id, oi.store_id, oi.date, oi.customer_segment;
                """
            ),
            {"r": args.run_id},
        )
        final_config_json = vars(args).copy()
        final_config_json.pop("pg_url", None)
        final_config_json["realism_knobs"] = {
            "enable_supply_realism": int(args.enable_supply_realism),
            "replenishment_leadtime_days": int(args.replenishment_leadtime_days),
            "replenishment_capacity_mult": float(args.replenishment_capacity_mult),
            "replenishment_noise_sigma": float(args.replenishment_noise_sigma),
            "supplier_fill_rate": float(args.supplier_fill_rate),
            "enable_ops_noise": int(args.enable_ops_noise),
            "picking_error_rate": float(args.picking_error_rate),
            "shrink_rate_daily": float(args.shrink_rate_daily),
            "enable_demand_shocks": int(args.enable_demand_shocks),
            "demand_shock_prob": float(args.demand_shock_prob),
            "demand_shock_mult_range": str(args.demand_shock_mult_range),
            "enable_competitor_prices": int(args.enable_competitor_prices),
            "competitor_reactive_mode": competitor_reactive_enabled,
            "competitor_reaction_mode": str(args.competitor_reaction_mode),
            "competitor_shared_across_stores": int(args.competitor_shared_across_stores),
            "perishable_remove_buffer_days": int(args.perishable_remove_buffer_days),
        }
        assignment_rows_count = 0
        orders_with_experiment_count = 0
        if experiment_enabled:
            assignment_rows_count = int(
                conn.execute(
                    text(
                        f"""
                        SELECT COUNT(*)
                        FROM {step1_schema}.step1_experiment_assignment_log
                        WHERE run_id = :r AND experiment_id = :e
                        """
                    ),
                    {"r": args.run_id, "e": str(args.experiment_id).strip()},
                ).scalar()
                or 0
            )
            if assignment_rows_count == 0:
                if args.experiment_unit == "customer":
                    conn.execute(
                        text(
                            f"""
                            INSERT INTO {step1_schema}.step1_experiment_assignment_log
                            (run_id, experiment_id, unit_type, unit_id, arm, split_pct, start_date, end_date, assigned_at, assignment_hash, assignment_salt, assignment_version)
                            SELECT
                              :r,
                              :e,
                              'customer',
                              os.customer_id,
                              COALESCE(MAX(o.arm), 'control') AS arm,
                              :pct,
                              MIN(o.date),
                              MAX(o.date),
                              MIN(o.date),
                              0,
                              :salt,
                              'v1_recovered'
                            FROM {step1_schema}.step1_orders o
                            JOIN raw.raw_orders_stream os ON os.order_id = o.order_id
                            WHERE o.run_id = :r AND o.experiment_id = :e
                            GROUP BY os.customer_id
                            """
                        ),
                        {
                            "r": args.run_id,
                            "e": str(args.experiment_id).strip(),
                            "pct": int(args.experiment_treat_pct),
                            "salt": experiment_salt,
                        },
                    )
                else:
                    conn.execute(
                        text(
                            f"""
                            INSERT INTO {step1_schema}.step1_experiment_assignment_log
                            (run_id, experiment_id, unit_type, unit_id, arm, split_pct, start_date, end_date, assigned_at, assignment_hash, assignment_salt, assignment_version)
                            SELECT
                              :r,
                              :e,
                              'store',
                              o.store_id,
                              COALESCE(MAX(o.arm), 'control') AS arm,
                              :pct,
                              MIN(o.date),
                              MAX(o.date),
                              MIN(o.date),
                              0,
                              :salt,
                              'v1_recovered'
                            FROM {step1_schema}.step1_orders o
                            WHERE o.run_id = :r AND o.experiment_id = :e
                            GROUP BY o.store_id
                            """
                        ),
                        {
                            "r": args.run_id,
                            "e": str(args.experiment_id).strip(),
                            "pct": int(args.experiment_treat_pct),
                            "salt": experiment_salt,
                        },
                    )
                assignment_rows_count = int(
                    conn.execute(
                        text(
                            f"""
                            SELECT COUNT(*)
                            FROM {step1_schema}.step1_experiment_assignment_log
                            WHERE run_id = :r AND experiment_id = :e
                            """
                        ),
                        {"r": args.run_id, "e": str(args.experiment_id).strip()},
                    ).scalar()
                    or 0
                )
            orders_with_experiment_count = int(
                conn.execute(
                    text(
                        f"""
                        SELECT COUNT(*)
                        FROM {step1_schema}.step1_orders
                        WHERE run_id = :r AND experiment_id = :e
                        """
                    ),
                    {"r": args.run_id, "e": str(args.experiment_id).strip()},
                ).scalar()
                or 0
            )
        final_config_json["assignment_status"] = (
            "ready" if (experiment_enabled and assignment_rows_count > 0) else "missing"
        )
        final_config_json["experiment_id"] = str(args.experiment_id or "").strip()
        final_config_json["experiment_unit"] = args.experiment_unit
        final_config_json["experiment_unit_effective"] = assignment_effective_unit
        final_config_json["experiment_treat_pct"] = int(args.experiment_treat_pct)
        final_config_json["experiment_salt"] = experiment_salt
        final_config_json["assignment_rows"] = int(assignment_rows_count)
        final_config_json["orders_with_experiment_rows"] = int(orders_with_experiment_count)
        final_config_json["assignment_fallback_used"] = bool(assignment_fallback_used)
        _ensure_run_registry(conn, args.run_id, args.mode_tag, feature_flags, final_config_json)

    print("ok: step1 simulation complete")


if __name__ == "__main__":
    main()
