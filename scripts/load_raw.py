#!/usr/bin/env python3
"""
Load RAW CSV files into Postgres schema raw.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import sys
from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.client_db_config import client_db_name
from src.security_utils import enforce_service_dsn_policy

TABLES = [
    "raw_categories",
    "raw_products",
    "raw_customers",
    "raw_day_scenarios",
    "raw_intraday_shocks",
    "raw_time_factors",
    "raw_orders_stream",
    "raw_order_items",
    "raw_initial_inventory",
]

EXPECTED_HEADERS = {
    "raw_categories": [
        "category_id",
        "category_name",
        "storage_type",
        "perishable_policy",
    ],
    "raw_products": [
        "product_id",
        "product_name",
        "category_id",
        "category_name",
        "storage_type",
        "unit",
        "substitute_group_id",
        "is_perishable",
        "expiry_days",
        "list_price",
        "unit_cogs",
        "max_discount_pct",
        "weight_kg",
        "popularity_weight",
    ],
    "raw_customers": [
        "customer_id",
        "customer_segment",
        "activity_weight",
        "initial_status",
        "home_store_id",
    ],
    "raw_day_scenarios": [
        "date",
        "season",
        "is_weekend",
        "is_holiday",
        "is_preholiday",
        "weather_bad",
        "local_event",
        "scenario_type",
        "intensity",
        "affected_store",
    ],
    "raw_intraday_shocks": [
        "date",
        "store_id",
        "shock_start_ts",
        "shock_end_ts",
        "shock_intensity",
        "shock_class",
        "shock_type",
    ],
    "raw_time_factors": [
        "ts",
        "date",
        "store_id",
        "hour",
        "season",
        "is_weekend",
        "is_holiday",
        "is_preholiday",
        "weather_bad",
        "local_event",
        "hourly_multiplier",
        "day_multiplier",
        "shock_multiplier",
        "demand_multiplier",
    ],
    "raw_orders_stream": [
        "ts_minute",
        "date",
        "store_id",
        "order_id",
        "customer_id",
        "customer_segment",
        "base_intent_value",
        "budget_signal",
        "is_floor_fill",
        "basket_size",
        "units_total",
    ],
    "raw_order_items": [
        "order_id",
        "product_id",
        "requested_qty",
        "is_perishable",
        "category_id",
        "store_id",
        "ts_minute",
        "date",
        "list_price",
        "unit_cogs",
        "discount_pct",
        "unit_price",
        "line_gmv_requested",
        "line_gp_requested",
    ],
    "raw_initial_inventory": [
        "as_of_date",
        "store_id",
        "product_id",
        "initial_qty",
        "batch_id",
        "supplier_id",
        "purchase_order_id",
    ],
}

OPTIONAL_HEADERS = {
    "raw_initial_inventory": ["batch_id", "supplier_id", "purchase_order_id"],
}

CRITICAL_COLS = {
    "raw_customers": ["customer_id", "customer_segment"],
    "raw_orders_stream": ["order_id", "store_id", "ts_minute", "date"],
    "raw_order_items": [
        "order_id",
        "store_id",
        "ts_minute",
        "date",
        "product_id",
        "requested_qty",
        "unit_price",
        "unit_cogs",
    ],
    "raw_initial_inventory": ["store_id", "product_id", "as_of_date", "initial_qty"],
}

TABLE_CONFIG = {
    "raw_categories": {
        "date_cols": [],
        "ts_cols": [],
        "int_cols": [],
        "float_cols": [],
    },
    "raw_products": {
        "date_cols": [],
        "ts_cols": [],
        "int_cols": ["is_perishable", "expiry_days"],
        "float_cols": [
            "list_price",
            "unit_cogs",
            "max_discount_pct",
            "weight_kg",
            "popularity_weight",
        ],
    },
    "raw_customers": {
        "date_cols": [],
        "ts_cols": [],
        "int_cols": [],
        "float_cols": ["activity_weight"],
    },
    "raw_day_scenarios": {
        "date_cols": ["date"],
        "ts_cols": [],
        "int_cols": [
            "is_weekend",
            "is_holiday",
            "is_preholiday",
            "weather_bad",
            "local_event",
        ],
        "float_cols": ["intensity"],
    },
    "raw_intraday_shocks": {
        "date_cols": ["date"],
        "ts_cols": ["shock_start_ts", "shock_end_ts"],
        "int_cols": [],
        "float_cols": ["shock_intensity"],
    },
    "raw_time_factors": {
        "date_cols": ["date"],
        "ts_cols": ["ts"],
        "int_cols": [
            "hour",
            "is_weekend",
            "is_holiday",
            "is_preholiday",
            "weather_bad",
            "local_event",
        ],
        "float_cols": [
            "hourly_multiplier",
            "day_multiplier",
            "shock_multiplier",
            "demand_multiplier",
        ],
    },
    "raw_orders_stream": {
        "date_cols": ["date"],
        "ts_cols": ["ts_minute"],
        "int_cols": ["is_floor_fill", "basket_size", "units_total"],
        "float_cols": ["base_intent_value", "budget_signal"],
    },
    "raw_order_items": {
        "date_cols": ["date"],
        "ts_cols": ["ts_minute"],
        "int_cols": ["requested_qty", "is_perishable"],
        "float_cols": [
            "list_price",
            "unit_cogs",
            "discount_pct",
            "unit_price",
            "line_gmv_requested",
            "line_gp_requested",
        ],
    },
    "raw_initial_inventory": {
        "date_cols": ["as_of_date"],
        "ts_cols": [],
        "int_cols": ["initial_qty"],
        "float_cols": [],
    },
}

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")


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


def _resolve_pg_url(arg_pg_url: str | None) -> str:
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        enforce_service_dsn_policy(database_url, "DATABASE_URL")
    service = os.getenv("PGSERVICE")
    pg_url = os.getenv("PG_DSN") or arg_pg_url or database_url
    if not pg_url and service:
        pg_url = f"postgresql:///?service={service}"
    if not pg_url:
        raise SystemExit("Missing PG_DSN/DATABASE_URL/PGSERVICE or --pg-url (service-based DSN only; use ~/.pgpass)")
    enforce_service_dsn_policy(pg_url, "PG_DSN/DATABASE_URL/--pg-url")
    return pg_url


def _read_header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8") as f:
        return next(csv.reader(f))


def _assert_headers_exact(path: Path, expected: list[str]) -> None:
    got = _read_header(path)
    if got != expected:
        raise SystemExit(
            f"CSV header mismatch: {path}\n"
            f"Expected: {expected}\n"
            f"Got:      {got}"
        )


def _assert_headers_with_optional(path: Path, expected: list[str], optional: list[str]) -> None:
    got = _read_header(path)
    required = [x for x in expected if x not in optional]
    if got == expected:
        return
    if got == required:
        return
    raise SystemExit(
        f"CSV header mismatch: {path}\n"
        f"Expected (full): {expected}\n"
        f"Expected (legacy): {required}\n"
        f"Got:            {got}"
    )


def _table_columns(conn, schema_name: str, table_name: str) -> set[str]:
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
    return {str(r[0]) for r in rows}


def _assert_no_nulls(df: pd.DataFrame, cols: list[str], table: str) -> None:
    bad = {c: int(df[c].isna().sum()) for c in cols if c in df.columns}
    bad = {c: n for c, n in bad.items() if n > 0}
    if bad:
        raise SystemExit(f"Nulls after parsing in {table}: {bad}. Check source CSV formats.")


def _assign_home_store_id(customer_id: str, store_ids: list[str]) -> str:
    h = hashlib.sha256(customer_id.encode("utf-8")).hexdigest()
    idx = int(h[:8], 16) % len(store_ids)
    return store_ids[idx]


def _load_csv(path: Path, cfg: dict) -> pd.DataFrame:
    df = pd.read_csv(path)
    for col in cfg.get("date_cols", []):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce").dt.date
    for col in cfg.get("ts_cols", []):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")
    for col in cfg.get("int_cols", []):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
    for col in cfg.get("float_cols", []):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Load RAW CSV into Postgres schema raw")
    parser.add_argument("--pg-url", default=None, help="Database URL or service-based connection (no password in args; use ~/.pgpass)")
    parser.add_argument("--raw-dir", required=True, help="Path to RAW directory (e.g. v0/data/raw/V0)")
    parser.add_argument("--allow-truncate-raw", type=int, default=0, help="Allow TRUNCATE raw.* (0/1)")
    parser.add_argument("--allow-legacy-customers", action="store_true", help="Allow legacy raw_customers without new columns")
    parser.add_argument("--initial-active-customers", type=int, default=800, help="Legacy: initial active customers")
    args = parser.parse_args()

    pg_url = _resolve_pg_url(args.pg_url)
    _assert_local_dsn(pg_url)

    raw_dir = Path(args.raw_dir)
    engine = create_engine(pg_url)
    expected_db = os.getenv("PG_EXPECTED_DB", client_db_name())

    with engine.begin() as conn:
        _assert_expected_db(conn, expected_db)
        raw_schema = _assert_safe_ident("raw", "raw schema")
        safe_tables = [_assert_safe_ident(t, "raw table") for t in TABLES]
        if args.allow_truncate_raw == 1:
            table_list = ", ".join([_qualified_name(raw_schema, t) for t in safe_tables])
            conn.execute(text("TRUNCATE " + table_list + " CASCADE;"))
        else:
            for t in safe_tables:
                exists = conn.execute(
                    text("SELECT 1 FROM " + _qualified_name(raw_schema, t) + " LIMIT 1;")
                ).fetchone()
                if exists:
                    raise SystemExit(
                        "RAW schema not empty. Re-run with --allow-truncate-raw 1 to truncate raw tables."
                    )

    legacy_customer_headers = [
        ["customer_id", "customer_segment", "activity_weight"],
        ["customer_id", "customer_segment", "activity_weight", "initial_status"],
    ]

    for table in TABLES:
        csv_path = raw_dir / f"{table}.csv"
        if not csv_path.exists():
            raise FileNotFoundError(csv_path)
        expected = EXPECTED_HEADERS.get(table)
        if expected:
            if table == "raw_customers" and args.allow_legacy_customers:
                got = _read_header(csv_path)
                if got != expected and got not in legacy_customer_headers:
                    _assert_headers_exact(csv_path, expected)
            elif table in OPTIONAL_HEADERS:
                _assert_headers_with_optional(csv_path, expected, OPTIONAL_HEADERS[table])
            else:
                _assert_headers_exact(csv_path, expected)
        cfg = TABLE_CONFIG.get(table, {})
        df = _load_csv(csv_path, cfg)
        if table in OPTIONAL_HEADERS:
            for col in OPTIONAL_HEADERS[table]:
                if col not in df.columns:
                    df[col] = None
        if table == "raw_customers" and args.allow_legacy_customers:
            if "initial_status" not in df.columns:
                n = len(df)
                active_n = min(max(int(args.initial_active_customers), 0), n)
                df["initial_status"] = ["active"] * active_n + ["reserve"] * (n - active_n)
            if "home_store_id" not in df.columns:
                store_ids = ["A", "B"]
                df["home_store_id"] = df["customer_id"].apply(lambda c: _assign_home_store_id(str(c), store_ids))
        if table == "raw_customers" and not args.allow_legacy_customers:
            _assert_no_nulls(df, ["initial_status", "home_store_id"], table)
        _assert_no_nulls(df, CRITICAL_COLS.get(table, []), table)
        with engine.begin() as conn:
            target_cols = _table_columns(conn, "raw", table)
        keep_cols = [c for c in df.columns if c in target_cols]
        if not keep_cols:
            raise SystemExit(f"No compatible columns for raw.{table}; apply schema migration or check source CSV.")
        if len(keep_cols) < len(df.columns):
            dropped = [c for c in df.columns if c not in target_cols]
            print(f"WARN: dropping non-schema columns for raw.{table}: {dropped}")
        df[keep_cols].to_sql(table, engine, schema="raw", if_exists="append", index=False, method="multi", chunksize=20000)

    print("ok: raw tables loaded")


if __name__ == "__main__":
    main()
