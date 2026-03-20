#!/usr/bin/env python3
"""
Captain Sanity v0: deterministic DQ gate for a given run_id.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import enforce_service_dsn_policy, write_sha256_sidecar

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")


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


def _print_table(rows: list[dict[str, Any]]) -> None:
    headers = ["check_name", "severity", "status", "actual_value", "message"]
    widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            widths[h] = max(widths[h], len(str(r.get(h, ""))))
    line = " | ".join(h.ljust(widths[h]) for h in headers)
    sep = "-+-".join("-" * widths[h] for h in headers)
    print(line)
    print(sep)
    for r in rows:
        print(" | ".join(str(r.get(h, "")).ljust(widths[h]) for h in headers))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run DQ checks for a run_id")
    parser.add_argument("--run-id", required=True, help="Run ID to validate")
    parser.add_argument("--pg-url", default=None, help="Database URL or service-based connection (no password in args; use ~/.pgpass)")
    args = parser.parse_args()

    pg_url = _resolve_pg_url(args.pg_url)
    _assert_local_dsn(pg_url)

    engine = _get_engine(pg_url)

    report_dir = Path("data/dq_reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    registry_row: dict[str, Any] | None = None
    with engine.begin() as conn:
        reg = conn.execute(
            text(
                """
                SELECT run_id, created_at, mode_tag, feature_flags, config_json
                FROM step1.step1_run_registry
                WHERE run_id = :r
                """
            ),
            {"r": args.run_id},
        ).mappings().first()
        if reg:
            registry_row = dict(reg)

    rows: list[dict[str, Any]] = []
    pre_rows: list[dict[str, Any]] = []
    if registry_row is None:
        with engine.begin() as conn:
            has_items = conn.execute(
                text(
                    "SELECT 1 FROM step1.step1_order_items WHERE run_id = :r LIMIT 1"
                ),
                {"r": args.run_id},
            ).fetchone()
            has_orders = conn.execute(
                text(
                    "SELECT 1 FROM step1.step1_orders WHERE run_id = :r LIMIT 1"
                ),
                {"r": args.run_id},
            ).fetchone()
        if has_items or has_orders:
            pre_rows.append(
                {
                    "check_name": "registry_present",
                    "severity": "WARN",
                    "status": "WARN",
                    "actual_value": "",
                    "message": "Run exists in step1 tables but is missing registry entry (legacy run).",
                }
            )
            registry_row = {
                "run_id": args.run_id,
                "created_at": None,
                "mode_tag": "default",
                "feature_flags": {},
                "config_json": {},
            }
        else:
            rows.append(
                {
                    "check_name": "registry_present",
                    "severity": "HARD_FAIL",
                    "status": "FAIL",
                    "actual_value": "",
                    "message": "run_registry missing for run_id",
                }
            )
            summary = {
                "PASS": 0,
                "WARN": 0,
                "FAIL": 1,
                "SKIP": 0,
                "HARD_FAIL": 1,
            }
            report = {
                "run_id": args.run_id,
                "created_at": None,
                "mode_tag": None,
                "feature_flags": {},
                "config_json": {},
                "summary": summary,
                "rows": rows,
            }
            _print_table(rows)
            out_path = report_dir / f"{args.run_id}.json"
            out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            write_sha256_sidecar(out_path)
            raise SystemExit(1)

    dq_sql = Path("v1/sql/dq/dq_checks.sql").read_text(encoding="utf-8")
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL statement_timeout = '15s';"))
        conn.execute(text("SET LOCAL idle_in_transaction_session_timeout = '15s';"))
        conn.execute(text("SET TRANSACTION READ ONLY;"))
        result = conn.execute(text(dq_sql), {"run_id": args.run_id}).mappings().all()
        rows = pre_rows + [dict(r) for r in result]

    summary = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0}
    hard_fail = False
    any_warn = False
    for r in rows:
        status = r.get("status", "")
        severity = r.get("severity", "")
        if status in summary:
            summary[status] += 1
        if severity == "HARD_FAIL" and status == "FAIL":
            hard_fail = True
        if status == "WARN":
            any_warn = True

    qa_status = "FAIL" if hard_fail else ("WARN" if any_warn else "PASS")

    report = {
        "run_id": registry_row.get("run_id"),
        "created_at": str(registry_row.get("created_at")),
        "mode_tag": registry_row.get("mode_tag"),
        "feature_flags": registry_row.get("feature_flags"),
        "config_json": registry_row.get("config_json"),
        "summary": summary,
        "rows": rows,
    }

    _print_table(rows)
    out_path = report_dir / f"{args.run_id}.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out_path)

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO step1.step1_run_registry(run_id, mode_tag, feature_flags, config_json)
                VALUES (:run_id, 'legacy', '{}'::jsonb, '{}'::jsonb)
                ON CONFLICT (run_id) DO NOTHING
                """
            ),
            {"run_id": args.run_id},
        )
        conn.execute(
            text(
                """
                UPDATE step1.step1_run_registry
                SET qa_status = :qa_status,
                    qa_updated_at = now(),
                    qa_summary = CAST(:qa_summary AS jsonb)
                WHERE run_id = :run_id
                """
            ),
            {
                "qa_status": qa_status,
                "qa_summary": json.dumps(summary),
                "run_id": args.run_id,
            },
        )

    if hard_fail:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
