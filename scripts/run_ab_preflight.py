#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import traceback

from pathlib import Path

from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from run_ab_analysis import (
    _assert_local_dsn,
    _assignment_counts,
    _detect_assignment_source,
    _detect_order_source,
    _orders_with_experiment_rows,
    _read_experiment_from_registry,
    _read_run_config,
    _resolve_estimand_contract,
    _resolve_dsn,
    _run_ab_preflight,
    _write_preflight_artifacts,
)
from src.client_db_config import client_db_service


DEFAULT_SERVICE = client_db_service("app")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AB preflight validation (data-contract / join / assignment)")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--primary-metric", default="")
    parser.add_argument("--pgservice", default=DEFAULT_SERVICE)
    args = parser.parse_args()

    run_id = args.run_id
    dsn = _resolve_dsn(args.pgservice)
    _assert_local_dsn(dsn)
    log_path = Path(f"data/logs/ab_preflight_{run_id}.log")

    try:
        engine = create_engine(dsn)
        with engine.begin() as conn:
            conn.execute(text("SET LOCAL statement_timeout = '15s';"))
            conn.execute(text("SET TRANSACTION READ ONLY;"))

            exp_id = str(args.experiment_id or "").strip()
            reg_exp_id, reg_unit = (None, None)
            if not exp_id:
                reg_exp_id, reg_unit = _read_experiment_from_registry(conn, run_id)
            run_cfg = _read_run_config(conn, run_id)
            if not exp_id:
                exp_id = reg_exp_id or ""
            requested_unit = str(reg_unit or run_cfg.get("experiment_unit") or "customer").strip().lower()
            cli_primary_metric = str(args.__dict__.get("primary_metric") or "").strip().lower()
            contract_ctx, contract_issues = _resolve_estimand_contract(
                run_cfg,
                cli_primary_metric=cli_primary_metric,
                requested_unit=requested_unit,
            )
            contract_ctx["_issues"] = contract_issues
            primary_metric = str(contract_ctx.get("primary_metric_id", "")).strip().lower()

            orders_table = _detect_order_source(conn)
            assignment_source = _detect_assignment_source(conn)
            assignment_counts = _assignment_counts(conn, run_id, exp_id, assignment_source) if exp_id else {"customer": {"control": 0, "treatment": 0}, "store": {"control": 0, "treatment": 0}}
            smoke_orders_experiment = _orders_with_experiment_rows(conn, run_id, exp_id, orders_table) if exp_id else None

            payload = _run_ab_preflight(
                conn,
                run_id=run_id,
                experiment_id=exp_id or "missing",
                requested_unit=requested_unit,
                primary_metric=primary_metric,
                orders_table=orders_table,
                assignment_source=assignment_source,
                assignment_counts=assignment_counts,
                smoke_orders_experiment=smoke_orders_experiment,
                contract_context=contract_ctx,
            )
            _write_preflight_artifacts(payload)
            print(f"ok: ab preflight written for run_id={run_id}")
    except Exception as exc:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(f"{exc}\n{traceback.format_exc()}", encoding="utf-8")
        payload = {
            "run_id": run_id,
            "experiment_id": str(args.experiment_id or "unknown"),
            "generated_at": "",
            "status": "FAIL",
            "pipeline_status": "FAIL",
            "measurement_state": "UNOBSERVABLE",
            "primary_metric": None,
            "error_family": "RUNTIME",
            "error_code": "AB_PREFLIGHT_RUNTIME_ERROR",
            "error_detail": f"See log: {log_path}",
            "checks": [],
            "version": "ab_preflight.v1",
        }
        _write_preflight_artifacts(payload)
        print(f"ok: ab preflight written for run_id={run_id} (fallback)")


if __name__ == "__main__":
    main()
