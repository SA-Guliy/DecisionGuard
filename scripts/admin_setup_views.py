#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.client_db_config import client_db_service, expected_db, resolve_pg_url


class PsqlRunError(RuntimeError):
    def __init__(self, returncode: int) -> None:
        super().__init__(f"psql failed with exit code {returncode}")
        self.returncode = returncode


def _write_log(log_file: Path, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    with log_file.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}] {message}\n")


def _parse_allowed_users(raw: str) -> set[str]:
    users = {x.strip() for x in raw.split(",") if x.strip()}
    return users


def _is_loopback(addr: str) -> bool:
    try:
        return ip_address(addr).is_loopback
    except ValueError:
        return False


def _preflight(engine, expected_db: str, allowed_users: set[str], allow_nonlocal: bool) -> dict[str, str | int | None]:
    row = engine.connect().execute(
        text(
            """
            SELECT
                current_database() AS db,
                inet_server_addr()::text AS addr,
                inet_server_port() AS port,
                session_user::text AS session_user,
                current_user::text AS current_user,
                current_role::text AS current_role
            """
        )
    ).mappings().first()
    if row is None:
        raise RuntimeError("preflight query returned no rows")

    db = row["db"]
    addr = row["addr"]
    current_user = row["current_user"]

    if db != expected_db:
        raise RuntimeError("unexpected database")

    if addr is not None and not allow_nonlocal and not _is_loopback(addr):
        raise RuntimeError("non-local database address is blocked")

    if current_user not in allowed_users:
        raise RuntimeError("current_user is not allowed for admin setup")

    return {
        "db": db,
        "addr": addr,
        "port": row["port"],
        "session_user": row["session_user"],
        "current_user": current_user,
        "current_role": row["current_role"],
    }


def _run_psql(pgservice: str, expected_db: str, views_sql: Path, grants_sql: Path, log_file: Path) -> None:
    env = os.environ.copy()
    env.update(
        {
            "PGSERVICE": pgservice,
            "PGDATABASE": expected_db,
            "PGOPTIONS": "-c search_path=pg_catalog",
        }
    )
    cmd = [
        "psql",
        "-X",
        "-q",
        "-v",
        "ON_ERROR_STOP=1",
        "--single-transaction",
        "-f",
        str(views_sql),
        "-f",
        str(grants_sql),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        _write_log(log_file, "psql execution failed")
        if result.stdout:
            _write_log(log_file, "psql stdout:\n" + result.stdout)
        if result.stderr:
            _write_log(log_file, "psql stderr:\n" + result.stderr)
        raise PsqlRunError(result.returncode)


def _postcheck(engine, views_schema: str, allowed_users: set[str]) -> None:
    view_names = ["vw_valid_orders", "vw_valid_order_items", "vw_valid_customer_daily"]
    with engine.connect() as conn:
        for view_name in view_names:
            fq = f"{views_schema}.{view_name}"
            exists = conn.execute(text("SELECT to_regclass(:n)"), {"n": fq}).scalar()
            if exists is None:
                raise RuntimeError(f"missing required view: {fq}")

        owner_rows = conn.execute(
            text(
                """
                SELECT schemaname, viewname, viewowner
                FROM pg_catalog.pg_views
                WHERE schemaname = :schema
                  AND viewname = ANY(:view_names)
                """
            ),
            {"schema": views_schema, "view_names": view_names},
        ).mappings().all()

    if len(owner_rows) != len(view_names):
        raise RuntimeError("view owner check failed: missing rows in pg_views")

    for row in owner_rows:
        if row["viewowner"] not in allowed_users:
            raise RuntimeError("security drift: unexpected view owner")


def main() -> None:
    parser = argparse.ArgumentParser(description="One-time admin setup for DQ views/grants")
    parser.add_argument("--pgservice", default=client_db_service("admin"))
    parser.add_argument("--expected-db", default=expected_db())
    parser.add_argument("--views-sql", default="v1/sql/dq/dq_views.sql")
    parser.add_argument("--grants-sql", default="v1/sql/dq/dq_views_grants.sql")
    parser.add_argument("--views-schema", default="step1")
    parser.add_argument(
        "--allowed-admin-users",
        default=f"postgres,{client_db_service('admin')}",
    )
    parser.add_argument("--allow-nonlocal", action="store_true")
    parser.add_argument("--log-file", default="data/logs/admin_setup_views.log")
    args = parser.parse_args()

    log_file = Path(args.log_file)
    views_sql = Path(args.views_sql)
    grants_sql = Path(args.grants_sql)
    allowed_users = _parse_allowed_users(args.allowed_admin_users)

    try:
        if not views_sql.exists() or not grants_sql.exists():
            raise RuntimeError("SQL files not found")

        engine = create_engine(resolve_pg_url(role="admin", fallback_service=args.pgservice))
        preflight = _preflight(
            engine=engine,
            expected_db=args.expected_db,
            allowed_users=allowed_users,
            allow_nonlocal=args.allow_nonlocal,
        )
        print(
            "admin preflight ok: "
            f"db={preflight['db']} addr={preflight['addr']} port={preflight['port']} "
            f"session_user={preflight['session_user']} current_user={preflight['current_user']} current_role={preflight['current_role']}"
        )

        _run_psql(args.pgservice, args.expected_db, views_sql, grants_sql, log_file)
        _postcheck(engine, args.views_schema, allowed_users)
        print("admin setup completed: views/grants are installed")

    except PsqlRunError as exc:
        _write_log(log_file, f"ERROR: {exc}")
        print(f"admin setup failed (exit code {exc.returncode}). See {log_file}")
        raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as exc:
        _write_log(log_file, f"ERROR: {exc}")
        _write_log(log_file, traceback.format_exc())
        print("unexpected error; see log file")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
