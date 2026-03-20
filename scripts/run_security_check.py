#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.client_db_config import client_db_service, expected_db, expected_user, resolve_pg_url
from src.security_utils import redact_text, write_sha256_sidecar


def _strict_mode(cli_strict: bool) -> bool:
    if cli_strict:
        return True
    return os.getenv("DS_STRICT_RUNTIME", "0") == "1"


def _assert_local_dsn(pg_url: str) -> None:
    if os.getenv("ALLOW_NONLOCALHOST", "0") == "1":
        return
    if "service=" in pg_url:
        return
    if "@localhost" in pg_url or "@127.0.0.1" in pg_url or "@::1" in pg_url:
        return
    raise SystemExit("Refusing non-localhost DSN. Set ALLOW_NONLOCALHOST=1 to override.")


def _write_log(log_file: Path, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    with log_file.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}] {redact_text(message)}\n")


def _default_out_json() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"data/security_reports/security_{ts}.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run policy-based runtime security checks (read-only)")
    parser.add_argument("--pgservice", default=client_db_service("app"))
    parser.add_argument("--expected-db", default=expected_db())
    parser.add_argument("--run-id", default="adhoc")
    parser.add_argument("--strict", action="store_true", help="Fail on any violations")
    parser.add_argument("--sql-file", default="v1/sql/security/security_check.sql")
    parser.add_argument("--out-json", default=None)
    parser.add_argument("--log-file", default=None)
    args = parser.parse_args()

    log_file = Path(args.log_file) if args.log_file else Path(f"data/logs/security_check_{args.run_id}.log")
    out_json = Path(args.out_json or _default_out_json())
    sql_file = Path(args.sql_file)
    if not sql_file.exists():
        raise SystemExit(f"SQL file not found: {sql_file}")

    pg_url = resolve_pg_url(role="app", fallback_service=args.pgservice)
    _assert_local_dsn(pg_url)
    strict = _strict_mode(args.strict)

    try:
        engine = create_engine(pg_url)
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT current_database() AS db, current_user AS usr")
            ).mappings().first()
            if row is None:
                raise SystemExit("security check failed: cannot verify database identity")
            if row["db"] != args.expected_db:
                raise SystemExit("security check failed: unexpected database")
            if str(row["usr"]) != expected_user("app"):
                raise SystemExit("security check failed: unexpected database role")
            db_name = str(row["db"])
            db_user = str(row["usr"])

            sql_text = sql_file.read_text(encoding="utf-8")
            results = conn.execute(text(sql_text)).mappings().all()

        violations: list[dict[str, Any]] = [
            {
                "code": str(r["code"]),
                "severity": str(r["severity"]),
                "role": str(r["role_name"]),
                "object": str(r["object_name"]),
                "detail": str(r["detail"]),
            }
            for r in results
        ]
        error_count = sum(1 for v in violations if v["severity"] == "ERROR")
        warn_count = sum(1 for v in violations if v["severity"] == "WARN")
        passed = error_count == 0 and (not strict or len(violations) == 0)

        report = {
            "passed": passed,
            "violations": violations,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "db": db_name,
            "user": db_user,
        }
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
        write_sha256_sidecar(out_json)

        print(
            f"security_check: violations={len(violations)} errors={error_count} warns={warn_count} "
            f"strict={int(strict)} passed={int(passed)}"
        )
        print(f"security_report: {out_json}")

        if strict and len(violations) > 0:
            raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as exc:
        _write_log(log_file, f"ERROR: {exc}")
        _write_log(log_file, redact_text(traceback.format_exc()))
        print(f"security_check failed (internal). see {log_file}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
