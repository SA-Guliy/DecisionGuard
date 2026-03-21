#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.architecture_v3 import (
    CONTRACTS_DIR,
    load_json_optional_with_integrity,
    load_json_with_integrity,
    write_gate_result,
)
from src.client_db_config import client_db_service, resolve_pg_url
from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar


DEFAULT_APP_SERVICE = client_db_service("app")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_date(value: Any) -> date | None:
    if isinstance(value, date):
        return value
    if isinstance(value, datetime):
        return value.date()
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        if "T" in raw:
            return datetime.fromisoformat(raw).date()
        return date.fromisoformat(raw)
    except Exception:
        return None


def _span_days(start: date | None, end: date | None) -> int:
    if start is None or end is None:
        return 0
    if end < start:
        return 0
    return int((end - start).days) + 1


def _assert_local_dsn(pg_url: str) -> None:
    if "service=" in pg_url:
        return
    if "@localhost" in pg_url or "@127.0.0.1" in pg_url or "@::1" in pg_url:
        return
    if str(os.getenv("ALLOW_NONLOCALHOST", "0")) == "1":
        return
    raise RuntimeError("non_localhost_dsn_forbidden")


def _load_assignment_rows(path: Path) -> list[dict[str, Any]]:
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        raise RuntimeError(f"assignment_log_integrity_invalid:{reason}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        rows = payload.get("rows")
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
    return []


def _coverage_days_from_assignment_rows(rows: list[dict[str, Any]]) -> int:
    starts: list[date] = []
    ends: list[date] = []
    for row in rows:
        assigned = _parse_date(row.get("assigned_at"))
        start_d = _parse_date(row.get("start_date")) or assigned
        end_d = _parse_date(row.get("end_date")) or assigned
        if start_d is not None:
            starts.append(start_d)
        if end_d is not None:
            ends.append(end_d)
    if not starts or not ends:
        return 0
    return _span_days(min(starts), max(ends))


def _coverage_days_from_assignment_db(experiment_id: str, *, pgservice: str) -> int:
    dsn = resolve_pg_url(role="app", fallback_service=pgservice)
    _assert_local_dsn(dsn)
    engine = create_engine(dsn)
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL statement_timeout = '12s';"))
        conn.execute(text("SET TRANSACTION READ ONLY;"))
        row = conn.execute(
            text(
                """
                SELECT
                  MIN(COALESCE(start_date, assigned_at)) AS min_date,
                  MAX(COALESCE(end_date, assigned_at))   AS max_date,
                  COUNT(*)::int                          AS row_count
                FROM step1.step1_experiment_assignment_log
                WHERE experiment_id = :experiment_id
                """
            ),
            {"experiment_id": experiment_id},
        ).mappings().first()
    if not isinstance(row, dict):
        return 0
    min_date = _parse_date(row.get("min_date"))
    max_date = _parse_date(row.get("max_date"))
    return _span_days(min_date, max_date)


def _ab_timeline_candidates(experiment_id: str, explicit_path: str = "") -> list[Path]:
    out: list[Path] = []
    if explicit_path:
        p = Path(explicit_path)
        if p.exists() and p.is_file():
            out.append(p)
        return out
    for pattern in (f"data/ab_reports/*_{experiment_id}_ab.json", f"data/ab_reports/*_{experiment_id}_ab_v2.json"):
        out.extend([p for p in Path().glob(pattern) if p.is_file()])
    # Deterministic order + de-dup.
    unique: dict[str, Path] = {}
    for p in sorted(out):
        unique[str(p)] = p
    return list(unique.values())


def _coverage_days_from_ab_timeline(experiment_id: str, explicit_path: str = "") -> int:
    ts_values: list[date] = []
    for path in _ab_timeline_candidates(experiment_id, explicit_path):
        try:
            payload = load_json_optional_with_integrity(path, required=False)
        except Exception:
            payload = None
        if not isinstance(payload, dict):
            continue
        generated = _parse_date(payload.get("generated_at"))
        if generated is not None:
            ts_values.append(generated)
        summary = payload.get("summary")
        if isinstance(summary, dict):
            start_d = _parse_date(summary.get("start_date"))
            end_d = _parse_date(summary.get("end_date"))
            if start_d is not None:
                ts_values.append(start_d)
            if end_d is not None:
                ts_values.append(end_d)
    if not ts_values:
        return 0
    return _span_days(min(ts_values), max(ts_values))


def _write_payload(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed gate for minimum experiment duration.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--assignment-log-path", default="", help="Optional JSON rows source for deterministic tests")
    parser.add_argument("--ab-artifact-path", default="", help="Optional AB artifact path for timeline fallback")
    parser.add_argument("--pgservice", default=DEFAULT_APP_SERVICE)
    parser.add_argument("--out-json", default="")
    args = parser.parse_args()

    run_id = str(args.run_id).strip()
    experiment_id = str(args.experiment_id).strip()
    out_json = Path(args.out_json) if str(args.out_json).strip() else Path(
        f"data/agent_quality/{run_id}_experiment_duration_gate.json"
    )

    if not experiment_id:
        payload = {
            "version": "experiment_duration_gate_v1",
            "run_id": run_id,
            "experiment_id": "",
            "generated_at": _now_iso(),
            "status": "FAIL",
            "error_code": "EXPERIMENT_CONTEXT_REQUIRED",
            "days_covered": 0,
            "min_experiment_days": 14,
            "safe_decision_before_min_days": "HOLD_NEED_DATA",
            "blocked_by": ["missing_experiment_id"],
            "required_actions": ["Provide --experiment-id <id>; run is blocked by governance policy."],
            "data_sources_used": [],
        }
        _write_payload(out_json, payload)
        write_gate_result(
            run_id,
            gate_name="experiment_duration_gate",
            status="FAIL",
            error_code="EXPERIMENT_CONTEXT_REQUIRED",
            blocked_by=["missing_experiment_id"],
            required_actions=["Provide --experiment-id <id>; run is blocked by governance policy."],
            details={"days_covered": 0, "min_experiment_days": 14},
        )
        raise SystemExit(1)

    policy_path = CONTRACTS_DIR / "experiment_duration_policy_v1.json"
    policy = load_json_with_integrity(policy_path)
    min_days = int(policy.get("min_experiment_days", 14) or 14)
    safe_decision = str(policy.get("safe_decision_before_min_days", "HOLD_NEED_DATA") or "HOLD_NEED_DATA").strip().upper()

    sources_used: list[str] = []
    coverage_days = 0
    source_errors: list[str] = []

    assignment_path = str(args.assignment_log_path or "").strip()
    if assignment_path:
        try:
            rows = _load_assignment_rows(Path(assignment_path))
            coverage_days = _coverage_days_from_assignment_rows(rows)
            sources_used.append(f"assignment_log_file:{assignment_path}")
        except Exception as exc:
            source_errors.append(f"assignment_log_file_error:{exc}")
    else:
        try:
            coverage_days = _coverage_days_from_assignment_db(experiment_id, pgservice=str(args.pgservice or DEFAULT_APP_SERVICE))
            if coverage_days > 0:
                sources_used.append("assignment_log_db:step1.step1_experiment_assignment_log")
        except Exception as exc:
            source_errors.append(f"assignment_log_db_error:{exc}")

    if coverage_days <= 0:
        coverage_days = _coverage_days_from_ab_timeline(experiment_id, str(args.ab_artifact_path or "").strip())
        if coverage_days > 0:
            sources_used.append("ab_artifact_timeline")

    pass_gate = coverage_days >= min_days
    status = "PASS" if pass_gate else "FAIL"
    error_code = "NONE" if pass_gate else "EXPERIMENT_DURATION_INSUFFICIENT"
    blocked_by = [] if pass_gate else ["experiment_days_below_minimum"]
    required_actions = [] if pass_gate else [f"continue_experiment_until_min_days:{min_days}"]
    if source_errors and not pass_gate:
        blocked_by.extend(source_errors[:3])

    payload = {
        "version": "experiment_duration_gate_v1",
        "run_id": run_id,
        "experiment_id": experiment_id,
        "generated_at": _now_iso(),
        "status": status,
        "error_code": error_code,
        "days_covered": int(max(0, coverage_days)),
        "min_experiment_days": int(min_days),
        "safe_decision_before_min_days": safe_decision,
        "blocked_by": blocked_by,
        "required_actions": required_actions,
        "data_sources_used": sources_used,
    }
    _write_payload(out_json, payload)
    write_gate_result(
        run_id,
        gate_name="experiment_duration_gate",
        status=status,
        error_code=error_code,
        blocked_by=blocked_by,
        required_actions=required_actions,
        details={
            "experiment_id": experiment_id,
            "days_covered": int(max(0, coverage_days)),
            "min_experiment_days": int(min_days),
            "safe_decision_before_min_days": safe_decision,
            "data_sources_used": sources_used,
            "source_errors": source_errors[:5],
            "policy_ref": str(policy_path),
        },
    )

    if status != "PASS":
        raise SystemExit(1)
    print(
        f"ok: experiment_duration_gate PASS run_id={run_id} experiment_id={experiment_id} "
        f"days_covered={coverage_days} min_days={min_days}"
    )


if __name__ == "__main__":
    main()
