#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.client_db_config import client_db_service, resolve_pg_url
from src.security_utils import redact_text, write_sha256_sidecar

DEFAULT_SERVICE = client_db_service("app")
MIN_ORDERS_PER_ARM = 500
MIN_UNITS_PER_ARM = 200
Z95 = 1.96
DEFAULT_BOOTSTRAP_ITERS = 300
ALLOWED_PRIMARY_METRICS = {"aov", "writeoff_rate_adj", "writeoff_units", "writeoff_cogs", "buyers"}
_SQL_RELNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")
_ALLOWED_DYNAMIC_RELATIONS = {
    "step1.step1_orders",
    "step1.vw_valid_orders",
    "step1.step1_experiment_assignment_log",
    "step1.vw_valid_experiment_assignment",
}
_WRITEOFF_LOG_REL = "step1.step1_writeoff_log"


def _assert_safe_dynamic_relation_name(rel: str) -> str:
    name = str(rel or "").strip()
    if name not in _ALLOWED_DYNAMIC_RELATIONS or not _SQL_RELNAME_RE.fullmatch(name):
        raise ValueError(f"unsafe dynamic relation name: {name}")
    return name


def _assert_local_dsn(pg_url: str) -> None:
    if os.getenv("ALLOW_NONLOCALHOST", "0") == "1":
        return
    if "service=" in pg_url:
        return
    if "@localhost" in pg_url or "@127.0.0.1" in pg_url or "@::1" in pg_url:
        return
    raise SystemExit("Refusing non-localhost DSN. Set ALLOW_NONLOCALHOST=1 to override.")


def _resolve_dsn(service: str) -> str:
    return resolve_pg_url(role="app", fallback_service=service)


def _safe_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _safe_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_snapshot_context(snapshot_path: Path) -> tuple[str, dict[str, Any]]:
    data_source_type = "unknown"
    contract_completeness: dict[str, Any] = {}
    if not snapshot_path.exists():
        return data_source_type, contract_completeness
    try:
        payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except Exception:
        return data_source_type, contract_completeness
    if isinstance(payload, dict):
        ds = str(payload.get("data_source_type", "")).strip().lower()
        if ds in {"synthetic", "real", "mixed"}:
            data_source_type = ds
        cc = payload.get("contract_completeness")
        if isinstance(cc, dict):
            contract_completeness = cc
    return data_source_type, contract_completeness


def _assignment_hash_bucket(experiment_id: str, unit_id: str, salt: str) -> int:
    payload = f"{experiment_id}:{unit_id}:{salt}".encode("utf-8")
    digest = hashlib.sha1(payload).hexdigest()
    raw = int(digest[:8], 16)
    return raw - (2**32) if raw >= 2**31 else raw


def _assignment_arm(experiment_id: str, unit_id: str, treat_pct: int, salt: str) -> tuple[str, int]:
    h = _assignment_hash_bucket(experiment_id, unit_id, salt)
    arm = "treatment" if (h % 100) < int(treat_pct) else "control"
    return arm, h


def _to_float(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _var_samp(values: list[float]) -> float | None:
    if len(values) <= 1:
        return None
    mean = sum(values) / len(values)
    return sum((x - mean) ** 2 for x in values) / (len(values) - 1)


def _p_value_from_samples(values_t: list[float], values_c: list[float]) -> float | None:
    if len(values_t) <= 1 or len(values_c) <= 1:
        return None
    mean_t = sum(values_t) / len(values_t)
    mean_c = sum(values_c) / len(values_c)
    var_t = _var_samp(values_t)
    var_c = _var_samp(values_c)
    if var_t is None or var_c is None:
        return None
    return _p_value_from_diff(mean_t - mean_c, float(var_t), float(var_c), len(values_t), len(values_c))


def _pick_contract_field(run_cfg: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in run_cfg and run_cfg.get(key) not in {None, ""}:
            return run_cfg.get(key)
    return None


def _default_metric_semantics_id(primary_metric_id: str) -> str:
    mapping = {
        "aov": "sem.aov.order_value.v1",
        "buyers": "sem.buyers.binary.v1",
        "writeoff_rate_adj": "sem.writeoff.rate_adj.v1",
        "writeoff_units": "sem.writeoff.units.v1",
        "writeoff_cogs": "sem.writeoff.cogs.v1",
    }
    return mapping.get(primary_metric_id, f"sem.{primary_metric_id}.v1")


def _resolve_estimand_contract(
    run_cfg: dict[str, Any],
    *,
    cli_primary_metric: str,
    requested_unit: str,
) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    contract_primary_raw = _pick_contract_field(
        run_cfg,
        "primary_metric_id",
        "experiment_primary_metric",
        "primary_metric",
    )
    contract_primary = str(contract_primary_raw or "").strip().lower()
    cli_primary = str(cli_primary_metric or "").strip().lower()
    if contract_primary and contract_primary not in ALLOWED_PRIMARY_METRICS:
        issues.append(f"contract_primary_metric_unsupported:{contract_primary}")
    if cli_primary and cli_primary not in ALLOWED_PRIMARY_METRICS:
        issues.append(f"cli_primary_metric_unsupported:{cli_primary}")
    if contract_primary and cli_primary and contract_primary != cli_primary:
        issues.append(f"primary_metric_immutable_mismatch:{contract_primary}!={cli_primary}")
    primary_metric_id = contract_primary or cli_primary
    if not primary_metric_id:
        issues.append("primary_metric_missing")

    randomization_unit = str(
        _pick_contract_field(run_cfg, "randomization_unit", "experiment_unit") or requested_unit or ""
    ).strip().lower()
    analysis_unit = str(
        _pick_contract_field(run_cfg, "analysis_unit", "ab_analysis_unit") or randomization_unit or requested_unit or ""
    ).strip().lower()
    if randomization_unit not in {"customer", "store", "store_week"}:
        issues.append(f"randomization_unit_invalid:{randomization_unit or 'missing'}")
    if analysis_unit not in {"customer", "store", "store_week"}:
        issues.append(f"analysis_unit_invalid:{analysis_unit or 'missing'}")

    estimand_id = str(_pick_contract_field(run_cfg, "estimand_id", "experiment_estimand_id") or "").strip()
    if not estimand_id and primary_metric_id and analysis_unit:
        estimand_id = f"estimand.{primary_metric_id}.{analysis_unit}.v1"
    if not estimand_id:
        issues.append("estimand_id_missing")

    metric_semantics_id = str(_pick_contract_field(run_cfg, "metric_semantics_id") or "").strip()
    if not metric_semantics_id and primary_metric_id:
        metric_semantics_id = _default_metric_semantics_id(primary_metric_id)
    if not metric_semantics_id:
        issues.append("metric_semantics_id_missing")

    attribution_window_rule = str(
        _pick_contract_field(run_cfg, "attribution_window_rule", "ab_attribution_rule", "attribution_rule") or ""
    ).strip()
    if not attribution_window_rule:
        issues.append("attribution_window_rule_missing")

    return {
        "estimand_id": estimand_id,
        "primary_metric_id": primary_metric_id,
        "metric_semantics_id": metric_semantics_id,
        "randomization_unit": randomization_unit,
        "analysis_unit": analysis_unit,
        "attribution_window_rule": attribution_window_rule,
    }, issues


def _legacy_contract_remediation_hints(
    *,
    contract_issues: list[str],
    run_cfg: dict[str, Any],
    requested_unit: str,
    cli_primary_metric: str,
) -> list[str]:
    hints: list[str] = []
    issues_blob = "|".join(contract_issues).lower()
    if "primary_metric_missing" in issues_blob:
        hints.append(
            "set run_config.primary_metric_id to one of: aov, writeoff_rate_adj, writeoff_units, writeoff_cogs, buyers"
        )
    if "randomization_unit_invalid" in issues_blob:
        hints.append("set run_config.randomization_unit to one of: customer, store, store_week")
    if "analysis_unit_invalid" in issues_blob:
        hints.append("set run_config.analysis_unit to one of: customer, store, store_week")
    if "metric_semantics_id_missing" in issues_blob:
        hints.append("set run_config.metric_semantics_id to a stable semantic ID (for example sem.writeoff.rate_adj.v1)")
    if "estimand_id_missing" in issues_blob:
        hints.append("set run_config.estimand_id to a stable estimand ID (for example estimand.writeoff_rate_adj.customer.v1)")
    if "attribution_window_rule_missing" in issues_blob:
        hints.append("set run_config.attribution_window_rule (example: order_created_at_within_experiment_window)")
    if "primary_metric_immutable_mismatch" in issues_blob:
        hints.append("remove --primary-metric override or align it with run_config.primary_metric_id")
    if not hints:
        hints.append("update run_config estimand contract fields and rerun AB preflight")
    cfg_unit = str(run_cfg.get("experiment_unit") or requested_unit or "customer")
    metric_hint = str(cli_primary_metric or run_cfg.get("primary_metric_id") or "writeoff_rate_adj")
    hints.append(
        f"expected_minimum_contract=randomization_unit:{cfg_unit}, analysis_unit:{cfg_unit}, primary_metric_id:{metric_hint}"
    )
    return hints[:8]


def _ci_diff(mean_t: float, mean_c: float, var_t: float, var_c: float, n_t: int, n_c: int) -> tuple[float | None, float | None, float | None]:
    if n_t <= 1 or n_c <= 1:
        return None, None, None
    se = math.sqrt(max(0.0, (var_t / n_t) + (var_c / n_c)))
    diff = mean_t - mean_c
    return diff, diff - (Z95 * se), diff + (Z95 * se)


def _pct_uplift_ci(diff: float | None, lo: float | None, hi: float | None, base: float) -> tuple[float | None, float | None, float | None]:
    if diff is None or lo is None or hi is None or base == 0:
        return None, None, None
    return diff / base, lo / base, hi / base


def _detect_order_source(conn) -> str:
    # Prefer base table first: it carries run-scoped customer_id and avoids view-level permission drift.
    candidates = ["step1.step1_orders", "step1.vw_valid_orders"]
    for rel in candidates:
        try:
            rel = _assert_safe_dynamic_relation_name(rel)
            exists = conn.execute(text("SELECT to_regclass(:rel)"), {"rel": rel}).scalar() is not None
            if not exists:
                continue
            with conn.begin_nested():
                conn.execute(text(f"SELECT 1 FROM {rel} LIMIT 1"))
            return rel
        except Exception:
            continue
    return "step1.step1_orders"


def _detect_assignment_source(conn) -> str:
    if conn.execute(text("SELECT to_regclass('step1.vw_valid_experiment_assignment')")).scalar() is not None:
        return _assert_safe_dynamic_relation_name("step1.vw_valid_experiment_assignment")
    return _assert_safe_dynamic_relation_name("step1.step1_experiment_assignment_log")


def _read_experiment_from_registry(conn, run_id: str) -> tuple[str | None, str | None]:
    # Use a savepoint so permission errors do not abort outer transaction.
    try:
        with conn.begin_nested():
            row = conn.execute(
                text(
                    """
                    SELECT
                      COALESCE(config_json->>'experiment_id','') AS experiment_id,
                      COALESCE(config_json->>'experiment_unit','') AS experiment_unit
                    FROM step1.step1_run_registry
                    WHERE run_id = :run_id
                    """
                ),
                {"run_id": run_id},
            ).mappings().first()
    except Exception:
        # Agent RO role can be intentionally blocked from run_registry.
        return None, None
    if not row:
        return None, None
    exp = str(row["experiment_id"]).strip() or None
    unit = str(row["experiment_unit"]).strip() or None
    return exp, unit


def _read_run_config(conn, run_id: str) -> dict[str, Any]:
    try:
        with conn.begin_nested():
            row = conn.execute(
                text(
                    """
                    SELECT config_json
                    FROM step1.step1_run_registry
                    WHERE run_id = :run_id
                    """
                ),
                {"run_id": run_id},
            ).mappings().first()
    except Exception:
        return {}
    cfg = row.get("config_json") if row else {}
    return cfg if isinstance(cfg, dict) else {}


def _table_has_column(conn, relation: str, column: str) -> bool:
    try:
        with conn.begin_nested():
            exists = conn.execute(
                text(
                    """
                    SELECT 1
                    FROM pg_attribute
                    WHERE attrelid = CAST(:rel AS regclass)
                      AND attname = :col
                      AND NOT attisdropped
                      AND attnum > 0
                    LIMIT 1
                    """
                ),
                {"rel": relation, "col": column},
            ).scalar()
        return bool(exists)
    except Exception:
        return False


def _first_existing_column(conn, relation: str, candidates: list[str]) -> str | None:
    for c in candidates:
        if _table_has_column(conn, relation, c):
            return c
    return None


def _writeoff_qty_column(conn) -> str | None:
    # Current schema uses qty_writeoff, but keep compatibility with legacy name if present.
    return _first_existing_column(conn, _WRITEOFF_LOG_REL, ["qty_writeoff", "writeoff_qty"])


def _writeoff_design_metadata(run_cfg: dict[str, Any], requested_unit: str, realized_unit: str, primary_metric: str) -> dict[str, Any]:
    def _pick(*keys: str) -> Any:
        for k in keys:
            if k in run_cfg and run_cfg.get(k) not in {None, ""}:
                return run_cfg.get(k)
        return None

    writeoff_metric = primary_metric in {"writeoff_rate_adj", "writeoff_units", "writeoff_cogs"}
    design = {
        "randomization_unit_cfg": str(run_cfg.get("experiment_unit") or requested_unit or "").strip().lower() or None,
        "analysis_unit_realized": str(realized_unit or "").strip().lower() or None,
        "pre_period_weeks": _pick("ab_pre_period_weeks", "pre_period_weeks"),
        "test_period_weeks": _pick("ab_test_period_weeks", "test_period_weeks"),
        "wash_in_days": _pick("ab_wash_in_days", "wash_in_days"),
        "attribution_window_rule": _pick("ab_attribution_rule", "attribution_rule"),
        "test_side": _pick("ab_test_side", "test_side"),
        "alpha": _pick("ab_alpha", "alpha"),
        "power_target": _pick("ab_power_target", "power_target"),
        "mde_target": _pick("ab_mde_target", "mde_target"),
        "metric_semantics": (
            "proxy_writeoff_units_over_requested_units"
            if primary_metric == "writeoff_rate_adj"
            else ("canonical_writeoff" if primary_metric in {"writeoff_units", "writeoff_cogs"} else "standard")
        ),
        "surrogate_batch_id_strategy": (
            "store_id|product_id|lot_received_date|lot_expiry_date"
            if writeoff_metric
            else None
        ),
    }
    design_gaps: list[str] = []
    if writeoff_metric:
        if design["pre_period_weeks"] in {None, ""}:
            design_gaps.append("pre_period_weeks_missing")
        if design["wash_in_days"] in {None, ""}:
            design_gaps.append("wash_in_days_missing")
        if not str(design.get("attribution_window_rule") or "").strip():
            design_gaps.append("attribution_window_rule_missing")
    design["design_gaps"] = design_gaps
    return design


def _assignment_counts(conn, run_id: str, experiment_id: str, assignment_source: str) -> dict[str, Any]:
    assignment_source = _assert_safe_dynamic_relation_name(assignment_source)
    rows = conn.execute(
        text(
            f"""
            SELECT unit_type, arm, COUNT(*)::bigint AS n
            FROM {assignment_source}
            WHERE run_id = :run_id AND experiment_id = :experiment_id
            GROUP BY unit_type, arm
            """
        ),
        {"run_id": run_id, "experiment_id": experiment_id},
    ).mappings().all()
    out: dict[str, Any] = {"customer": {"control": 0, "treatment": 0}, "store": {"control": 0, "treatment": 0}}
    for r in rows:
        out[str(r["unit_type"])][str(r["arm"])] = int(r["n"])
    return out


def _orders_with_experiment_rows(conn, run_id: str, experiment_id: str, orders_table: str) -> int | None:
    orders_table = _assert_safe_dynamic_relation_name(orders_table)
    # Smoke check is best-effort under agent_ro privileges.
    try:
        with conn.begin_nested():
            return int(
                conn.execute(
                    text(
                        f"""
                        SELECT COUNT(*)
                        FROM {orders_table}
                        WHERE run_id = :run_id AND experiment_id = :experiment_id
                        """
                    ),
                    {"run_id": run_id, "experiment_id": experiment_id},
                ).scalar()
                or 0
            )
    except Exception:
        try:
            with conn.begin_nested():
                return int(
                    conn.execute(
                        text(
                            """
                            SELECT COUNT(*)
                            FROM step1.vw_valid_order_items
                            WHERE run_id = :run_id AND experiment_id = :experiment_id
                            """
                        ),
                        {"run_id": run_id, "experiment_id": experiment_id},
                    ).scalar()
                    or 0
                )
        except Exception:
            return None


def _preflight_error_payload(
    run_id: str,
    experiment_id: str,
    requested_unit: str,
    orders_table: str,
    assignment_source: str,
    assignment_counts: dict[str, Any],
    checks: list[dict[str, Any]],
    error_family: str,
    error_code: str,
    error_detail: str,
    primary_metric: str | None = None,
    contract_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "experiment_id": experiment_id,
        "primary_metric": (str(primary_metric).strip() if primary_metric else None),
        "contract_context": (contract_context if isinstance(contract_context, dict) else {}),
        "requested_unit": requested_unit,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "FAIL",
        "pipeline_status": "FAIL",
        "measurement_state": "UNOBSERVABLE",
        "error_family": error_family,
        "error_code": error_code,
        "error_detail": error_detail,
        "orders_table": orders_table,
        "assignment_source": assignment_source,
        "assignment_counts": assignment_counts,
        "checks": checks,
        "version": "ab_preflight.v1",
    }


def _render_preflight_md(payload: dict[str, Any]) -> str:
    checks = payload.get("checks", []) if isinstance(payload.get("checks"), list) else []
    contract_ctx = payload.get("contract_context", {}) if isinstance(payload.get("contract_context"), dict) else {}
    lines = [
        f"# AB Preflight: {payload.get('run_id')} / {payload.get('experiment_id')}",
        "",
        f"- status: `{payload.get('status')}`",
        f"- pipeline_status: `{payload.get('pipeline_status')}`",
        f"- measurement_state: `{payload.get('measurement_state')}`",
        f"- requested_unit: `{payload.get('requested_unit')}`",
        f"- primary_metric: `{payload.get('primary_metric')}`",
        f"- estimand_id: `{contract_ctx.get('estimand_id')}`",
        f"- primary_metric_id: `{contract_ctx.get('primary_metric_id')}`",
        f"- metric_semantics_id: `{contract_ctx.get('metric_semantics_id')}`",
        f"- randomization_unit: `{contract_ctx.get('randomization_unit')}`",
        f"- analysis_unit: `{contract_ctx.get('analysis_unit')}`",
        f"- orders_table: `{payload.get('orders_table')}`",
        f"- assignment_source: `{payload.get('assignment_source')}`",
        f"- error_family: `{payload.get('error_family')}`",
        f"- error_code: `{payload.get('error_code')}`",
        f"- error_detail: {payload.get('error_detail')}",
        "",
        "## Assignment Counts",
        f"- customer.control: `{(((payload.get('assignment_counts') or {}).get('customer') or {}).get('control'))}`",
        f"- customer.treatment: `{(((payload.get('assignment_counts') or {}).get('customer') or {}).get('treatment'))}`",
        f"- store.control: `{(((payload.get('assignment_counts') or {}).get('store') or {}).get('control'))}`",
        f"- store.treatment: `{(((payload.get('assignment_counts') or {}).get('store') or {}).get('treatment'))}`",
        "",
        "## Checks",
        "| Check | Layer | Status | Code | Detail |",
        "|---|---|---|---|---|",
    ]
    if not checks:
        lines.append("| none | — | — | — | — |")
    for c in checks:
        lines.append(
            "| {name} | {layer} | {status} | {code} | {detail} |".format(
                name=str(c.get("name", "unknown")),
                layer=str(c.get("layer", "unknown")),
                status=str(c.get("status", "unknown")),
                code=str(c.get("error_code", "")),
                detail=str(c.get("detail", "")),
            )
        )
    lines.append("")
    return "\n".join(lines)


def _write_preflight_artifacts(payload: dict[str, Any]) -> tuple[Path, Path]:
    run_id = str(payload.get("run_id", "unknown"))
    exp_id = str(payload.get("experiment_id", "unknown"))
    json_path = Path(f"data/ab_preflight/{run_id}_{exp_id}_preflight.json")
    md_path = Path(f"reports/L1_ops/{run_id}/AB_PREFLIGHT_{exp_id}.md")
    _safe_write_json(json_path, payload)
    _safe_write(md_path, _render_preflight_md(payload))
    return json_path, md_path


def _probe_unit_join_rows(conn, run_id: str, experiment_id: str, requested_unit: str, orders_table: str, assignment_source: str) -> tuple[list[dict[str, Any]], str | None]:
    try:
        if requested_unit == "customer":
            return _order_metrics_customer(conn, run_id, experiment_id, orders_table, assignment_source), None
        return _order_metrics_store(conn, run_id, experiment_id, orders_table, assignment_source), None
    except Exception as exc:
        return [], str(exc).splitlines()[0][:240]


def _run_ab_preflight(
    conn,
    *,
    run_id: str,
    experiment_id: str,
    requested_unit: str,
    primary_metric: str,
    orders_table: str,
    assignment_source: str,
    assignment_counts: dict[str, Any],
    smoke_orders_experiment: int | None,
    contract_context: dict[str, Any] | None = None,
    data_source_type: str = "unknown",
    contract_completeness: dict[str, Any] | None = None,
) -> dict[str, Any]:
    orders_table = _assert_safe_dynamic_relation_name(orders_table)
    assignment_source = _assert_safe_dynamic_relation_name(assignment_source)
    checks: list[dict[str, Any]] = []
    requested_unit = str(requested_unit or "customer").strip().lower()
    primary_metric = str(primary_metric or "").strip().lower()
    contract_context = contract_context if isinstance(contract_context, dict) else {}
    contract_completeness = contract_completeness if isinstance(contract_completeness, dict) else {}
    contract_issues = contract_context.get("_issues", [])
    if not isinstance(contract_issues, list):
        contract_issues = []

    def _add_check(name: str, layer: str, ok: bool, code: str, detail: str) -> None:
        checks.append(
            {
                "name": name,
                "layer": layer,
                "status": "PASS" if ok else "FAIL",
                "error_code": code if not ok else "",
                "detail": detail,
            }
        )

    if not experiment_id.strip():
        _add_check("experiment_id_present", "Contract", False, "CONTRACT_EXPERIMENT_ID_MISSING", "experiment_id is empty")
        return _preflight_error_payload(
            run_id,
            "missing",
            requested_unit,
            orders_table,
            assignment_source,
            assignment_counts,
            checks,
            "CONTRACT",
            "CONTRACT_EXPERIMENT_ID_MISSING",
            "AB preflight requires experiment_id.",
            primary_metric,
            contract_context,
        )
    _add_check("experiment_id_present", "Contract", True, "", "experiment_id is present")
    _add_check(
        "primary_metric_present",
        "Contract",
        bool(primary_metric),
        "CONTRACT_PRIMARY_METRIC_MISSING",
        f"primary_metric={primary_metric or 'missing'}",
    )
    _add_check(
        "primary_metric_supported",
        "Contract",
        primary_metric in ALLOWED_PRIMARY_METRICS,
        "CONTRACT_PRIMARY_METRIC_UNSUPPORTED",
        f"primary_metric={primary_metric or 'missing'}, allowed={sorted(ALLOWED_PRIMARY_METRICS)}",
    )
    _add_check(
        "estimand_contract_resolution",
        "Contract",
        len(contract_issues) == 0,
        "CONTRACT_ESTIMAND_RESOLUTION_FAIL",
        f"issues={contract_issues}",
    )
    normalized_data_source = str(data_source_type or "").strip().lower()
    _add_check(
        "data_source_type_supported",
        "Data Contract",
        normalized_data_source in {"synthetic", "real", "mixed"},
        "DATA_SOURCE_TYPE_UNKNOWN",
        f"data_source_type={normalized_data_source or 'missing'}",
    )
    if contract_context:
        contract_required = [
            "estimand_id",
            "primary_metric_id",
            "metric_semantics_id",
            "randomization_unit",
            "analysis_unit",
            "attribution_window_rule",
        ]
        missing_contract = [k for k in contract_required if not str(contract_context.get(k, "")).strip()]
        _add_check(
            "estimand_contract_complete",
            "Contract",
            len(missing_contract) == 0,
            "CONTRACT_ESTIMAND_FIELDS_MISSING",
            f"missing={missing_contract}",
        )
        contract_primary_metric = str(contract_context.get("primary_metric_id", "")).strip().lower()
        _add_check(
            "primary_metric_immutable",
            "Contract",
            bool(contract_primary_metric) and contract_primary_metric == primary_metric,
            "CONTRACT_PRIMARY_METRIC_IMMUTABLE",
            f"contract_primary_metric={contract_primary_metric or 'missing'}, runtime_primary_metric={primary_metric or 'missing'}",
        )
        contract_analysis = str(contract_context.get("analysis_unit", "")).strip().lower()
        _add_check(
            "analysis_unit_alignment",
            "Method",
            bool(contract_analysis) and contract_analysis == requested_unit,
            "METHOD_ANALYSIS_UNIT_MISMATCH",
            f"analysis_unit={contract_analysis or 'missing'}, requested_unit={requested_unit}",
        )

    has_customer_col = _table_has_column(conn, orders_table, "customer_id")
    if requested_unit == "customer":
        _add_check(
            "orders_customer_id_column",
            "Data Schema",
            has_customer_col,
            "DATA_COLUMN_MISSING_CUSTOMER_ID",
            f"{orders_table}.customer_id {'present' if has_customer_col else 'missing'}",
        )
    else:
        _add_check("orders_store_id_available", "Data Schema", True, "", f"{orders_table}.store_id used for store assignment joins")

    writeoff_metric = primary_metric in {"writeoff_rate_adj", "writeoff_units", "writeoff_cogs"}
    _add_check(
        "writeoff_metric_store_unit_required",
        "Method",
        (not writeoff_metric) or requested_unit == "store",
        "METHOD_PRIMARY_METRIC_UNIT_MISMATCH",
        f"primary_metric={primary_metric}, requested_unit={requested_unit}",
    )
    if writeoff_metric:
        writeoff_exists = conn.execute(text("SELECT to_regclass(:rel)"), {"rel": _WRITEOFF_LOG_REL}).scalar() is not None
        _add_check(
            "writeoff_log_present",
            "Data Schema",
            bool(writeoff_exists),
            "DATA_WRITEOFF_LOG_MISSING",
            f"{_WRITEOFF_LOG_REL} {'present' if writeoff_exists else 'missing'}",
        )
        qty_col = _writeoff_qty_column(conn) if writeoff_exists else None
        _add_check(
            "writeoff_qty_column",
            "Data Schema",
            bool(qty_col),
            "DATA_COLUMN_MISSING_WRITEOFF_QTY",
            f"{_WRITEOFF_LOG_REL}.qty_writeoff/writeoff_qty {'found: ' + str(qty_col) if qty_col else 'missing'}",
        )
        if primary_metric == "writeoff_cogs":
            has_writeoff_cogs = _table_has_column(conn, _WRITEOFF_LOG_REL, "writeoff_cogs") if writeoff_exists else False
            _add_check(
                "writeoff_cogs_column",
                "Data Schema",
                bool(has_writeoff_cogs),
                "DATA_COLUMN_MISSING_WRITEOFF_COGS",
                f"{_WRITEOFF_LOG_REL}.writeoff_cogs {'present' if has_writeoff_cogs else 'missing'}",
            )
        # Needed for surrogate batch_id / attribution window rules in current dataset.
        has_lot_received = _table_has_column(conn, _WRITEOFF_LOG_REL, "lot_received_date") if writeoff_exists else False
        has_lot_expiry = _table_has_column(conn, _WRITEOFF_LOG_REL, "lot_expiry_date") if writeoff_exists else False
        has_batch_id = _table_has_column(conn, _WRITEOFF_LOG_REL, "batch_id") if writeoff_exists else False
        has_reason_norm = _table_has_column(conn, _WRITEOFF_LOG_REL, "writeoff_reason_norm") if writeoff_exists else False
        has_reason_raw = _table_has_column(conn, _WRITEOFF_LOG_REL, "reason") if writeoff_exists else False
        _add_check(
            "writeoff_lot_dates_for_surrogate_batch_id",
            "Data Schema",
            bool(has_lot_received and has_lot_expiry),
            "DATA_LOT_DATES_MISSING_FOR_BATCH_SURROGATE",
            f"lot_received_date={has_lot_received}, lot_expiry_date={has_lot_expiry}",
        )
        _add_check(
            "writeoff_batch_id_column",
            "Data Schema",
            bool(has_batch_id),
            "DATA_COLUMN_MISSING_BATCH_ID",
            f"{_WRITEOFF_LOG_REL}.batch_id {'present' if has_batch_id else 'missing'}",
        )
        _add_check(
            "writeoff_reason_column",
            "Data Schema",
            bool(has_reason_norm or has_reason_raw),
            "DATA_COLUMN_MISSING_WRITEOFF_REASON",
            f"reason_norm={has_reason_norm}, reason={has_reason_raw}",
        )
        cc_checks = contract_completeness.get("checks", {}) if isinstance(contract_completeness.get("checks"), dict) else {}

        def _coverage_value(name: str) -> float | None:
            row = cc_checks.get(name, {}) if isinstance(cc_checks, dict) else {}
            if not isinstance(row, dict):
                return None
            try:
                return float(row.get("value"))
            except Exception:
                return None

        reason_cov = _coverage_value("writeoff_reason_coverage")
        expiry_cov = _coverage_value("expiry_date_coverage")
        batch_cov = _coverage_value("batch_join_coverage")
        _add_check(
            "goal1_reason_coverage_threshold",
            "Data Contract",
            reason_cov is not None and reason_cov >= 0.99,
            "DATA_CONTRACT_GOAL1_REASON_COVERAGE",
            f"writeoff_reason_coverage={reason_cov}, required>=0.99",
        )
        _add_check(
            "goal1_expiry_coverage_threshold",
            "Data Contract",
            expiry_cov is not None and expiry_cov >= 0.99,
            "DATA_CONTRACT_GOAL1_EXPIRY_COVERAGE",
            f"expiry_date_coverage={expiry_cov}, required>=0.99",
        )
        _add_check(
            "goal1_batch_coverage_threshold",
            "Data Contract",
            batch_cov is not None and batch_cov >= 0.95,
            "DATA_CONTRACT_GOAL1_BATCH_COVERAGE",
            f"batch_join_coverage={batch_cov}, required>=0.95",
        )

    requested_assign_counts = assignment_counts.get(requested_unit, {}) if isinstance(assignment_counts, dict) else {}
    n_req_assign = int(requested_assign_counts.get("control", 0) or 0) + int(requested_assign_counts.get("treatment", 0) or 0)
    _add_check(
        "assignment_rows_for_requested_unit",
        "Data Assignment",
        n_req_assign > 0,
        "DATA_ASSIGNMENT_MISSING_FOR_REQUESTED_UNIT",
        f"assignment rows for unit={requested_unit}: {n_req_assign}",
    )

    if smoke_orders_experiment is None:
        _add_check(
            "orders_experiment_smoke",
            "Data Access",
            False,
            "DATA_ACCESS_SMOKE_CHECK_UNAVAILABLE",
            "Unable to verify experiment rows in orders table due to access/visibility limits.",
        )
    else:
        _add_check(
            "orders_experiment_smoke",
            "Data Join",
            smoke_orders_experiment > 0,
            "DATA_NO_ORDERS_FOR_EXPERIMENT",
            f"orders with experiment_id={experiment_id}: {smoke_orders_experiment}",
        )

    probe_rows, probe_err = _probe_unit_join_rows(conn, run_id, experiment_id, requested_unit, orders_table, assignment_source)
    if probe_err:
        if requested_unit == "customer":
            _add_check(
                "requested_unit_join_probe",
                "Data Join",
                False,
                "DATA_JOIN_CUSTOMER_GRAIN_UNAVAILABLE",
                probe_err,
            )
        else:
            _add_check("requested_unit_join_probe", "Data Join", False, "DATA_JOIN_STORE_GRAIN_FAILED", probe_err)
    else:
        _add_check(
            "requested_unit_join_probe",
            "Data Join",
            bool(probe_rows),
            "DATA_JOIN_PROBE_EMPTY_FOR_REQUESTED_UNIT",
            f"aggregated arm rows returned: {len(probe_rows)}",
        )

    fail_rows = [c for c in checks if str(c.get("status")) == "FAIL"]
    if fail_rows:
        top = fail_rows[0]
        family_map = {
            "Contract": "CONTRACT",
            "Data Schema": "DATA_SCHEMA",
            "Data Assignment": "DATA_ASSIGNMENT",
            "Data Join": "DATA_JOIN",
            "Data Access": "DATA_ACCESS",
            "Data Contract": "DATA_CONTRACT",
            "Method": "METHOD",
        }
        return _preflight_error_payload(
            run_id,
            experiment_id,
            requested_unit,
            orders_table,
            assignment_source,
            assignment_counts,
            checks,
            family_map.get(str(top.get("layer")), "DATA_CONTRACT"),
            str(top.get("error_code") or "AB_PREFLIGHT_FAIL"),
            str(top.get("detail") or "AB preflight failed"),
            primary_metric,
            contract_context,
        )

    return {
        "run_id": run_id,
        "experiment_id": experiment_id,
        "primary_metric": primary_metric or None,
        "contract_context": contract_context,
        "requested_unit": requested_unit,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "PASS",
        "pipeline_status": "PASS",
        "measurement_state": "OBSERVABLE_READY",
        "error_family": "NONE",
        "error_code": "NONE",
        "error_detail": "",
        "orders_table": orders_table,
        "assignment_source": assignment_source,
        "assignment_counts": assignment_counts,
        "checks": checks,
        "version": "ab_preflight.v1",
    }


def _order_metrics_store(conn, run_id: str, experiment_id: str, orders_table: str, assignment_source: str) -> list[dict[str, Any]]:
    orders_table = _assert_safe_dynamic_relation_name(orders_table)
    assignment_source = _assert_safe_dynamic_relation_name(assignment_source)
    return [
        dict(r)
        for r in conn.execute(
            text(
                f"""
                SELECT
                  a.arm,
                  COUNT(*)::bigint AS n_orders,
                  COUNT(DISTINCT o.store_id)::bigint AS n_units,
                  AVG(o.order_gmv)::double precision AS mean_aov,
                  VAR_SAMP(o.order_gmv)::double precision AS var_aov,
                  AVG(o.order_gp)::double precision AS mean_gp_order,
                  VAR_SAMP(o.order_gp)::double precision AS var_gp_order,
                  SUM(o.order_gmv)::double precision AS gmv,
                  SUM(o.order_gp)::double precision AS gp,
                  SUM(o.requested_units)::double precision AS requested_units,
                  SUM(o.fulfilled_units)::double precision AS fulfilled_units
                FROM {orders_table} o
                JOIN {assignment_source} a
                  ON a.run_id = o.run_id
                 AND a.experiment_id = :experiment_id
                 AND a.unit_type = 'store'
                 AND a.unit_id = o.store_id
                WHERE o.run_id = :run_id
                GROUP BY a.arm
                ORDER BY a.arm
                """
            ),
            {"run_id": run_id, "experiment_id": experiment_id},
        ).mappings().all()
    ]


def _order_metrics_customer(conn, run_id: str, experiment_id: str, orders_table: str, assignment_source: str) -> list[dict[str, Any]]:
    orders_table = _assert_safe_dynamic_relation_name(orders_table)
    assignment_source = _assert_safe_dynamic_relation_name(assignment_source)
    def _fetch(use_orders_customer_col: bool) -> list[dict[str, Any]]:
        if use_orders_customer_col:
            customer_join = "o.customer_id"
            join_raw = ""
            n_units_expr = "COUNT(DISTINCT o.customer_id)::bigint"
        else:
            customer_join = "os.customer_id"
            join_raw = (
                "JOIN raw.raw_orders_stream os "
                "ON os.order_id = o.order_id AND os.store_id = o.store_id AND os.date = o.date"
            )
            n_units_expr = "COUNT(DISTINCT os.customer_id)::bigint"
        return [
            dict(r)
            for r in conn.execute(
                text(
                    f"""
                    SELECT
                      a.arm,
                      COUNT(*)::bigint AS n_orders,
                      {n_units_expr} AS n_units,
                      AVG(o.order_gmv)::double precision AS mean_aov,
                      VAR_SAMP(o.order_gmv)::double precision AS var_aov,
                      AVG(o.order_gp)::double precision AS mean_gp_order,
                      VAR_SAMP(o.order_gp)::double precision AS var_gp_order,
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
                     AND a.unit_id = {customer_join}
                    WHERE o.run_id = :run_id
                    GROUP BY a.arm
                    ORDER BY a.arm
                    """
                ),
                {"run_id": run_id, "experiment_id": experiment_id},
            ).mappings().all()
        ]

    has_customer_col = _table_has_column(conn, orders_table, "customer_id")
    rows = _fetch(use_orders_customer_col=has_customer_col)
    # If derived step1 customer_id exists but has poor/null coverage, retry via raw stream join.
    if not rows and has_customer_col:
        try:
            rows = _fetch(use_orders_customer_col=False)
        except Exception:
            pass
    return rows


def _arm_map(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        out[str(r.get("arm", ""))] = r
    return out


def _recover_assignment_from_orders(
    conn,
    run_id: str,
    experiment_id: str,
    requested_unit: str,
    orders_table: str,
    treat_pct: int,
    salt: str,
) -> tuple[str, dict[str, dict[str, int]], list[dict[str, Any]], list[str]]:
    orders_table = _assert_safe_dynamic_relation_name(orders_table)
    notes: list[str] = []
    unit_type = requested_unit
    rows_out: list[dict[str, Any]] = []
    counts = {"customer": {"control": 0, "treatment": 0}, "store": {"control": 0, "treatment": 0}}

    if requested_unit == "customer":
        if _table_has_column(conn, orders_table, "customer_id"):
            unit_expr = "o.customer_id"
            joins = ""
            where_customer = "AND o.customer_id IS NOT NULL"
        else:
            unit_expr = "os.customer_id"
            joins = (
                "JOIN raw.raw_orders_stream os "
                "ON os.order_id = o.order_id AND os.store_id = o.store_id AND os.date = o.date"
            )
            where_customer = "AND os.customer_id IS NOT NULL"
        try:
            q = text(
                f"""
                SELECT
                  {unit_expr}::text AS unit_id,
                  o.order_gmv::double precision AS order_gmv,
                  o.order_gp::double precision AS order_gp,
                  o.requested_units::double precision AS requested_units,
                  o.fulfilled_units::double precision AS fulfilled_units
                FROM {orders_table} o
                {joins}
                WHERE o.run_id = :run_id
                {where_customer}
                """
            )
            rows = conn.execute(q, {"run_id": run_id}).mappings().all()
        except Exception:
            rows = []
        if not rows:
            unit_type = "store"
            notes.append("assignment_recovery_fallback_store")
        else:
            for r in rows:
                uid = str(r.get("unit_id", "")).strip()
                if not uid:
                    continue
                arm, _ = _assignment_arm(experiment_id, uid, treat_pct, salt)
                counts["customer"][arm] += 1
                rows_out.append(
                    {
                        "arm": arm,
                        "unit_id": uid,
                        "order_gmv": _to_float(r.get("order_gmv")),
                        "order_gp": _to_float(r.get("order_gp")),
                        "requested_units": _to_float(r.get("requested_units")),
                        "fulfilled_units": _to_float(r.get("fulfilled_units")),
                    }
                )
            return unit_type, counts, rows_out, notes

    q = text(
        f"""
        SELECT
          o.store_id::text AS unit_id,
          o.order_gmv::double precision AS order_gmv,
          o.order_gp::double precision AS order_gp,
          o.requested_units::double precision AS requested_units,
          o.fulfilled_units::double precision AS fulfilled_units
        FROM {orders_table} o
        WHERE o.run_id = :run_id
          AND o.store_id IS NOT NULL
        """
    )
    rows = conn.execute(q, {"run_id": run_id}).mappings().all()
    for r in rows:
        uid = str(r.get("unit_id", "")).strip()
        if not uid:
            continue
        arm, _ = _assignment_arm(experiment_id, uid, treat_pct, salt)
        counts["store"][arm] += 1
        rows_out.append(
            {
                "arm": arm,
                "unit_id": uid,
                "order_gmv": _to_float(r.get("order_gmv")),
                "order_gp": _to_float(r.get("order_gp")),
                "requested_units": _to_float(r.get("requested_units")),
                "fulfilled_units": _to_float(r.get("fulfilled_units")),
            }
        )
    return "store", counts, rows_out, notes


def _p_value_from_diff(diff: float | None, var_t: float, var_c: float, n_t: int, n_c: int) -> float | None:
    if diff is None or n_t <= 1 or n_c <= 1:
        return None
    se = math.sqrt(max(0.0, (var_t / n_t) + (var_c / n_c)))
    if se <= 0:
        return None
    z = abs(diff / se)
    return float(math.erfc(z / math.sqrt(2.0)))


def _formal_srm_check(
    *,
    run_id: str,
    experiment_id: str,
    n_control: int,
    n_treatment: int,
    expected_treatment_share: float,
) -> dict[str, Any]:
    total = max(0, int(n_control)) + max(0, int(n_treatment))
    exp_t_share = max(0.0, min(1.0, float(expected_treatment_share)))
    exp_c_share = 1.0 - exp_t_share
    obs_t_share = (n_treatment / total) if total > 0 else 0.0
    imbalance_pp = abs(obs_t_share - exp_t_share) * 100.0

    if total <= 0:
        p_value = 0.0
    else:
        exp_t = max(1e-9, total * exp_t_share)
        exp_c = max(1e-9, total * exp_c_share)
        chi2 = ((n_treatment - exp_t) ** 2) / exp_t + ((n_control - exp_c) ** 2) / exp_c
        p_value = float(math.erfc(math.sqrt(max(0.0, chi2) / 2.0)))

    if total <= 0 or min(n_control, n_treatment) <= 0:
        status = "FAIL"
    elif p_value < 0.01 or imbalance_pp >= 10.0:
        status = "FAIL"
    elif p_value < 0.05 or imbalance_pp >= 5.0:
        status = "WARN"
    else:
        status = "PASS"

    return {
        "run_id": run_id,
        "experiment_id": experiment_id,
        "expected_split": {"control": round(exp_c_share, 6), "treatment": round(exp_t_share, 6)},
        "observed_counts_by_arm": {"control": int(n_control), "treatment": int(n_treatment)},
        "test_name": "chi_square_df1",
        "p_value": round(max(0.0, min(1.0, p_value)), 6),
        "imbalance_pp": round(imbalance_pp, 4),
        "status": status,
        "version": "srm_check.v1",
    }


def _write_srm_artifact(payload: dict[str, Any]) -> Path:
    run_id = str(payload.get("run_id", "unknown"))
    experiment_id = str(payload.get("experiment_id", "unknown"))
    out_path = Path(f"data/ab_reports/{run_id}_{experiment_id}_srm_check.v1.json")
    _safe_write_json(out_path, payload)
    write_sha256_sidecar(out_path)
    return out_path


def _summarize_recovered_order_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    per_arm: dict[str, dict[str, Any]] = {
        "control": {"n_orders": 0, "units": set(), "aov": [], "gp": [], "req": 0.0, "ful": 0.0, "gmv": 0.0, "gp_sum": 0.0},
        "treatment": {"n_orders": 0, "units": set(), "aov": [], "gp": [], "req": 0.0, "ful": 0.0, "gmv": 0.0, "gp_sum": 0.0},
    }
    for r in rows:
        arm = str(r.get("arm", "")).strip()
        if arm not in per_arm:
            continue
        s = per_arm[arm]
        s["n_orders"] += 1
        s["units"].add(str(r.get("unit_id", "")))
        gmv = _to_float(r.get("order_gmv"))
        gp = _to_float(r.get("order_gp"))
        req = _to_float(r.get("requested_units"))
        ful = _to_float(r.get("fulfilled_units"))
        s["aov"].append(gmv)
        s["gp"].append(gp)
        s["req"] += req
        s["ful"] += ful
        s["gmv"] += gmv
        s["gp_sum"] += gp

    out: list[dict[str, Any]] = []
    for arm, s in per_arm.items():
        aov_vals = s["aov"]
        gp_vals = s["gp"]
        mean_aov = sum(aov_vals) / len(aov_vals) if aov_vals else 0.0
        mean_gp = sum(gp_vals) / len(gp_vals) if gp_vals else 0.0
        var_aov = (
            sum((x - mean_aov) ** 2 for x in aov_vals) / (len(aov_vals) - 1)
            if len(aov_vals) > 1
            else 0.0
        )
        var_gp = (
            sum((x - mean_gp) ** 2 for x in gp_vals) / (len(gp_vals) - 1)
            if len(gp_vals) > 1
            else 0.0
        )
        out.append(
            {
                "arm": arm,
                "n_orders": int(s["n_orders"]),
                "n_units": int(len(s["units"])),
                "mean_aov": float(mean_aov),
                "var_aov": float(var_aov),
                "mean_gp_order": float(mean_gp),
                "var_gp_order": float(var_gp),
                "gmv": float(s["gmv"]),
                "gp": float(s["gp_sum"]),
                "requested_units": float(s["req"]),
                "fulfilled_units": float(s["ful"]),
            }
        )
    return out


def _bootstrap_ci(values_t: list[float], values_c: list[float], iters: int, seed: int) -> tuple[float | None, float | None]:
    if not values_t or not values_c or iters < 30:
        return None, None
    rng = random.Random(seed)
    n_t = len(values_t)
    n_c = len(values_c)
    diffs: list[float] = []
    for _ in range(iters):
        bt = [values_t[rng.randrange(n_t)] for _ in range(n_t)]
        bc = [values_c[rng.randrange(n_c)] for _ in range(n_c)]
        diffs.append((sum(bt) / n_t) - (sum(bc) / n_c))
    diffs.sort()
    lo_idx = int(0.025 * (iters - 1))
    hi_idx = int(0.975 * (iters - 1))
    return diffs[lo_idx], diffs[hi_idx]


def _primary_metric_values(
    conn,
    run_id: str,
    experiment_id: str,
    orders_table: str,
    assignment_source: str,
    unit_type: str,
    primary_metric: str,
) -> dict[str, list[float]]:
    orders_table = _assert_safe_dynamic_relation_name(orders_table)
    assignment_source = _assert_safe_dynamic_relation_name(assignment_source)
    has_customer_col = _table_has_column(conn, orders_table, "customer_id")
    customer_join = "o.customer_id" if has_customer_col else "os.customer_id"
    raw_join = (
        ""
        if has_customer_col
        else "LEFT JOIN raw.raw_orders_stream os ON os.order_id = o.order_id AND os.store_id = o.store_id AND os.date = o.date"
    )
    if primary_metric == "buyers":
        if unit_type == "customer":
            has_customer_col = _table_has_column(conn, orders_table, "customer_id")
            order_exists_expr = "COUNT(o.order_id)" if has_customer_col else "COUNT(os.order_id)"
            customer_id_pred = "" if has_customer_col else "AND os.customer_id = a.unit_id"
            rows = conn.execute(
                text(
                    f"""
                    SELECT
                      a.arm,
                      CASE WHEN {order_exists_expr} > 0 THEN 1.0 ELSE 0.0 END AS metric_value
                    FROM {assignment_source} a
                    LEFT JOIN {orders_table} o
                      ON o.run_id = :run_id
                     {f"AND o.customer_id = a.unit_id" if has_customer_col else ""}
                    {"" if has_customer_col else "LEFT JOIN raw.raw_orders_stream os ON os.order_id = o.order_id AND os.store_id = o.store_id AND os.date = o.date"}
                    WHERE a.run_id = :run_id
                      AND a.experiment_id = :experiment_id
                      AND a.unit_type = 'customer'
                      {customer_id_pred}
                    GROUP BY a.arm, a.unit_id
                    """
                ),
                {"run_id": run_id, "experiment_id": experiment_id},
            ).mappings().all()
        else:
            rows = conn.execute(
                text(
                    f"""
                    SELECT
                      a.arm,
                      CASE WHEN COUNT(o.order_id) > 0 THEN 1.0 ELSE 0.0 END AS metric_value
                    FROM {assignment_source} a
                    LEFT JOIN {orders_table} o
                      ON o.run_id = :run_id
                     AND o.store_id = a.unit_id
                    WHERE a.run_id = :run_id
                      AND a.experiment_id = :experiment_id
                      AND a.unit_type = 'store'
                    GROUP BY a.arm, a.unit_id
                    """
                ),
                {"run_id": run_id, "experiment_id": experiment_id},
            ).mappings().all()
    elif primary_metric in {"writeoff_rate_adj", "writeoff_units", "writeoff_cogs"}:
        if unit_type != "store":
            return {"control": [], "treatment": []}
        qty_col = _writeoff_qty_column(conn)
        if primary_metric in {"writeoff_rate_adj", "writeoff_units"} and not qty_col:
            return {"control": [], "treatment": []}
        value_expr = (
            f"COALESCE(wr.writeoff_units, 0.0) / NULLIF(req.requested_units, 0.0)"
            if primary_metric == "writeoff_rate_adj"
            else ("COALESCE(wr.writeoff_units, 0.0)" if primary_metric == "writeoff_units" else "COALESCE(wr.writeoff_cogs, 0.0)")
        )
        wr_select = (
            f"SUM({qty_col})::double precision AS writeoff_units,\n"
            "                  SUM(writeoff_cogs)::double precision AS writeoff_cogs"
            if qty_col
            else "NULL::double precision AS writeoff_units,\n                  SUM(writeoff_cogs)::double precision AS writeoff_cogs"
        )
        rows = conn.execute(
            text(
                f"""
                WITH req AS (
                  SELECT run_id, store_id, SUM(requested_units)::double precision AS requested_units
                  FROM {orders_table}
                  WHERE run_id = :run_id
                  GROUP BY run_id, store_id
                ),
                wr AS (
                  SELECT run_id, store_id, {wr_select}
                  FROM step1.step1_writeoff_log
                  WHERE run_id = :run_id
                  GROUP BY run_id, store_id
                )
                SELECT
                  a.arm,
                  {value_expr} AS metric_value
                FROM {assignment_source} a
                JOIN req
                  ON req.run_id = a.run_id
                 AND req.store_id = a.unit_id
                LEFT JOIN wr
                  ON wr.run_id = req.run_id
                 AND wr.store_id = req.store_id
                WHERE a.run_id = :run_id
                  AND a.experiment_id = :experiment_id
                  AND a.unit_type = 'store'
                """
            ),
            {"run_id": run_id, "experiment_id": experiment_id},
        ).mappings().all()
    else:
        if unit_type == "customer":
            rows = conn.execute(
                text(
                    f"""
                    SELECT
                      a.arm,
                      AVG(o.order_gmv)::double precision AS metric_value
                    FROM {orders_table} o
                    {raw_join}
                    JOIN {assignment_source} a
                      ON a.run_id = o.run_id
                     AND a.experiment_id = :experiment_id
                     AND a.unit_type = 'customer'
                     AND a.unit_id = {customer_join}
                    WHERE o.run_id = :run_id
                    GROUP BY a.arm, a.unit_id
                    """
                ),
                {"run_id": run_id, "experiment_id": experiment_id},
            ).mappings().all()
        else:
            rows = conn.execute(
                text(
                    f"""
                    SELECT
                      a.arm,
                      AVG(o.order_gmv)::double precision AS metric_value
                    FROM {orders_table} o
                    JOIN {assignment_source} a
                      ON a.run_id = o.run_id
                     AND a.experiment_id = :experiment_id
                     AND a.unit_type = 'store'
                     AND a.unit_id = o.store_id
                    WHERE o.run_id = :run_id
                    GROUP BY a.arm, a.unit_id
                    """
                ),
                {"run_id": run_id, "experiment_id": experiment_id},
            ).mappings().all()
    out = {"control": [], "treatment": []}
    for r in rows:
        arm = str(r.get("arm", "")).strip()
        try:
            val = float(r.get("metric_value"))
        except Exception:
            continue
        if arm in out:
            out[arm].append(val)
    return out


def _classify_ab_failure(status: str, notes: list[str], errors: list[str]) -> dict[str, Any]:
    status_u = str(status or "").upper()
    note_s = [str(n).strip() for n in notes if str(n).strip()]
    err_s = [str(e).strip() for e in errors if str(e).strip()]
    joined_notes = " | ".join(note_s).lower()
    joined_errors = " | ".join(err_s).lower()

    pipeline_status = "PASS"
    error_family = "NONE"
    error_code = "NONE"

    if status_u in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "INVALID", "INVALID_METHODS", "BLOCKED_BY_DATA"}:
        pipeline_status = "FAIL"

    if status_u == "MISSING_ASSIGNMENT":
        preflight_code = None
        for n in note_s:
            if n.startswith("preflight_error_code:"):
                preflight_code = n.split(":", 1)[1].strip().upper() or None
                break
        if preflight_code:
            code_to_family = {
                "CONTRACT_EXPERIMENT_ID_MISSING": "CONTRACT",
                "CONTRACT_PRIMARY_METRIC_MISSING": "CONTRACT",
                "CONTRACT_PRIMARY_METRIC_UNSUPPORTED": "CONTRACT",
                "CONTRACT_PRIMARY_METRIC_IMMUTABLE": "CONTRACT",
                "CONTRACT_ESTIMAND_FIELDS_MISSING": "CONTRACT",
                "DATA_COLUMN_MISSING_CUSTOMER_ID": "DATA_SCHEMA",
                "DATA_ASSIGNMENT_MISSING_FOR_REQUESTED_UNIT": "DATA_ASSIGNMENT",
                "DATA_NO_ORDERS_FOR_EXPERIMENT": "DATA_JOIN",
                "DATA_ACCESS_SMOKE_CHECK_UNAVAILABLE": "DATA_ACCESS",
                "DATA_JOIN_CUSTOMER_GRAIN_UNAVAILABLE": "DATA_JOIN",
                "DATA_JOIN_STORE_GRAIN_FAILED": "DATA_JOIN",
                "DATA_JOIN_PROBE_EMPTY_FOR_REQUESTED_UNIT": "DATA_JOIN",
                "DATA_SOURCE_TYPE_UNKNOWN": "DATA_CONTRACT",
                "DATA_CONTRACT_GOAL1_REASON_COVERAGE": "DATA_CONTRACT",
                "DATA_CONTRACT_GOAL1_EXPIRY_COVERAGE": "DATA_CONTRACT",
                "DATA_CONTRACT_GOAL1_BATCH_COVERAGE": "DATA_CONTRACT",
                "METHOD_ANALYSIS_UNIT_MISMATCH": "METHOD",
                "METHOD_PRIMARY_METRIC_UNIT_MISMATCH": "METHOD",
            }
            error_family = code_to_family.get(preflight_code, "DATA_CONTRACT")
            error_code = preflight_code
        elif "missing_experiment_id" in joined_notes:
            error_family = "CONTRACT"
            error_code = "CONTRACT_EXPERIMENT_ID_MISSING"
        elif (
            "customer_join_error:" in joined_notes
            or "customer_join_unavailable_fallback_store" in joined_notes
            or "customer_join_error_post_preflight:" in joined_notes
        ):
            error_family = "DATA_JOIN"
            error_code = "DATA_JOIN_CUSTOMER_GRAIN_UNAVAILABLE"
        elif "store_join_error_post_preflight:" in joined_notes:
            error_family = "DATA_JOIN"
            error_code = "DATA_JOIN_STORE_GRAIN_FAILED"
        elif "assignment_recovery_failed" in joined_notes:
            error_family = "DATA_ASSIGNMENT"
            error_code = "DATA_ASSIGNMENT_RECOVERY_FAILED"
        elif "orders_have_experiment_but_assignment_log_empty" in joined_errors:
            error_family = "DATA_CONTRACT"
            error_code = "DATA_ASSIGNMENT_LOG_EMPTY_WITH_EXPERIMENT_ROWS"
        elif "permission" in joined_notes or "privilege" in joined_notes:
            error_family = "DATA_ACCESS"
            error_code = "DATA_ASSIGNMENT_VISIBILITY_UNAVAILABLE"
        else:
            error_family = "DATA_ASSIGNMENT"
            error_code = "DATA_ASSIGNMENT_MISSING"
    elif status_u == "METHODOLOGY_MISMATCH":
        if "customer_join_error:" in joined_notes or "customer_join_unavailable_fallback_store" in joined_notes:
            error_family = "DATA_JOIN"
            error_code = "DATA_JOIN_CUSTOMER_GRAIN_UNAVAILABLE"
        else:
            error_family = "METHOD"
            error_code = "METHOD_ANALYSIS_UNIT_MISMATCH"
    elif status_u == "INVALID_METHODS":
        error_family = "STATS"
        error_code = "STATS_METHOD_INCONSISTENCY"
    elif status_u == "UNDERPOWERED":
        error_family = "STATS"
        error_code = "STATS_UNDERPOWERED"
    elif status_u == "INCONCLUSIVE":
        error_family = "STATS"
        error_code = "STATS_INCONCLUSIVE"
    elif status_u == "HOLD_RISK":
        error_family = "RISK"
        error_code = "RISK_GUARDRAIL_OR_SRM_WARN"
    elif status_u == "BLOCKED_BY_DATA":
        error_family = "DATA_CONTRACT"
        if "goal1_contract_incomplete" in joined_notes:
            error_code = "DATA_GOAL1_CONTRACT_INCOMPLETE"
        elif "unknown_data_source_type" in joined_notes:
            error_code = "DATA_SOURCE_TYPE_UNKNOWN"
        else:
            error_code = "DATA_BLOCKED_BY_DATA"

    signals: list[str] = []
    for n in note_s:
        if n not in signals:
            signals.append(n)
    for e in err_s:
        if e not in signals:
            signals.append(e)

    return {
        "pipeline_status": pipeline_status,
        "error_family": error_family,
        "error_code": error_code,
        "error_signals": signals[:20],
    }


def _ab_result_payload(
    run_id: str,
    experiment_id: str,
    unit_type: str,
    status: str,
    methodology_text: str,
    arms: dict[str, Any],
    summary: dict[str, Any],
    notes: list[str],
    errors: list[str] | None = None,
) -> dict[str, Any]:
    error_list = list(errors or [])
    failure_meta = _classify_ab_failure(status=status, notes=notes, errors=error_list)
    return {
        "run_id": run_id,
        "experiment_id": experiment_id,
        "unit_type": unit_type,
        "status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "methodology_text": methodology_text,
        "sample_size_gate": {
            "min_orders_per_arm": MIN_ORDERS_PER_ARM,
            "min_units_per_arm": MIN_UNITS_PER_ARM,
        },
        "arms": arms,
        "summary": summary,
        "notes": notes,
        "errors": error_list,
        "failure_meta": failure_meta,
        "version": "ab_analysis.v1.1",
    }


def _render_md(payload: dict[str, Any]) -> str:
    s = payload.get("summary", {})
    fm = payload.get("failure_meta", {}) if isinstance(payload.get("failure_meta"), dict) else {}
    lines = [
        f"# AB Analysis: {payload['run_id']} / {payload['experiment_id']}",
        "",
        f"- status: `{payload['status']}`",
        f"- unit_type: `{payload['unit_type']}`",
        f"- methodology: {payload.get('methodology_text', '')}",
        f"- pipeline_status: `{fm.get('pipeline_status', 'unknown')}`",
        f"- error_family: `{fm.get('error_family', 'none')}`",
        f"- error_code: `{fm.get('error_code', 'none')}`",
        "",
        "## Uplift",
        f"- primary_metric: `{s.get('primary_metric')}`",
        f"- primary_control: `{s.get('primary_metric_control')}`",
        f"- primary_treatment: `{s.get('primary_metric_treatment')}`",
        f"- primary_delta_abs: `{s.get('primary_metric_delta_abs')}`",
        f"- primary_uplift: `{s.get('primary_metric_uplift')}`",
        f"- primary_uplift_ci95: `{s.get('primary_metric_uplift_ci95')}`",
        f"- primary_p_value: `{s.get('primary_metric_p_value')}`",
        f"- aov_uplift: `{s.get('aov_uplift')}`",
        f"- aov_uplift_ci95: `{s.get('aov_uplift_ci95')}`",
        f"- gp_per_order_uplift: `{s.get('gp_per_order_uplift')}`",
        f"- fill_rate_uplift: `{s.get('fill_rate_uplift')}`",
        "",
        "## Sample",
        f"- n_orders_control: `{s.get('n_orders_control')}`",
        f"- n_orders_treatment: `{s.get('n_orders_treatment')}`",
        f"- n_units_control: `{s.get('n_units_control')}`",
        f"- n_units_treatment: `{s.get('n_units_treatment')}`",
    ]
    if payload.get("notes"):
        lines.extend(["", "## Notes"])
        for n in payload["notes"]:
            lines.append(f"- {n}")
    if fm.get("error_signals"):
        lines.extend(["", "## Failure Signals"])
        for sig in fm.get("error_signals", []):
            lines.append(f"- {sig}")
    if payload.get("errors"):
        lines.extend(["", "## Errors"])
        for err in payload.get("errors", []):
            lines.append(f"- {err}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run minimal deterministic AB analysis")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--pgservice", default=DEFAULT_SERVICE)
    parser.add_argument(
        "--primary-metric",
        default="",
    )
    parser.add_argument("--bootstrap-iters", type=int, default=DEFAULT_BOOTSTRAP_ITERS)
    parser.add_argument("--allow-assignment-recovery", type=int, default=0, choices=[0, 1])
    args = parser.parse_args()

    run_id = args.run_id
    dsn = _resolve_dsn(args.pgservice)
    _assert_local_dsn(dsn)

    log_path = Path(f"data/logs/ab_analysis_{run_id}.log")
    out_dir = Path("data/ab_reports")
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        engine = create_engine(dsn)
        notes: list[str] = []
        with engine.begin() as conn:
            conn.execute(text("SET LOCAL statement_timeout = '15s';"))
            conn.execute(text("SET TRANSACTION READ ONLY;"))
            errors: list[str] = []
            exp_id = str(args.experiment_id).strip()
            reg_exp_id, reg_unit = (None, None)
            if not exp_id:
                reg_exp_id, reg_unit = _read_experiment_from_registry(conn, run_id)
            run_cfg = _read_run_config(conn, run_id)
            snapshot_path = Path(f"data/metrics_snapshots/{run_id}.json")
            data_source_type, contract_completeness = _read_snapshot_context(snapshot_path)
            if not exp_id:
                exp_id = reg_exp_id or ""
            if not exp_id:
                payload = _ab_result_payload(
                    run_id=run_id,
                    experiment_id="missing",
                    unit_type="unknown",
                    status="MISSING_ASSIGNMENT",
                    methodology_text="difference in means, fixed 14d window",
                    arms={},
                    summary={},
                    notes=["missing_experiment_id"],
                )
                (out_dir / f"{run_id}_missing_ab.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                (out_dir / f"{run_id}_missing_ab.md").write_text(_render_md(payload), encoding="utf-8")
                print(f"ok: ab analysis written for run_id={run_id}")
                return

            orders_table = _detect_order_source(conn)
            assignment_source = _detect_assignment_source(conn)
            assignment_counts = _assignment_counts(conn, run_id, exp_id, assignment_source)
            assignment_total = (
                assignment_counts["customer"]["control"]
                + assignment_counts["customer"]["treatment"]
                + assignment_counts["store"]["control"]
                + assignment_counts["store"]["treatment"]
            )
            smoke_orders_experiment = _orders_with_experiment_rows(conn, run_id, exp_id, orders_table)
            if smoke_orders_experiment is None:
                notes.append("assignment_smoke_check_unavailable_privilege")
            elif smoke_orders_experiment > 0 and assignment_total == 0:
                errors.append("BUG:orders_have_experiment_but_assignment_log_empty")
            requested_unit = str(reg_unit or run_cfg.get("experiment_unit") or "customer").strip().lower()
            unit_type = requested_unit
            cli_primary_metric = str(args.primary_metric or "").strip().lower()
            contract_ctx, contract_issues = _resolve_estimand_contract(
                run_cfg,
                cli_primary_metric=cli_primary_metric,
                requested_unit=requested_unit,
            )
            contract_hints = _legacy_contract_remediation_hints(
                contract_issues=contract_issues,
                run_cfg=run_cfg,
                requested_unit=requested_unit,
                cli_primary_metric=cli_primary_metric,
            )
            contract_ctx["_issues"] = contract_issues
            primary_metric = str(contract_ctx.get("primary_metric_id", "")).strip().lower()
            if contract_issues:
                notes.extend([f"contract_issue:{issue}" for issue in contract_issues])
                notes.extend([f"legacy_contract_hint:{hint}" for hint in contract_hints])
            if cli_primary_metric and cli_primary_metric not in ALLOWED_PRIMARY_METRICS:
                raise SystemExit(f"unsupported --primary-metric: {cli_primary_metric}")

            preflight = _run_ab_preflight(
                conn,
                run_id=run_id,
                experiment_id=exp_id,
                requested_unit=requested_unit,
                primary_metric=primary_metric,
                orders_table=orders_table,
                assignment_source=assignment_source,
                assignment_counts=assignment_counts,
                smoke_orders_experiment=smoke_orders_experiment,
                contract_context=contract_ctx,
                data_source_type=data_source_type,
                contract_completeness=contract_completeness,
            )
            preflight_json_path, preflight_md_path = _write_preflight_artifacts(preflight)
            notes.append(f"ab_preflight_json:{preflight_json_path}")
            notes.append(f"ab_preflight_md:{preflight_md_path}")
            if str(preflight.get("status", "")).upper() != "PASS":
                preflight_family = str(preflight.get("error_family", "")).upper()
                preflight_code = str(preflight.get("error_code", "")).upper()
                preflight_fail_status = (
                    "INVALID_METHODS"
                    if (
                        preflight_family in {"METHOD", "CONTRACT"}
                        or preflight_code.startswith("METHOD_")
                        or preflight_code.startswith("CONTRACT_")
                    )
                    else ("BLOCKED_BY_DATA" if preflight_family in {"DATA_CONTRACT", "DATA_SCHEMA", "DATA_ACCESS"} else "MISSING_ASSIGNMENT")
                )
                summary_missing = {
                    "primary_metric": primary_metric,
                    "estimand_id": contract_ctx.get("estimand_id"),
                    "primary_metric_id": contract_ctx.get("primary_metric_id"),
                    "metric_semantics_id": contract_ctx.get("metric_semantics_id"),
                    "randomization_unit": contract_ctx.get("randomization_unit"),
                    "analysis_unit": contract_ctx.get("analysis_unit"),
                    "attribution_window_rule": contract_ctx.get("attribution_window_rule"),
                    "primary_metric_uplift": None,
                    "primary_metric_uplift_ci95": None,
                    "sample_size_control": 0,
                    "sample_size_treat": 0,
                    "preflight_status": preflight.get("status"),
                    "ab_design_contract": _writeoff_design_metadata(run_cfg, requested_unit, unit_type, primary_metric),
                    "contract_remediation_hints": contract_hints,
                    "data_source_type": data_source_type,
                    "contract_completeness": contract_completeness,
                }
                notes.extend(
                    [
                        "ab_preflight_fail",
                        f"preflight_error_family:{preflight.get('error_family')}",
                        f"preflight_error_code:{preflight.get('error_code')}",
                    ]
                )
                payload = _ab_result_payload(
                    run_id=run_id,
                    experiment_id=exp_id,
                    unit_type=unit_type,
                    status=preflight_fail_status,
                    methodology_text=(
                        f"preflight validation stop, unit={unit_type}, "
                        f"primary_metric={primary_metric}, no statistical execution"
                    ),
                    arms=assignment_counts,
                    summary=summary_missing,
                    notes=notes + [f"preflight_error_detail:{preflight.get('error_detail')}"] ,
                    errors=errors,
                )
                out_json = out_dir / f"{run_id}_{exp_id}_ab.json"
                out_md = out_dir / f"{run_id}_{exp_id}_ab.md"
                out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                write_sha256_sidecar(out_json)
                out_md.write_text(_render_md(payload), encoding="utf-8")
                print(f"ok: ab analysis written for run_id={run_id}")
                return

            rows: list[dict[str, Any]] = []
            recovered_rows: list[dict[str, Any]] = []
            recovered_used = False
            if requested_unit == "customer":
                try:
                    with conn.begin_nested():
                        rows = _order_metrics_customer(conn, run_id, exp_id, orders_table, assignment_source)
                    unit_type = "customer"
                except Exception as exc:
                    notes.append(f"customer_join_error_post_preflight:{str(exc).splitlines()[0][:140]}")
                    rows = []
            else:
                try:
                    with conn.begin_nested():
                        rows = _order_metrics_store(conn, run_id, exp_id, orders_table, assignment_source)
                    unit_type = "store"
                except Exception as exc:
                    notes.append(f"store_join_error_post_preflight:{str(exc).splitlines()[0][:140]}")
                    rows = []

            methodology_mismatch = False

            if not rows and assignment_total == 0 and int(args.allow_assignment_recovery) == 1:
                treat_pct = int(run_cfg.get("experiment_treat_pct") or 50)
                treat_pct = max(0, min(100, treat_pct))
                salt = str(run_cfg.get("experiment_salt") or run_id).strip() or run_id
                unit_type, recovered_counts, recovered_rows, recovered_notes = _recover_assignment_from_orders(
                    conn=conn,
                    run_id=run_id,
                    experiment_id=exp_id,
                    requested_unit=requested_unit,
                    orders_table=orders_table,
                    treat_pct=treat_pct,
                    salt=salt,
                )
                if recovered_rows:
                    recovered_used = True
                    assignment_counts = recovered_counts
                    if requested_unit == "customer" and unit_type != "customer":
                        notes.extend(recovered_notes + ["assignment_recovery_unit_mismatch_blocked"])
                        rows = []
                        unit_type = requested_unit
                    else:
                        rows = _summarize_recovered_order_rows(recovered_rows)
                        notes.extend(recovered_notes + ["assignment_recovered_post_hoc"])

            if not rows:
                summary_missing = {
                    "primary_metric": primary_metric,
                    "estimand_id": contract_ctx.get("estimand_id"),
                    "primary_metric_id": contract_ctx.get("primary_metric_id"),
                    "metric_semantics_id": contract_ctx.get("metric_semantics_id"),
                    "randomization_unit": contract_ctx.get("randomization_unit"),
                    "analysis_unit": contract_ctx.get("analysis_unit"),
                    "attribution_window_rule": contract_ctx.get("attribution_window_rule"),
                    "primary_metric_uplift": None,
                    "primary_metric_uplift_ci95": None,
                    "sample_size_control": 0,
                    "sample_size_treat": 0,
                    "ab_design_contract": _writeoff_design_metadata(run_cfg, requested_unit, unit_type, primary_metric),
                    "data_source_type": data_source_type,
                    "contract_completeness": contract_completeness,
                }
                missing_reason = "missing_assignment_log"
                if assignment_total == 0 and int(args.allow_assignment_recovery) == 1:
                    missing_reason = "assignment_recovery_failed"
                payload = _ab_result_payload(
                    run_id=run_id,
                    experiment_id=exp_id,
                    unit_type=unit_type,
                    status="MISSING_ASSIGNMENT",
                    methodology_text=(
                        f"difference in means, fixed 14d window, unit={unit_type}, "
                        f"assignment hash, primary_metric={primary_metric}, bootstrap_iters={args.bootstrap_iters}"
                    ),
                    arms=assignment_counts,
                    summary=summary_missing,
                    notes=notes + [missing_reason],
                    errors=errors,
                )
                out_json = out_dir / f"{run_id}_{exp_id}_ab.json"
                out_md = out_dir / f"{run_id}_{exp_id}_ab.md"
                out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                write_sha256_sidecar(out_json)
                out_md.write_text(_render_md(payload), encoding="utf-8")
                print(f"ok: ab analysis written for run_id={run_id}")
                return

            arm_rows = _arm_map(rows)
            c = arm_rows.get("control", {})
            t = arm_rows.get("treatment", {})

            n_orders_c = int(c.get("n_orders", 0) or 0)
            n_orders_t = int(t.get("n_orders", 0) or 0)
            n_units_c = int(c.get("n_units", 0) or 0)
            n_units_t = int(t.get("n_units", 0) or 0)

            mean_aov_c = _to_float(c.get("mean_aov"))
            mean_aov_t = _to_float(t.get("mean_aov"))
            var_aov_c = _to_float(c.get("var_aov"))
            var_aov_t = _to_float(t.get("var_aov"))

            mean_gp_c = _to_float(c.get("mean_gp_order"))
            mean_gp_t = _to_float(t.get("mean_gp_order"))
            var_gp_c = _to_float(c.get("var_gp_order"))
            var_gp_t = _to_float(t.get("var_gp_order"))

            req_c = _to_float(c.get("requested_units"))
            req_t = _to_float(t.get("requested_units"))
            ful_c = _to_float(c.get("fulfilled_units"))
            ful_t = _to_float(t.get("fulfilled_units"))

            fill_c = (ful_c / req_c) if req_c > 0 else None
            fill_t = (ful_t / req_t) if req_t > 0 else None
            fill_diff = (fill_t - fill_c) if (fill_t is not None and fill_c is not None) else None
            fill_uplift = (fill_diff / fill_c) if (fill_diff is not None and fill_c and fill_c != 0) else None

            aov_diff, aov_lo, aov_hi = _ci_diff(mean_aov_t, mean_aov_c, var_aov_t, var_aov_c, n_orders_t, n_orders_c)
            gp_diff, gp_lo, gp_hi = _ci_diff(mean_gp_t, mean_gp_c, var_gp_t, var_gp_c, n_orders_t, n_orders_c)
            aov_u, aov_u_lo, aov_u_hi = _pct_uplift_ci(aov_diff, aov_lo, aov_hi, mean_aov_c)
            gp_u, gp_u_lo, gp_u_hi = _pct_uplift_ci(gp_diff, gp_lo, gp_hi, mean_gp_c)
            aov_p_value = _p_value_from_diff(aov_diff, var_aov_t, var_aov_c, n_orders_t, n_orders_c)

            underpowered = (
                n_orders_c < MIN_ORDERS_PER_ARM
                or n_orders_t < MIN_ORDERS_PER_ARM
                or n_units_c < MIN_UNITS_PER_ARM
                or n_units_t < MIN_UNITS_PER_ARM
            )
            if underpowered:
                mde_estimate = "underpowered"
            else:
                mde_estimate = abs(float(aov_u_hi or 0.0) - float(aov_u_lo or 0.0)) / 2.0 if (aov_u_lo is not None and aov_u_hi is not None) else None

            try:
                with conn.begin_nested():
                    primary_values = _primary_metric_values(
                        conn=conn,
                        run_id=run_id,
                        experiment_id=exp_id,
                        orders_table=orders_table,
                        assignment_source=assignment_source,
                        unit_type=unit_type,
                        primary_metric=primary_metric,
                    )
            except Exception:
                primary_values = {"control": [], "treatment": []}
                notes.append("primary_metric_values_unavailable")
            pv_c = primary_values.get("control", [])
            pv_t = primary_values.get("treatment", [])
            primary_mean_c = (sum(pv_c) / len(pv_c)) if pv_c else None
            primary_mean_t = (sum(pv_t) / len(pv_t)) if pv_t else None
            primary_delta_abs = (
                (primary_mean_t - primary_mean_c)
                if (primary_mean_t is not None and primary_mean_c is not None)
                else None
            )
            primary_delta_pct = (
                (primary_delta_abs / primary_mean_c)
                if (primary_delta_abs is not None and primary_mean_c not in {None, 0.0})
                else None
            )
            bs_seed = int(hashlib.sha1(f"{run_id}:{exp_id}:{primary_metric}".encode("utf-8")).hexdigest()[:8], 16)
            bs_lo_abs, bs_hi_abs = _bootstrap_ci(pv_t, pv_c, max(30, int(args.bootstrap_iters)), bs_seed)
            if bs_lo_abs is not None and primary_mean_c not in {None, 0.0}:
                primary_ci_pct = [bs_lo_abs / primary_mean_c, bs_hi_abs / primary_mean_c]
            else:
                primary_ci_pct = None
            primary_p_value = _p_value_from_samples(pv_t, pv_c)
            expected_treat_share = max(
                0.0,
                min(1.0, (_to_float(run_cfg.get("experiment_treat_pct") or 50) / 100.0)),
            )
            srm_payload = _formal_srm_check(
                run_id=run_id,
                experiment_id=exp_id,
                n_control=n_units_c,
                n_treatment=n_units_t,
                expected_treatment_share=expected_treat_share,
            )
            srm_artifact_path = _write_srm_artifact(srm_payload)
            notes.append(f"srm_check_artifact:{srm_artifact_path}")

            invalid_methods = False
            expected_analysis_unit = str(contract_ctx.get("analysis_unit") or "").strip().lower()
            if expected_analysis_unit and unit_type != expected_analysis_unit:
                invalid_methods = True
                notes.append(
                    f"analysis_unit_runtime_mismatch:expected={expected_analysis_unit},observed={unit_type}"
                )
                errors.append("INVALID_METHODS:unit_of_inference_mismatch")
            if not pv_c or not pv_t:
                invalid_methods = True
                notes.append("primary_metric_values_missing_by_arm")
                errors.append("INVALID_METHODS:primary_metric_values_missing")

            status = "ASSIGNMENT_RECOVERED" if recovered_used else ("UNDERPOWERED" if underpowered else "OK")
            if underpowered:
                notes.append("extend_experiment_window_for_sample_size")
            if not underpowered and not recovered_used:
                ci_cross_zero = False
                ci = primary_ci_pct if primary_ci_pct is not None else [aov_u_lo, aov_u_hi]
                if ci[0] is not None and ci[1] is not None and (ci[0] <= 0.0 <= ci[1]):
                    ci_cross_zero = True
                if ci_cross_zero:
                    status = "INCONCLUSIVE"
                    notes.append("ci_crosses_zero_hold_extend")
            if invalid_methods:
                status = "INVALID_METHODS"
                notes.append("estimand_first_runtime_block")
            if methodology_mismatch:
                status = "METHODOLOGY_MISMATCH"
                notes.append("measurement_blind_spot")
                errors.append(
                    "Cannot compute uplift: Customer assignment lost, store aggregation invalid for customer experiment."
                )
                aov_u = None
                aov_u_lo = None
                aov_u_hi = None
                gp_u = None
                gp_u_lo = None
                gp_u_hi = None
                fill_uplift = None
                primary_delta_abs = None
                primary_delta_pct = None
                primary_ci_pct = None
                primary_p_value = None
            if status != "METHODOLOGY_MISMATCH" and invalid_methods:
                aov_u = None
                aov_u_lo = None
                aov_u_hi = None
                gp_u = None
                gp_u_lo = None
                gp_u_hi = None
                fill_uplift = None
                primary_delta_abs = None
                primary_delta_pct = None
                primary_ci_pct = None
                primary_p_value = None
            if (
                data_source_type not in {"synthetic", "real", "mixed"}
                and status not in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "INVALID_METHODS", "ASSIGNMENT_RECOVERED"}
            ):
                status = "BLOCKED_BY_DATA"
                notes.append("unknown_data_source_type")
            goal1_ready = bool(contract_completeness.get("goal1_contract_ready", False))
            if (
                primary_metric in {"writeoff_rate_adj", "writeoff_units", "writeoff_cogs"}
                and not goal1_ready
                and status not in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "INVALID_METHODS", "ASSIGNMENT_RECOVERED"}
            ):
                status = "BLOCKED_BY_DATA"
                notes.append("goal1_contract_incomplete")

            summary = {
                "n_orders_control": n_orders_c,
                "n_orders_treatment": n_orders_t,
                "n_units_control": n_units_c,
                "n_units_treatment": n_units_t,
                "aov_control": mean_aov_c,
                "aov_treatment": mean_aov_t,
                "aov_uplift": aov_u,
                "aov_uplift_ci95": [aov_u_lo, aov_u_hi] if aov_u_lo is not None else None,
                "gp_per_order_control": mean_gp_c,
                "gp_per_order_treatment": mean_gp_t,
                "gp_per_order_uplift": gp_u,
                "gp_per_order_uplift_ci95": [gp_u_lo, gp_u_hi] if gp_u_lo is not None else None,
                "fill_rate_control": fill_c,
                "fill_rate_treatment": fill_t,
                "fill_rate_uplift": fill_uplift,
                "assignment_labels": {
                    "canonical_field": "arm",
                    "compat_alias": "variant",
                    "mapping": {"control": "control", "treatment": "treat"},
                },
                "estimand_id": contract_ctx.get("estimand_id"),
                "primary_metric_id": contract_ctx.get("primary_metric_id"),
                "metric_semantics_id": contract_ctx.get("metric_semantics_id"),
                "randomization_unit": contract_ctx.get("randomization_unit"),
                "analysis_unit": contract_ctx.get("analysis_unit"),
                "unit_of_inference": unit_type,
                "attribution_window_rule": contract_ctx.get("attribution_window_rule"),
                "primary_metric": primary_metric,
                "primary_metric_control": primary_mean_c,
                "primary_metric_treatment": primary_mean_t,
                "primary_metric_delta_abs": primary_delta_abs,
                "primary_metric_uplift": primary_delta_pct,
                "primary_metric_uplift_ci95": primary_ci_pct,
                "primary_metric_p_value": primary_p_value,
                "sample_size_control": n_orders_c if unit_type == "store" else n_units_c,
                "sample_size_treat": n_orders_t if unit_type == "store" else n_units_t,
                "mde_estimate": mde_estimate,
                "srm_status": str(srm_payload.get("status", "MISSING")),
                "srm_check_artifact": str(srm_artifact_path),
                "srm_test_name": srm_payload.get("test_name"),
                "srm_p_value": srm_payload.get("p_value"),
                "srm_imbalance_pp": srm_payload.get("imbalance_pp"),
                "gp_negative_rows": int((mean_gp_c < 0.0) or (mean_gp_t < 0.0)),
                "reasonable_bounds": {
                    "fill_rate_control_in_0_1": (fill_c is None) or (0.0 <= float(fill_c) <= 1.0),
                    "fill_rate_treatment_in_0_1": (fill_t is None) or (0.0 <= float(fill_t) <= 1.0),
                    "aov_control_nonnegative": mean_aov_c >= 0.0,
                    "aov_treatment_nonnegative": mean_aov_t >= 0.0,
                },
                "guardrail_checks": {
                    "gp_nonnegative": (mean_gp_c >= 0.0 and mean_gp_t >= 0.0),
                    "fill_rate_floor_0_92": (
                        (fill_c is not None and float(fill_c) >= 0.92)
                        and (fill_t is not None and float(fill_t) >= 0.92)
                    ),
                    "srm_status": str(srm_payload.get("status", "MISSING")),
                },
                "required_sample_size": {
                    "control": MIN_ORDERS_PER_ARM if unit_type == "store" else MIN_UNITS_PER_ARM,
                    "treatment": MIN_ORDERS_PER_ARM if unit_type == "store" else MIN_UNITS_PER_ARM,
                },
                "actual_sample_size": {
                    "control": n_orders_c if unit_type == "store" else n_units_c,
                    "treatment": n_orders_t if unit_type == "store" else n_units_t,
                },
                "assignment_recovered": bool(recovered_used),
                "analysis_status_detail": status,
                "metrics_snapshot_ref": str(snapshot_path),
                "data_source_type": data_source_type,
                "contract_completeness": contract_completeness,
                "recommendation": (
                    "stop_measurement_blind_spot"
                    if methodology_mismatch
                    else (
                    "hold_risk_reconstructed_assignment"
                    if recovered_used
                    else (
                    "extend"
                    if underpowered or status == "INCONCLUSIVE"
                    else "evaluate_rollout_with_guardrails"
                    )
                    )
                ),
                "ab_design_contract": _writeoff_design_metadata(run_cfg, requested_unit, unit_type, primary_metric),
            }
            if summary["gp_negative_rows"] > 0:
                notes.append("gp_negative_detected_guardrail")
                if status == "OK":
                    status = "HOLD_RISK"
            if summary["guardrail_checks"]["srm_status"] == "WARN" and status == "OK":
                status = "HOLD_RISK"
            if summary["guardrail_checks"]["srm_status"] == "FAIL" and status in {"OK", "HOLD_RISK", "INCONCLUSIVE"}:
                status = "INVALID_METHODS"
                notes.append("srm_formal_test_fail")

            payload = _ab_result_payload(
                run_id=run_id,
                experiment_id=exp_id,
                unit_type=unit_type,
                status=status,
                methodology_text=(
                    f"difference in means, fixed 14d window, unit={unit_type}, "
                    f"assignment hash, primary_metric={primary_metric}, bootstrap_iters={args.bootstrap_iters}"
                ),
                arms=arm_rows,
                summary=summary,
                notes=notes,
                errors=errors,
            )

        out_json = out_dir / f"{run_id}_{exp_id}_ab.json"
        out_md = out_dir / f"{run_id}_{exp_id}_ab.md"
        out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(out_json)
        out_md.write_text(_render_md(payload), encoding="utf-8")
        print(f"ok: ab analysis written for run_id={run_id}")
    except Exception:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(redact_text(traceback.format_exc()), encoding="utf-8")
        raise SystemExit(f"ab analysis failed. See {log_path}")


if __name__ == "__main__":
    main()
