from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from src.security_utils import verify_sha256_sidecar

_ENV_KEY = "DS_DOMAIN_TEMPLATE_PATH"
_LEGACY_ENV_KEY = "DS_DOMAIN_TEMPLATE"
_OVERRIDE_PATH = ""
_SCHEMA_PATHS = {
    "domain_template.v1": Path("configs/contracts/domain_template_v1.json"),
    "domain_template.v2": Path("configs/contracts/domain_template_v2.json"),
}


class ConfigurationError(RuntimeError):
    pass


def _as_list_of_str(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if text:
            out.append(text)
    return out


def _as_goal_id(value: Any) -> str:
    return str(value or "").strip().lower()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigurationError(f"Invalid Domain Template JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError(f"Invalid Domain Template payload: {path}")
    return payload


def _detect_contract_version(payload: dict[str, Any]) -> str:
    raw = str(payload.get("contract_version", "") or payload.get("version", "")).strip().lower()
    if raw == "domain_template.v2":
        return "domain_template.v2"
    if isinstance(payload.get("metrics_dictionary"), dict):
        return "domain_template.v2"
    return "domain_template.v1"


def _load_schema(contract_version: str) -> dict[str, Any]:
    schema_path = _SCHEMA_PATHS.get(contract_version)
    if schema_path is None:
        raise ConfigurationError(f"Unsupported Domain Template contract version: {contract_version}")
    if not schema_path.exists():
        raise ConfigurationError(f"Missing Domain Template schema: {schema_path}")
    ok, reason = verify_sha256_sidecar(schema_path, required=True)
    if not ok:
        raise ConfigurationError(f"Domain Template schema integrity error: {reason}")
    schema = _load_json(schema_path)
    return schema


def _validate_schema(payload: dict[str, Any]) -> None:
    schema = _load_schema(_detect_contract_version(payload))
    try:
        from jsonschema import validate as _validate  # type: ignore
    except Exception as exc:
        raise ConfigurationError("jsonschema dependency missing for Domain Template validation") from exc
    try:
        _validate(instance=payload, schema=schema)
    except Exception as exc:
        raise ConfigurationError(f"Domain Template schema validation failed: {exc}") from exc


def resolve_domain_template_path(path: str = "") -> Path:
    raw = (
        str(path or "").strip()
        or str(_OVERRIDE_PATH or "").strip()
        or str(os.getenv(_ENV_KEY, "")).strip()
        or str(os.getenv(_LEGACY_ENV_KEY, "")).strip()
    )
    if not raw:
        raise ConfigurationError("Missing Domain Template")
    resolved = Path(raw)
    if resolved.suffix.lower() != ".json":
        raise ConfigurationError("Domain Template must be a .json file")
    return resolved


def _convert_contract_v1(payload: dict[str, Any]) -> dict[str, Any]:
    goals_src = payload.get("goal_definitions")
    if not isinstance(goals_src, list):
        raise ConfigurationError("Missing Domain Template goals")

    mappings = payload.get("mappings", {}) if isinstance(payload.get("mappings"), dict) else {}
    target_to_primary = mappings.get("target_metric_to_primary_metric", {})
    if not isinstance(target_to_primary, dict):
        target_to_primary = {}

    goals: list[dict[str, Any]] = []
    metric_to_goal: dict[str, str] = {}
    goal_metric_groups: dict[str, list[str]] = {}
    primary_metrics: list[str] = []
    secondary_metrics: list[str] = []
    required_denominators: list[str] = []

    for row in goals_src:
        if not isinstance(row, dict):
            continue
        goal_id = _as_goal_id(row.get("goal_id"))
        alias = str(row.get("target_metric_alias", "")).strip()
        primary_metric = str(row.get("primary_metric", "")).strip()
        if not goal_id or not alias or not primary_metric:
            continue
        mapped_primary = str(target_to_primary.get(alias, "")).strip() or primary_metric
        expected_direction = str(row.get("expected_direction", "")).strip().lower()
        if expected_direction not in {"increase", "decrease"}:
            expected_direction = ""
        goals.append(
            {
                "goal_id": goal_id,
                "target_metric": alias,
                "default_primary_metric": mapped_primary,
                "commander_default_metric": primary_metric,
                "expected_direction": expected_direction,
                "risk_note": str(row.get("risk_note", "")).strip(),
            }
        )
        primary_metrics.append(primary_metric)
        secondary_metrics.extend(_as_list_of_str(row.get("secondary_metrics")))
        required_denominators.extend(_as_list_of_str(row.get("required_denominators")))

        family = _as_list_of_str(row.get("metric_family"))
        if alias not in family:
            family.append(alias)
        if primary_metric not in family:
            family.append(primary_metric)
        goal_metric_groups[goal_id] = family
        for metric in family:
            metric_to_goal[metric.strip().lower()] = goal_id

    if not goals:
        raise ConfigurationError("Missing Domain Template goals")

    guardrails_raw = payload.get("guardrails")
    guardrails_by_component: dict[str, list[dict[str, Any]]] = {}
    guardrails_default: list[dict[str, Any]] = []
    if isinstance(guardrails_raw, dict):
        for key, rows in guardrails_raw.items():
            if not isinstance(rows, list):
                continue
            guardrails_by_component[str(key).strip()] = [x for x in rows if isinstance(x, dict)]
        for preferred in ("doctor_variance", "commander_priority", "experiment_evaluator"):
            if preferred in guardrails_by_component:
                guardrails_default = guardrails_by_component[preferred]
                break
    elif isinstance(guardrails_raw, list):
        guardrails_default = [x for x in guardrails_raw if isinstance(x, dict)]

    thresholds_raw = payload.get("thresholds", {}) if isinstance(payload.get("thresholds"), dict) else {}
    doctor_thresholds = thresholds_raw.get("doctor_variance", {})
    if not isinstance(doctor_thresholds, dict):
        doctor_thresholds = {}
    doctor_cfg = payload.get("doctor") if isinstance(payload.get("doctor"), dict) else {}
    if isinstance(doctor_cfg.get("thresholds"), dict):
        doctor_thresholds = {**doctor_thresholds, **doctor_cfg.get("thresholds", {})}
    doctor_captain_issue_policies = doctor_cfg.get("captain_issue_policies") if isinstance(doctor_cfg.get("captain_issue_policies"), dict) else {}
    doctor_run_config_rules = doctor_cfg.get("run_config_rules") if isinstance(doctor_cfg.get("run_config_rules"), list) else []

    return {
        "version": str(payload.get("contract_version", "domain_template.v1") or "domain_template.v1"),
        "template_id": f"{str(payload.get('domain_id', 'template')).strip() or 'template'}_v1",
        "domain": str(payload.get("domain_id", "unknown_domain") or "unknown_domain"),
        "metrics": {
            "primary": primary_metrics,
            "secondary": secondary_metrics,
            "required_denominators": required_denominators,
            "goal_metric_groups": goal_metric_groups,
        },
        "goals": goals,
        "target_metric_to_primary_metric": {str(k): str(v) for k, v in target_to_primary.items() if str(k).strip() and str(v).strip()},
        "metric_to_goal": metric_to_goal,
        "guardrails": guardrails_default,
        "guardrails_by_component": guardrails_by_component,
        "doctor": {
            "thresholds": doctor_thresholds,
            "required_ready_now": _as_list_of_str(doctor_cfg.get("required_ready_now")),
            "blocked_phase2_metrics": _as_list_of_str(doctor_cfg.get("blocked_phase2_metrics")),
            "captain_issue_policies": {str(k): v for k, v in doctor_captain_issue_policies.items() if str(k).strip() and isinstance(v, dict)},
            "run_config_rules": [x for x in doctor_run_config_rules if isinstance(x, dict)],
        },
        "captain": {
            "allowed_sql_tables": [],
            "sql_step_templates": [],
        },
        "data_mapping_rules": payload.get("data_mapping_rules") if isinstance(payload.get("data_mapping_rules"), dict) else {},
    }


def _normalize_legacy(payload: dict[str, Any]) -> dict[str, Any]:
    goals_src = payload.get("goals")
    if not isinstance(goals_src, list):
        raise ConfigurationError("Missing Domain Template goals")

    goals: list[dict[str, Any]] = []
    for row in goals_src:
        if not isinstance(row, dict):
            continue
        goal_id = _as_goal_id(row.get("goal_id"))
        target_metric = str(row.get("target_metric", "")).strip()
        default_primary = str(row.get("default_primary_metric", "")).strip()
        commander_default = str(row.get("commander_default_metric", "")).strip() or default_primary
        expected_direction = str(row.get("expected_direction", "")).strip().lower()
        if expected_direction not in {"increase", "decrease"}:
            expected_direction = ""
        if not goal_id or not target_metric or not default_primary:
            continue
        goals.append(
            {
                "goal_id": goal_id,
                "target_metric": target_metric,
                "default_primary_metric": default_primary,
                "commander_default_metric": commander_default,
                "expected_direction": expected_direction,
                "risk_note": str(row.get("risk_note", "")).strip(),
            }
        )
    if not goals:
        raise ConfigurationError("Missing Domain Template goals")

    metrics = payload.get("metrics", {}) if isinstance(payload.get("metrics"), dict) else {}
    goal_metric_groups = metrics.get("goal_metric_groups", {}) if isinstance(metrics.get("goal_metric_groups"), dict) else {}

    target_map = payload.get("target_metric_to_primary_metric") if isinstance(payload.get("target_metric_to_primary_metric"), dict) else {}
    metric_to_goal = payload.get("metric_to_goal") if isinstance(payload.get("metric_to_goal"), dict) else {}

    return {
        "version": str(payload.get("version", "domain_template.v1") or "domain_template.v1"),
        "template_id": str(payload.get("template_id", "domain_template") or "domain_template"),
        "domain": str(payload.get("domain", "unknown_domain") or "unknown_domain"),
        "metrics": {
            "primary": _as_list_of_str(metrics.get("primary")),
            "secondary": _as_list_of_str(metrics.get("secondary")),
            "required_denominators": _as_list_of_str(metrics.get("required_denominators")),
            "goal_metric_groups": {
                _as_goal_id(k): _as_list_of_str(v)
                for k, v in goal_metric_groups.items()
                if _as_goal_id(k)
            },
        },
        "goals": goals,
        "target_metric_to_primary_metric": {str(k): str(v) for k, v in target_map.items() if str(k).strip() and str(v).strip()},
        "metric_to_goal": {str(k).strip().lower(): _as_goal_id(v) for k, v in metric_to_goal.items() if str(k).strip() and _as_goal_id(v)},
        "guardrails": [x for x in payload.get("guardrails", []) if isinstance(x, dict)] if isinstance(payload.get("guardrails"), list) else [],
        "guardrails_by_component": {
            str(k).strip(): [x for x in v if isinstance(x, dict)]
            for k, v in (payload.get("guardrails_by_component") if isinstance(payload.get("guardrails_by_component"), dict) else {}).items()
            if str(k).strip() and isinstance(v, list)
        },
        "doctor": payload.get("doctor") if isinstance(payload.get("doctor"), dict) else {},
        "captain": payload.get("captain") if isinstance(payload.get("captain"), dict) else {},
        "data_mapping_rules": payload.get("data_mapping_rules") if isinstance(payload.get("data_mapping_rules"), dict) else {},
    }


def _metric_expected_direction(metric_def: dict[str, Any]) -> str:
    direction = str(metric_def.get("direction_is_good", "")).strip().lower()
    if direction in {"increase", "decrease"}:
        return direction
    return ""


def _normalize_experiment_variants(raw: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for key in ("ctrl", "treatment"):
        row = raw.get(key)
        if not isinstance(row, dict):
            continue
        mode_tag = str(row.get("mode_tag", "")).strip()
        horizon_days = row.get("horizon_days")
        seed = row.get("seed")
        if not mode_tag:
            continue
        try:
            horizon_days_num = int(horizon_days)
        except Exception:
            continue
        try:
            seed_num = int(seed)
        except Exception:
            continue
        if horizon_days_num <= 0:
            continue
        overrides_raw = row.get("overrides")
        overrides = overrides_raw if isinstance(overrides_raw, dict) else {}
        out[key] = {
            "mode_tag": mode_tag,
            "horizon_days": horizon_days_num,
            "seed": seed_num,
            "overrides": dict(overrides),
        }
    return out


def _convert_contract_v2(payload: dict[str, Any]) -> dict[str, Any]:
    template_meta = payload.get("template_metadata") if isinstance(payload.get("template_metadata"), dict) else {}
    metrics_dictionary = payload.get("metrics_dictionary") if isinstance(payload.get("metrics_dictionary"), dict) else {}
    goals_taxonomy = payload.get("goals_taxonomy") if isinstance(payload.get("goals_taxonomy"), dict) else {}
    runtime_bindings = payload.get("runtime_bindings") if isinstance(payload.get("runtime_bindings"), dict) else {}
    eval_rules = payload.get("evaluation_rules") if isinstance(payload.get("evaluation_rules"), dict) else {}

    metrics_block = runtime_bindings.get("metrics") if isinstance(runtime_bindings.get("metrics"), dict) else {}
    doctor_cfg = runtime_bindings.get("doctor") if isinstance(runtime_bindings.get("doctor"), dict) else {}
    captain_cfg = runtime_bindings.get("captain") if isinstance(runtime_bindings.get("captain"), dict) else {}
    guardrails_by_component = runtime_bindings.get("guardrails_by_component")
    if not isinstance(guardrails_by_component, dict):
        guardrails_by_component = {}
    goal_rows = runtime_bindings.get("goals")
    if not isinstance(goal_rows, list):
        goal_rows = []

    primary_metrics = _as_list_of_str(metrics_block.get("primary"))
    secondary_metrics = _as_list_of_str(metrics_block.get("secondary"))
    required_denominators = _as_list_of_str(metrics_block.get("required_denominators"))
    goal_metric_groups = {
        _as_goal_id(k): _as_list_of_str(v)
        for k, v in (metrics_block.get("goal_metric_groups") if isinstance(metrics_block.get("goal_metric_groups"), dict) else {}).items()
        if _as_goal_id(k)
    }

    metric_to_goal: dict[str, str] = {}
    for goal_id_raw, metrics in goals_taxonomy.items():
        goal_id = _as_goal_id(goal_id_raw)
        if not goal_id:
            continue
        metric_names = _as_list_of_str(metrics)
        if not metric_names:
            continue
        if goal_id not in goal_metric_groups:
            goal_metric_groups[goal_id] = metric_names
        for metric_name in metric_names:
            metric_to_goal[str(metric_name).strip().lower()] = goal_id

    for metric_name, metric_def_raw in metrics_dictionary.items():
        if not isinstance(metric_def_raw, dict):
            continue
        role = str(metric_def_raw.get("role", "")).strip().lower()
        metric_key = str(metric_name).strip()
        if not metric_key:
            continue
        if role == "primary_target" and metric_key not in primary_metrics:
            primary_metrics.append(metric_key)
        elif role in {"secondary_target", "guardrail", "supporting"} and metric_key not in secondary_metrics:
            secondary_metrics.append(metric_key)
        denom = str(metric_def_raw.get("canonical_denominator", "")).strip()
        if denom and denom not in required_denominators:
            required_denominators.append(denom)

    goals: list[dict[str, Any]] = []
    for row in goal_rows:
        if not isinstance(row, dict):
            continue
        goal_id = _as_goal_id(row.get("goal_id"))
        target_metric = str(row.get("target_metric", "")).strip()
        default_primary = str(row.get("default_primary_metric", "")).strip()
        if not goal_id or not target_metric or not default_primary:
            continue
        commander_default = str(row.get("commander_default_metric", "")).strip() or default_primary
        expected_direction = str(row.get("expected_direction", "")).strip().lower()
        if expected_direction not in {"increase", "decrease"}:
            metric_def = metrics_dictionary.get(default_primary)
            expected_direction = _metric_expected_direction(metric_def) if isinstance(metric_def, dict) else ""
        goals.append(
            {
                "goal_id": goal_id,
                "target_metric": target_metric,
                "default_primary_metric": default_primary,
                "commander_default_metric": commander_default,
                "expected_direction": expected_direction,
                "risk_note": str(row.get("risk_note", "")).strip(),
            }
        )

    target_map = runtime_bindings.get("target_metric_to_primary_metric")
    target_metric_to_primary_metric = (
        {str(k): str(v) for k, v in target_map.items() if str(k).strip() and str(v).strip()}
        if isinstance(target_map, dict)
        else {}
    )

    if not goals:
        for goal_id, metric_names in goals_taxonomy.items():
            gid = _as_goal_id(goal_id)
            names = _as_list_of_str(metric_names)
            if not gid or not names:
                continue
            preferred_primary = next((m for m in names if m in primary_metrics), names[0])
            target_metric = f"{gid}_target"
            if target_metric not in target_metric_to_primary_metric:
                target_metric_to_primary_metric[target_metric] = preferred_primary
            metric_def = metrics_dictionary.get(preferred_primary)
            expected_direction = _metric_expected_direction(metric_def) if isinstance(metric_def, dict) else ""
            goals.append(
                {
                    "goal_id": gid,
                    "target_metric": target_metric,
                    "default_primary_metric": preferred_primary,
                    "commander_default_metric": preferred_primary,
                    "expected_direction": expected_direction,
                    "risk_note": "",
                }
            )

    if not goals:
        raise ConfigurationError("Missing Domain Template goals")

    for row in goals:
        alias = str(row.get("target_metric", "")).strip()
        primary_metric = str(row.get("default_primary_metric", "")).strip()
        if alias and primary_metric and alias not in target_metric_to_primary_metric:
            target_metric_to_primary_metric[alias] = primary_metric

    if not metric_to_goal:
        for row in goals:
            goal_id = _as_goal_id(row.get("goal_id"))
            for metric_name in goal_metric_groups.get(goal_id, []):
                metric_to_goal[str(metric_name).strip().lower()] = goal_id
            target_metric = str(row.get("target_metric", "")).strip().lower()
            if target_metric:
                metric_to_goal[target_metric] = goal_id
            primary_metric = str(row.get("default_primary_metric", "")).strip().lower()
            if primary_metric:
                metric_to_goal[primary_metric] = goal_id

    guardrails_default: list[dict[str, Any]] = []
    for metric_name, metric_def_raw in metrics_dictionary.items():
        if not isinstance(metric_def_raw, dict):
            continue
        if str(metric_def_raw.get("role", "")).strip().lower() != "guardrail":
            continue
        min_threshold = metric_def_raw.get("hard_threshold_min")
        max_threshold = metric_def_raw.get("hard_threshold_max")
        if min_threshold is not None:
            guardrails_default.append({"metric": str(metric_name), "op": ">=", "threshold": min_threshold})
        if max_threshold is not None:
            guardrails_default.append({"metric": str(metric_name), "op": "<=", "threshold": max_threshold})

    if not guardrails_by_component and guardrails_default:
        guardrails_by_component = {
            "doctor_variance": list(guardrails_default),
            "commander_priority": list(guardrails_default),
            "experiment_evaluator": list(guardrails_default),
        }
    if not guardrails_default and isinstance(guardrails_by_component, dict):
        for preferred in ("doctor_variance", "commander_priority", "experiment_evaluator"):
            rows = guardrails_by_component.get(preferred)
            if isinstance(rows, list):
                guardrails_default = [x for x in rows if isinstance(x, dict)]
                if guardrails_default:
                    break

    normalized_doctor = {
        "thresholds": doctor_cfg.get("thresholds") if isinstance(doctor_cfg.get("thresholds"), dict) else {},
        "required_ready_now": _as_list_of_str(doctor_cfg.get("required_ready_now")),
        "blocked_phase2_metrics": _as_list_of_str(doctor_cfg.get("blocked_phase2_metrics")),
        "captain_issue_policies": {
            str(k): v
            for k, v in (doctor_cfg.get("captain_issue_policies") if isinstance(doctor_cfg.get("captain_issue_policies"), dict) else {}).items()
            if str(k).strip() and isinstance(v, dict)
        },
        "run_config_rules": [x for x in doctor_cfg.get("run_config_rules", []) if isinstance(x, dict)]
        if isinstance(doctor_cfg.get("run_config_rules"), list)
        else [],
    }
    normalized_captain = {
        "allowed_sql_tables": _as_list_of_str(captain_cfg.get("allowed_sql_tables")),
        "sql_step_templates": _as_list_of_str(captain_cfg.get("sql_step_templates")),
    }
    experiment_variants = _normalize_experiment_variants(payload.get("experiment_variants"))

    return {
        "version": str(payload.get("contract_version", "domain_template.v2") or "domain_template.v2"),
        "template_id": str(payload.get("template_id", "domain_template_v2") or "domain_template_v2"),
        "domain": str(template_meta.get("domain_name", payload.get("domain", "unknown_domain")) or "unknown_domain"),
        "metrics": {
            "primary": primary_metrics,
            "secondary": secondary_metrics,
            "required_denominators": required_denominators,
            "goal_metric_groups": goal_metric_groups,
        },
        "goals": goals,
        "target_metric_to_primary_metric": target_metric_to_primary_metric,
        "metric_to_goal": metric_to_goal,
        "guardrails": guardrails_default,
        "guardrails_by_component": {
            str(k).strip(): [x for x in v if isinstance(x, dict)]
            for k, v in guardrails_by_component.items()
            if str(k).strip() and isinstance(v, list)
        },
        "doctor": normalized_doctor,
        "captain": normalized_captain,
        "experiment_variants": experiment_variants,
        "data_mapping_rules": payload.get("data_mapping_rules") if isinstance(payload.get("data_mapping_rules"), dict) else {},
        "evaluation_rules": eval_rules,
    }


def set_domain_template_override(path: str = "") -> None:
    global _OVERRIDE_PATH
    _OVERRIDE_PATH = str(path or "").strip()
    if _OVERRIDE_PATH:
        os.environ[_ENV_KEY] = _OVERRIDE_PATH
        os.environ[_LEGACY_ENV_KEY] = _OVERRIDE_PATH


def load_domain_template(path: str = "") -> dict[str, Any]:
    resolved = resolve_domain_template_path(path)
    if not resolved.exists():
        raise ConfigurationError(f"Missing Domain Template: {resolved}")
    ok, reason = verify_sha256_sidecar(resolved, required=True)
    if not ok:
        raise ConfigurationError(f"Domain Template integrity error: {reason}")

    payload = _load_json(resolved)
    _validate_schema(payload)
    contract_version = _detect_contract_version(payload)
    if contract_version == "domain_template.v2":
        normalized = _convert_contract_v2(payload)
    elif isinstance(payload.get("goal_definitions"), list):
        normalized = _convert_contract_v1(payload)
    else:
        normalized = _normalize_legacy(payload)

    normalized["source_path"] = str(resolved)
    return normalized


def domain_template_source(path: str = "") -> str:
    return str(resolve_domain_template_path(path))


def load_experiment_variants(path: str = "") -> dict[str, dict[str, Any]] | None:
    tpl = load_domain_template(path)
    variants = tpl.get("experiment_variants")
    if not isinstance(variants, dict):
        return None
    ctrl = variants.get("ctrl")
    treatment = variants.get("treatment")
    if not isinstance(ctrl, dict) or not isinstance(treatment, dict):
        return None
    return {
        "ctrl": dict(ctrl),
        "treatment": dict(treatment),
    }


def metric_goal(metric: str, template: dict[str, Any] | None = None) -> str:
    tpl = template or load_domain_template("")
    mapping = tpl.get("metric_to_goal") if isinstance(tpl.get("metric_to_goal"), dict) else {}
    return str(mapping.get(str(metric or "").strip().lower(), "unknown"))


def domain_goal_metric_sets(path: str = "") -> dict[str, set[str]]:
    tpl = load_domain_template(path)
    groups = tpl.get("metrics", {}).get("goal_metric_groups", {}) if isinstance(tpl.get("metrics"), dict) else {}
    out: dict[str, set[str]] = {}
    if isinstance(groups, dict):
        for goal_id, values in groups.items():
            key = _as_goal_id(goal_id)
            if not key:
                continue
            out[key] = {str(x).strip().lower() for x in _as_list_of_str(values)}
    return out


def domain_target_metric_to_primary_metric(path: str = "") -> dict[str, str]:
    tpl = load_domain_template(path)
    mapping = tpl.get("target_metric_to_primary_metric") if isinstance(tpl.get("target_metric_to_primary_metric"), dict) else {}
    return {str(k): str(v) for k, v in mapping.items() if str(k).strip() and str(v).strip()}


def domain_goal_default_metrics(path: str = "") -> dict[str, str]:
    tpl = load_domain_template(path)
    out: dict[str, str] = {}
    goals = tpl.get("goals") if isinstance(tpl.get("goals"), list) else []
    for row in goals:
        if not isinstance(row, dict):
            continue
        goal_id = _as_goal_id(row.get("goal_id"))
        default_primary = str(row.get("default_primary_metric", "")).strip()
        if goal_id and default_primary:
            out[goal_id] = default_primary
    return out


def domain_goal_definitions(path: str = "") -> list[dict[str, Any]]:
    tpl = load_domain_template(path)
    goals = tpl.get("goals") if isinstance(tpl.get("goals"), list) else []
    out: list[dict[str, Any]] = []
    for row in goals:
        if not isinstance(row, dict):
            continue
        goal_id = _as_goal_id(row.get("goal_id"))
        default_metric = str(row.get("commander_default_metric", "")).strip()
        primary_metric = str(row.get("default_primary_metric", "")).strip()
        target_alias = str(row.get("target_metric", "")).strip()
        if not goal_id or not default_metric:
            continue
        out.append(
            {
                "goal_id": goal_id,
                "default_metric": default_metric,
                "primary_metric": primary_metric,
                "target_metric_alias": target_alias,
                "risk_note": str(row.get("risk_note", "")).strip(),
                "expected_direction": str(row.get("expected_direction", "")).strip().lower(),
            }
        )
    return out


def domain_target_metric_alias_to_goal(path: str = "") -> dict[str, str]:
    tpl = load_domain_template(path)
    goals = tpl.get("goals") if isinstance(tpl.get("goals"), list) else []
    out: dict[str, str] = {}
    for row in goals:
        if not isinstance(row, dict):
            continue
        alias = str(row.get("target_metric", "")).strip()
        goal_id = _as_goal_id(row.get("goal_id"))
        if alias and goal_id:
            out[alias] = goal_id
    return out


def domain_target_metric_aliases(path: str = "") -> set[str]:
    return set(domain_target_metric_alias_to_goal(path).keys())


def domain_goal_expected_direction(path: str = "") -> dict[str, str]:
    tpl = load_domain_template(path)
    goals = tpl.get("goals") if isinstance(tpl.get("goals"), list) else []
    out: dict[str, str] = {}
    for row in goals:
        if not isinstance(row, dict):
            continue
        goal_id = _as_goal_id(row.get("goal_id"))
        direction = str(row.get("expected_direction", "")).strip().lower()
        if goal_id and direction in {"increase", "decrease"}:
            out[goal_id] = direction
    return out


def domain_signal_metric_to_target_metric(path: str = "") -> dict[str, str]:
    tpl = load_domain_template(path)
    alias_by_goal = {v: k for k, v in domain_target_metric_alias_to_goal(path).items()}
    metric_to_goal_map = tpl.get("metric_to_goal") if isinstance(tpl.get("metric_to_goal"), dict) else {}
    out: dict[str, str] = {}
    for metric, goal_id in metric_to_goal_map.items():
        alias = alias_by_goal.get(_as_goal_id(goal_id))
        if alias:
            out[str(metric)] = alias
    return out


def domain_thresholds_for(component: str, path: str = "") -> dict[str, Any]:
    tpl = load_domain_template(path)
    component_norm = str(component or "").strip().lower()
    doctor = tpl.get("doctor") if isinstance(tpl.get("doctor"), dict) else {}
    if component_norm in {"doctor", "doctor_variance"}:
        thresholds = doctor.get("thresholds") if isinstance(doctor.get("thresholds"), dict) else {}
        return dict(thresholds)
    return {}


def domain_guardrails_for(component: str, path: str = "") -> list[dict[str, Any]]:
    tpl = load_domain_template(path)
    component_norm = str(component or "").strip()

    by_component = tpl.get("guardrails_by_component") if isinstance(tpl.get("guardrails_by_component"), dict) else {}
    rows = by_component.get(component_norm)
    if not isinstance(rows, list):
        rows = tpl.get("guardrails") if isinstance(tpl.get("guardrails"), list) else []

    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        metric = str(row.get("metric", "")).strip()
        op = str(row.get("op", "")).strip()
        if not metric or op not in {">=", "<=", ">", "<"}:
            continue
        threshold = row.get("threshold")
        norm = {"metric": metric, "op": op, "threshold": threshold}
        if row.get("dynamic_baseline_ratio") is not None:
            norm["dynamic_baseline_ratio"] = row.get("dynamic_baseline_ratio")
        out.append(norm)
    return out


def domain_data_mapping_rules(path: str = "") -> dict[str, Any]:
    tpl = load_domain_template(path)
    rules = tpl.get("data_mapping_rules")
    return dict(rules) if isinstance(rules, dict) else {}
