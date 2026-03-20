from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar

_DEFAULT_RUNTIME_LIMITS_PATH = Path("configs/contracts/runtime_limits_v1.json")
_DEFAULT_FEATURE_STATE_PATH = Path("configs/contracts/feature_state_v1.json")
_DEFAULT_RETRY_POLICY_PATH = Path("configs/contracts/retry_policy_v1.json")
_DEFAULT_TOPIC_REGISTRY_PATH = Path("configs/contracts/event_bus/topic_registry_v2.json")
_EVENT_BUS_SCHEMA_DIR = Path("configs/contracts/event_bus")
_RUNTIME_GUARD_DIR = Path("data/runtime_guard")

_WEAK_RECON_TOPICS = {
    "ai.reasoning.weak_path_detected.v1": "weak_reasoning_result",
    "ai.reconciliation.requested.v1": "reconciliation_request",
    "ai.reconciliation.completed.v1": "reconciliation_result",
    "ai.reconciliation.recommended_override.v1": "recommended_override",
}

_REQUIRED_TOPIC_SCHEMAS = {
    "ai.reasoning.weak_path_detected.v1": "weak_reasoning_result_v1.json",
    "ai.reconciliation.requested.v1": "reconciliation_request_v1.json",
    "ai.reconciliation.completed.v1": "reconciliation_result_v1.json",
    "ai.reconciliation.recommended_override.v1": "recommended_override_v1.json",
}

_INLINE_PAYLOAD_FORBIDDEN_KEYS = {
    "payload_inline",
    "inline_payload",
    "payload_data",
    "payload_json",
    "payload_blob",
    "payload_bytes_inline",
}


def _to_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except Exception:
        return None


def _parse_iso_ts(raw: Any) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_integrity_checked_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing_contract_file:{path}")
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        raise RuntimeError(f"contract_integrity_error:{reason}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise RuntimeError(f"invalid_contract_json:{path}")
    if not isinstance(payload, dict):
        raise RuntimeError(f"invalid_contract_schema:{path}")
    return payload


def _positive_int(value: Any, *, name: str) -> int:
    try:
        out = int(value)
    except Exception:
        raise RuntimeError(f"invalid_runtime_limit:{name}")
    if out <= 0:
        raise RuntimeError(f"invalid_runtime_limit:{name}")
    return out


def _load_jsonschema_validator() -> Callable[..., None]:
    try:
        from jsonschema import validate as _validate  # type: ignore
    except Exception:
        raise RuntimeError("schema_validation_error:jsonschema_dependency_missing")
    return _validate


def load_runtime_limits_contract(path: str = "") -> dict[str, Any]:
    payload = _load_integrity_checked_json(Path(path) if str(path).strip() else _DEFAULT_RUNTIME_LIMITS_PATH)
    limits = payload.get("limits") if isinstance(payload.get("limits"), dict) else {}
    concurrency = _positive_int(limits.get("concurrency"), name="concurrency")
    max_batch_size = _positive_int(limits.get("max_batch_size"), name="max_batch_size")
    max_payload_bytes = _positive_int(limits.get("max_payload_bytes"), name="max_payload_bytes")
    max_reconcile_attempts = _positive_int(limits.get("max_reconcile_attempts"), name="max_reconcile_attempts")
    reconciliation_ttl_hours = _positive_int(limits.get("reconciliation_ttl_hours"), name="reconciliation_ttl_hours")
    chunk_ref_required = _to_bool(limits.get("chunk_ref_required"), default=False)
    runtime_guard_report_required = _to_bool(limits.get("runtime_guard_report_required"), default=False)
    backoff_schedule_raw = limits.get("backoff_schedule")
    if not isinstance(backoff_schedule_raw, list) or not backoff_schedule_raw:
        raise RuntimeError("invalid_runtime_limit:backoff_schedule")
    backoff_schedule: list[int] = []
    for idx, raw in enumerate(backoff_schedule_raw, start=1):
        try:
            val = int(raw)
        except Exception:
            raise RuntimeError(f"invalid_runtime_limit:backoff_schedule_{idx}")
        if val < 0:
            raise RuntimeError(f"invalid_runtime_limit:backoff_schedule_{idx}")
        backoff_schedule.append(val)

    sla_mode = str(limits.get("sla_mode", "")).strip().lower()
    if sla_mode != "batch_nightly":
        raise RuntimeError("invalid_runtime_limit:sla_mode")
    if concurrency != 1:
        raise RuntimeError("invalid_runtime_limit:concurrency_must_be_1")
    if not chunk_ref_required:
        raise RuntimeError("invalid_runtime_limit:chunk_ref_required_must_be_true")
    if not runtime_guard_report_required:
        raise RuntimeError("invalid_runtime_limit:runtime_guard_report_required_must_be_true")
    # OOM headroom guard: control-payload only.
    if max_payload_bytes > 16 * 1024 * 1024:
        raise RuntimeError("invalid_runtime_limit:max_payload_bytes_too_large")

    return {
        "version": str(payload.get("version", "runtime_limits_v1")),
        "concurrency": concurrency,
        "max_batch_size": max_batch_size,
        "max_payload_bytes": max_payload_bytes,
        "chunk_ref_required": chunk_ref_required,
        "max_reconcile_attempts": max_reconcile_attempts,
        "backoff_schedule": backoff_schedule,
        "reconciliation_ttl_hours": reconciliation_ttl_hours,
        "sla_mode": sla_mode,
        "runtime_guard_report_required": runtime_guard_report_required,
    }


def load_feature_state_contract(path: str = "") -> dict[str, Any]:
    payload = _load_integrity_checked_json(Path(path) if str(path).strip() else _DEFAULT_FEATURE_STATE_PATH)
    state = payload.get("state") if isinstance(payload.get("state"), dict) else {}
    weak_path_runtime = str(state.get("weak_path_runtime", "")).strip().upper()
    reconciliation_runtime = str(state.get("reconciliation_runtime", "")).strip().upper()
    auto_decision_change = str(state.get("auto_decision_change", "")).strip().upper()
    default_weak_path_ceiling = str(state.get("default_weak_path_ceiling", "")).strip().upper()
    if weak_path_runtime != "DISABLED":
        raise RuntimeError("invalid_feature_state:weak_path_runtime")
    if reconciliation_runtime != "NOT_IMPLEMENTED":
        raise RuntimeError("invalid_feature_state:reconciliation_runtime")
    if auto_decision_change != "FORBIDDEN":
        raise RuntimeError("invalid_feature_state:auto_decision_change")
    if default_weak_path_ceiling != "HOLD_NEED_DATA":
        raise RuntimeError("invalid_feature_state:default_weak_path_ceiling")
    return {
        "version": str(payload.get("version", "feature_state_v1")),
        "weak_path_runtime": weak_path_runtime,
        "reconciliation_runtime": reconciliation_runtime,
        "auto_decision_change": auto_decision_change,
        "default_weak_path_ceiling": default_weak_path_ceiling,
    }


def load_retry_policy_contract(path: str = "") -> dict[str, Any]:
    payload = _load_integrity_checked_json(Path(path) if str(path).strip() else _DEFAULT_RETRY_POLICY_PATH)
    policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
    global_budget = policy.get("global_budget") if isinstance(policy.get("global_budget"), dict) else {}
    on_exceed = policy.get("on_exceed") if isinstance(policy.get("on_exceed"), dict) else {}

    max_llm_calls_per_run = _positive_int(global_budget.get("max_llm_calls_per_run"), name="max_llm_calls_per_run")
    max_llm_failures_per_run = _positive_int(global_budget.get("max_llm_failures_per_run"), name="max_llm_failures_per_run")
    max_consecutive_failures = _positive_int(
        global_budget.get("max_consecutive_failures_before_open_circuit"),
        name="max_consecutive_failures_before_open_circuit",
    )
    circuit_cooldown_seconds = _positive_int(global_budget.get("circuit_cooldown_seconds"), name="circuit_cooldown_seconds")

    safe_decision = str(on_exceed.get("safe_decision", "")).strip().upper()
    stop_pipeline = _to_bool(on_exceed.get("stop_pipeline"), default=True)
    if safe_decision != "HOLD_NEED_DATA":
        raise RuntimeError("invalid_retry_policy:safe_decision")
    if not stop_pipeline:
        raise RuntimeError("invalid_retry_policy:stop_pipeline_must_be_true")

    return {
        "version": str(payload.get("version", "retry_policy_v1")),
        "max_llm_calls_per_run": max_llm_calls_per_run,
        "max_llm_failures_per_run": max_llm_failures_per_run,
        "max_consecutive_failures_before_open_circuit": max_consecutive_failures,
        "circuit_cooldown_seconds": circuit_cooldown_seconds,
        "safe_decision": safe_decision,
        "stop_pipeline": stop_pipeline,
    }


def _load_topic_registry_map() -> dict[str, str]:
    payload = _load_integrity_checked_json(_DEFAULT_TOPIC_REGISTRY_PATH)
    topics = payload.get("topics") if isinstance(payload.get("topics"), list) else []
    topic_map: dict[str, str] = {}
    for row in topics:
        if not isinstance(row, dict):
            continue
        topic = str(row.get("topic", "")).strip()
        schema = str(row.get("schema", "")).strip()
        if topic and schema:
            topic_map[topic] = schema
    for topic, expected_schema in _REQUIRED_TOPIC_SCHEMAS.items():
        actual = topic_map.get(topic, "")
        if actual != expected_schema:
            raise RuntimeError(f"schema_registry_mismatch:{topic}")
    return topic_map


def _load_schema_for_topic(topic: str, topic_map: dict[str, str]) -> dict[str, Any]:
    schema_rel = str(topic_map.get(topic, "")).strip()
    if not schema_rel:
        raise RuntimeError(f"schema_validation_error:missing_registry_schema:{topic}")
    path = (_EVENT_BUS_SCHEMA_DIR / schema_rel).resolve()
    return _load_integrity_checked_json(path)


def _classify_weak_reconciliation_event(topic: str) -> str:
    return _WEAK_RECON_TOPICS.get(topic, "")


def _extract_run_events_from_payload(payload: Any, run_id: str, source_path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def _register(topic_hint: str, raw_obj: Any) -> None:
        if not isinstance(raw_obj, dict):
            return
        topic = str(raw_obj.get("topic", "") or topic_hint).strip()
        if topic not in _WEAK_RECON_TOPICS:
            return
        payload_obj = raw_obj.get("payload") if isinstance(raw_obj.get("payload"), dict) else raw_obj
        if not isinstance(payload_obj, dict):
            return
        if str(payload_obj.get("run_id", "")).strip() != run_id:
            return
        row = dict(payload_obj)
        # carry event-level ids if available
        if "event_id" not in row and raw_obj.get("event_id") is not None:
            row["event_id"] = raw_obj.get("event_id")
        row["__topic"] = topic
        row["__kind"] = _classify_weak_reconciliation_event(topic)
        row["__source_path"] = source_path
        rows.append(row)

    if isinstance(payload, dict):
        _register(str(payload.get("topic", "")).strip(), payload)
        for key in ("events", "items", "records"):
            arr = payload.get(key)
            if isinstance(arr, list):
                for item in arr:
                    _register(str(payload.get("topic", "")).strip(), item)
    elif isinstance(payload, list):
        for item in payload:
            _register("", item)

    return rows


def collect_weak_reconciliation_events(run_id: str, event_bus_root: Path | None = None) -> list[dict[str, Any]]:
    root = event_bus_root or Path("data/event_bus")
    if not root.exists():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows.extend(_extract_run_events_from_payload(payload, run_id, path.as_posix()))
    return rows


def runtime_guard_report_path(run_id: str) -> Path:
    return _RUNTIME_GUARD_DIR / f"{run_id}_runtime_guard.json"


def retry_state_path(run_id: str) -> Path:
    return _RUNTIME_GUARD_DIR / f"{run_id}_retry_state.json"


def retry_guard_report_path(run_id: str) -> Path:
    return _RUNTIME_GUARD_DIR / f"{run_id}_retry_guard.json"


def _write_json_with_sidecar(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(path)


def _default_retry_state(run_id: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "llm_calls": 0,
        "llm_failures": 0,
        "consecutive_failures": 0,
        "circuit_open_until": "",
        "last_failure_reason": "",
        "updated_at": _now_utc_iso(),
    }


def _retry_state_integrity_required() -> bool:
    if str(os.getenv("DS_STRICT_RUNTIME", "0")).strip() == "1":
        return True
    profile = str(os.getenv("DS_SECURITY_PROFILE", "")).strip().lower()
    return profile in {"production", "prod"}


def _load_retry_state(run_id: str, *, integrity_required: bool | None = None) -> dict[str, Any]:
    required = _retry_state_integrity_required() if integrity_required is None else bool(integrity_required)
    path = retry_state_path(run_id)
    if not path.exists():
        return _default_retry_state(run_id)
    ok, reason = verify_sha256_sidecar(path, required=required)
    if not ok:
        raise RuntimeError(f"retry_state_integrity_error:{reason}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        if required:
            raise RuntimeError("retry_state_integrity_error:invalid_retry_state_json")
        return _default_retry_state(run_id)
    if not isinstance(payload, dict):
        if required:
            raise RuntimeError("retry_state_integrity_error:invalid_retry_state_schema")
        return _default_retry_state(run_id)
    state = _default_retry_state(run_id)
    state.update(payload)
    state["run_id"] = run_id
    return state


def _save_retry_state(run_id: str, state: dict[str, Any]) -> dict[str, Any]:
    safe = _default_retry_state(run_id)
    safe.update(state)
    safe["run_id"] = run_id
    safe["updated_at"] = _now_utc_iso()
    _write_json_with_sidecar(retry_state_path(run_id), safe)
    return safe


def get_retry_budget_status(run_id: str, retry_policy: dict[str, Any], *, now_utc: datetime | None = None) -> dict[str, Any]:
    now = now_utc or datetime.now(timezone.utc)
    try:
        state = _load_retry_state(run_id)
    except RuntimeError as exc:
        reason_code = str(exc) or "retry_state_integrity_error"
        return {
            "allowed": False,
            "reason": "retry_state_integrity_error",
            "reason_code": reason_code,
            "safe_decision": retry_policy.get("safe_decision", "HOLD_NEED_DATA"),
            "state": _default_retry_state(run_id),
        }

    open_until = _parse_iso_ts(state.get("circuit_open_until"))
    if open_until is not None and now < open_until:
        return {
            "allowed": False,
            "reason": "circuit_breaker_open",
            "safe_decision": retry_policy.get("safe_decision", "HOLD_NEED_DATA"),
            "state": state,
        }

    if int(state.get("llm_calls", 0) or 0) >= int(retry_policy.get("max_llm_calls_per_run", 1) or 1):
        return {
            "allowed": False,
            "reason": "retry_budget_exceeded",
            "safe_decision": retry_policy.get("safe_decision", "HOLD_NEED_DATA"),
            "state": state,
        }

    if int(state.get("llm_failures", 0) or 0) >= int(retry_policy.get("max_llm_failures_per_run", 1) or 1):
        return {
            "allowed": False,
            "reason": "retry_failure_budget_exceeded",
            "safe_decision": retry_policy.get("safe_decision", "HOLD_NEED_DATA"),
            "state": state,
        }

    return {
        "allowed": True,
        "reason": "ok",
        "safe_decision": retry_policy.get("safe_decision", "HOLD_NEED_DATA"),
        "state": state,
    }


def register_retry_outcome(
    run_id: str,
    retry_policy: dict[str, Any],
    *,
    success: bool,
    failure_reason: str = "",
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    now = now_utc or datetime.now(timezone.utc)
    state = _load_retry_state(run_id)
    state["llm_calls"] = int(state.get("llm_calls", 0) or 0) + 1

    if success:
        state["consecutive_failures"] = 0
        state["last_failure_reason"] = ""
    else:
        state["llm_failures"] = int(state.get("llm_failures", 0) or 0) + 1
        state["consecutive_failures"] = int(state.get("consecutive_failures", 0) or 0) + 1
        state["last_failure_reason"] = str(failure_reason or "llm_call_failed")[:200]
        if int(state.get("consecutive_failures", 0) or 0) >= int(
            retry_policy.get("max_consecutive_failures_before_open_circuit", 1) or 1
        ):
            cooldown = int(retry_policy.get("circuit_cooldown_seconds", 1) or 1)
            state["circuit_open_until"] = (now + timedelta(seconds=cooldown)).isoformat()

    return _save_retry_state(run_id, state)


def write_retry_guard_report(run_id: str, *, status: str, reason: str, retry_policy: dict[str, Any], state: dict[str, Any]) -> Path:
    payload = {
        "run_id": run_id,
        "generated_at": _now_utc_iso(),
        "status": status,
        "reason_code": reason,
        "safe_decision": str(retry_policy.get("safe_decision", "HOLD_NEED_DATA") or "HOLD_NEED_DATA"),
        "policy_version": str(retry_policy.get("version", "retry_policy_v1")),
        "state": state,
    }
    path = retry_guard_report_path(run_id)
    _write_json_with_sidecar(path, payload)
    return path


def _schema_validate_events(
    events: list[dict[str, Any]],
    *,
    topic_map: dict[str, str],
    jsonschema_validate: Callable[..., None],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    schema_cache: dict[str, dict[str, Any]] = {}

    for row in events:
        topic = str(row.get("__topic", "")).strip()
        if topic not in _WEAK_RECON_TOPICS:
            continue
        try:
            schema = schema_cache.get(topic)
            if schema is None:
                schema = _load_schema_for_topic(topic, topic_map)
                schema_cache[topic] = schema
            payload = {k: v for k, v in row.items() if not str(k).startswith("__")}
            jsonschema_validate(instance=payload, schema=schema)
        except Exception as exc:
            issues.append(
                {
                    "reason": "schema_validation_error",
                    "topic": topic,
                    "source": row.get("__source_path"),
                    "error": str(exc).splitlines()[0][:240],
                }
            )
    return issues


def _build_guard_report_base(run_id: str, runtime_limits: dict[str, Any], feature_state: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "generated_at": _now_utc_iso(),
        "status": "PASS",
        "reason_code": "ok",
        "safe_decision_on_fail": "HOLD_NEED_DATA",
        "limits": runtime_limits,
        "feature_state": feature_state,
        "stages": [],
        "violations": [],
        "stats": {
            "events_total": 0,
            "weak_events": 0,
            "reconciliation_requests": 0,
            "reconciliation_results": 0,
            "recommended_overrides": 0,
        },
    }


def evaluate_runtime_guard(
    run_id: str,
    runtime_limits: dict[str, Any],
    feature_state: dict[str, Any],
    *,
    event_bus_root: Path | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    now = now_utc or datetime.now(timezone.utc)
    report = _build_guard_report_base(run_id, runtime_limits, feature_state)

    def _pass_stage(stage: str, details: dict[str, Any]) -> None:
        report["stages"].append({"stage": stage, "status": "PASS", "details": details})

    def _fail_stage(stage: str, reason_code: str, details: dict[str, Any]) -> dict[str, Any]:
        report["status"] = "FAIL"
        report["reason_code"] = reason_code
        report["stages"].append({"stage": stage, "status": "FAIL", "details": details})
        report["violations"].append({"stage": stage, "reason": reason_code, **details})
        return report

    # 1) integrity
    try:
        topic_map = _load_topic_registry_map()
        jsonschema_validate = _load_jsonschema_validator()
        # Pre-load required schemas with integrity check.
        for topic in _REQUIRED_TOPIC_SCHEMAS:
            _load_schema_for_topic(topic, topic_map)
    except Exception as exc:
        return _fail_stage(
            "integrity",
            "runtime_guard_integrity_error",
            {"error": str(exc).splitlines()[0][:240]},
        )
    _pass_stage("integrity", {"required_topics": sorted(_REQUIRED_TOPIC_SCHEMAS.keys())})

    events = collect_weak_reconciliation_events(run_id, event_bus_root=event_bus_root)
    weak_events = [e for e in events if e.get("__kind") == "weak_reasoning_result"]
    reconciliation_requests = [e for e in events if e.get("__kind") == "reconciliation_request"]
    reconciliation_results = [e for e in events if e.get("__kind") == "reconciliation_result"]
    recommended_overrides = [e for e in events if e.get("__kind") == "recommended_override"]
    report["stats"] = {
        "events_total": len(events),
        "weak_events": len(weak_events),
        "reconciliation_requests": len(reconciliation_requests),
        "reconciliation_results": len(reconciliation_results),
        "recommended_overrides": len(recommended_overrides),
    }

    # 2) schema
    schema_issues = _schema_validate_events(events, topic_map=topic_map, jsonschema_validate=jsonschema_validate)
    if schema_issues:
        return _fail_stage(
            "schema",
            "schema_validation_error",
            {"issues": schema_issues[:5], "count": len(schema_issues)},
        )
    _pass_stage("schema", {"validated_events": len(events)})

    # 3) feature_state
    weak_disabled = str(feature_state.get("weak_path_runtime", "")).upper() == "DISABLED"
    reconciliation_disabled = str(feature_state.get("reconciliation_runtime", "")).upper() == "NOT_IMPLEMENTED"
    if events and (weak_disabled or reconciliation_disabled):
        return _fail_stage(
            "feature_state",
            "feature_state_disabled_runtime_event_detected",
            {
                "events_total": len(events),
                "weak_path_runtime": feature_state.get("weak_path_runtime"),
                "reconciliation_runtime": feature_state.get("reconciliation_runtime"),
            },
        )
    _pass_stage("feature_state", {"events_total": len(events)})

    # 4) payload/memory
    max_payload_bytes_contract = int(runtime_limits.get("max_payload_bytes", 0) or 0)
    max_batch_size_contract = int(runtime_limits.get("max_batch_size", 0) or 0)
    contract_concurrency = int(runtime_limits.get("concurrency", 1) or 1)
    payload_violations: list[dict[str, Any]] = []
    for row in reconciliation_requests:
        payload_ref = str(row.get("payload_ref", "")).strip()
        if not payload_ref:
            payload_violations.append({"reason": "payload_ref_missing", "source": row.get("__source_path")})

        if not _to_bool(row.get("chunk_ref_required")):
            payload_violations.append({
                "reason": "chunk_ref_required_must_be_true",
                "source": row.get("__source_path"),
            })

        for key in _INLINE_PAYLOAD_FORBIDDEN_KEYS:
            if key in row and row.get(key) not in (None, "", [], {}):
                payload_violations.append(
                    {
                        "reason": "inline_payload_forbidden",
                        "key": key,
                        "source": row.get("__source_path"),
                    }
                )

        payload_size = _to_int(row.get("max_payload_bytes"))
        if payload_size is not None and max_payload_bytes_contract > 0 and payload_size > max_payload_bytes_contract:
            payload_violations.append(
                {
                    "reason": "payload_exceeds_contract_limit",
                    "max_payload_bytes": payload_size,
                    "contract_max_payload_bytes": max_payload_bytes_contract,
                    "source": row.get("__source_path"),
                }
            )

        batch_size = _to_int(row.get("batch_size"))
        if batch_size is not None and max_batch_size_contract > 0 and batch_size > max_batch_size_contract:
            payload_violations.append(
                {
                    "reason": "batch_size_exceeds_contract",
                    "batch_size": batch_size,
                    "contract_max_batch_size": max_batch_size_contract,
                    "source": row.get("__source_path"),
                }
            )

        row_concurrency = _to_int(row.get("concurrency"))
        if row_concurrency is not None and row_concurrency > contract_concurrency:
            payload_violations.append(
                {
                    "reason": "concurrency_exceeds_contract",
                    "concurrency": row_concurrency,
                    "contract_concurrency": contract_concurrency,
                    "source": row.get("__source_path"),
                }
            )

    if payload_violations:
        return _fail_stage(
            "payload_memory",
            "payload_policy_violation",
            {"issues": payload_violations[:5], "count": len(payload_violations)},
        )
    _pass_stage("payload_memory", {"checked_requests": len(reconciliation_requests)})

    # 5) loop/dedup
    loop_violations: list[dict[str, Any]] = []
    max_attempts_contract = int(runtime_limits.get("max_reconcile_attempts", 1) or 1)
    loop_guard_counts: dict[str, int] = {}
    recon_events = [*reconciliation_requests, *reconciliation_results]
    reconciliation_ids = {
        str(e.get("reconciliation_id", "")).strip()
        for e in [*reconciliation_requests, *reconciliation_results, *recommended_overrides]
        if str(e.get("reconciliation_id", "")).strip()
    }
    for event in recon_events:
        attempt_no = _to_int(event.get("attempt_no"))
        max_attempts = _to_int(event.get("max_attempts"))
        if attempt_no is not None and max_attempts is not None and attempt_no > max_attempts:
            loop_violations.append(
                {
                    "reason": "attempt_exceeds_event_max_attempts",
                    "attempt_no": attempt_no,
                    "max_attempts": max_attempts,
                    "source": event.get("__source_path"),
                }
            )
        if attempt_no is not None and attempt_no > max_attempts_contract:
            loop_violations.append(
                {
                    "reason": "attempt_exceeds_contract_max_attempts",
                    "attempt_no": attempt_no,
                    "contract_max_attempts": max_attempts_contract,
                    "source": event.get("__source_path"),
                }
            )

        loop_guard_key = str(event.get("loop_guard_key", "")).strip()
        if loop_guard_key:
            loop_guard_counts[loop_guard_key] = int(loop_guard_counts.get(loop_guard_key, 0) or 0) + 1

        source_event_id = str(event.get("source_event_id", "")).strip()
        event_id = str(event.get("event_id", "")).strip()
        reconciliation_id = str(event.get("reconciliation_id", "")).strip()
        if source_event_id and source_event_id in reconciliation_ids:
            loop_violations.append(
                {
                    "reason": "cyclic_source_event_id",
                    "source_event_id": source_event_id,
                    "reconciliation_id": reconciliation_id,
                    "source": event.get("__source_path"),
                }
            )
        if source_event_id and event_id and source_event_id == event_id:
            loop_violations.append(
                {
                    "reason": "self_enqueue_detected",
                    "event_id": event_id,
                    "source": event.get("__source_path"),
                }
            )
        if source_event_id and reconciliation_id and source_event_id == reconciliation_id:
            loop_violations.append(
                {
                    "reason": "source_event_equals_reconciliation_id",
                    "source_event_id": source_event_id,
                    "reconciliation_id": reconciliation_id,
                    "source": event.get("__source_path"),
                }
            )

    for key, cnt in loop_guard_counts.items():
        if cnt > 1:
            loop_violations.append({"reason": "duplicate_loop_guard_key", "loop_guard_key": key, "count": cnt})

    weak_ceiling = str(feature_state.get("default_weak_path_ceiling", "HOLD_NEED_DATA")).upper() or "HOLD_NEED_DATA"
    for row in weak_events:
        if str(row.get("decision_ceiling_applied", "")).upper() != weak_ceiling:
            loop_violations.append(
                {
                    "reason": "weak_path_without_required_ceiling",
                    "source_event_id": row.get("source_event_id"),
                    "source": row.get("__source_path"),
                }
            )
        if _to_bool(row.get("auto_decision_change_applied")):
            loop_violations.append(
                {
                    "reason": "auto_decision_change_detected",
                    "source_event_id": row.get("source_event_id"),
                    "source": row.get("__source_path"),
                }
            )

    for row in recommended_overrides:
        if not _to_bool(row.get("human_approval_required")):
            loop_violations.append(
                {
                    "reason": "recommended_override_requires_human_approval",
                    "reconciliation_id": row.get("reconciliation_id"),
                    "source": row.get("__source_path"),
                }
            )

    terminal_statuses = {"COMPLETED", "EXPIRED", "FAILED"}
    ttl_hours = int(runtime_limits.get("reconciliation_ttl_hours", 24) or 24)
    result_by_source: dict[str, list[dict[str, Any]]] = {}
    for row in reconciliation_results:
        source = str(row.get("source_event_id", "")).strip()
        if source:
            result_by_source.setdefault(source, []).append(row)
    for weak in weak_events:
        weak_status = str(weak.get("reconciliation_status", "")).upper()
        if weak_status in terminal_statuses:
            continue
        source_event_id = str(weak.get("source_event_id", "")).strip()
        matched_results = result_by_source.get(source_event_id, [])
        latest_status = ""
        latest_ts: datetime | None = None
        for res in matched_results:
            ts = _parse_iso_ts(res.get("completed_at"))
            if ts and (latest_ts is None or ts > latest_ts):
                latest_ts = ts
                latest_status = str(res.get("reconciliation_status", "")).upper()
        if latest_status in terminal_statuses:
            continue
        weak_ts = _parse_iso_ts(weak.get("occurred_at"))
        if weak_ts is None:
            loop_violations.append(
                {
                    "reason": "weak_occurred_at_missing_or_invalid",
                    "source_event_id": source_event_id,
                    "source": weak.get("__source_path"),
                }
            )
            continue
        age_hours = (now - weak_ts).total_seconds() / 3600.0
        if age_hours > float(ttl_hours):
            loop_violations.append(
                {
                    "reason": "reconciliation_stale",
                    "source_event_id": source_event_id,
                    "age_hours": round(age_hours, 2),
                    "ttl_hours": ttl_hours,
                    "source": weak.get("__source_path"),
                }
            )

    if loop_violations:
        return _fail_stage(
            "loop_dedup",
            "loop_or_dedup_violation",
            {"issues": loop_violations[:5], "count": len(loop_violations)},
        )
    _pass_stage("loop_dedup", {"checked_events": len(recon_events)})

    # 6) execution gate is open only after all checks above.
    _pass_stage("execution", {"admission": "granted"})
    return report


def enforce_runtime_limits_for_run(
    run_id: str,
    runtime_limits: dict[str, Any],
    feature_state: dict[str, Any],
    *,
    event_bus_root: Path | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    report = evaluate_runtime_guard(
        run_id,
        runtime_limits,
        feature_state,
        event_bus_root=event_bus_root,
        now_utc=now_utc,
    )
    _write_json_with_sidecar(runtime_guard_report_path(run_id), report)
    if str(report.get("status", "PASS")).upper() != "PASS":
        raise RuntimeError(str(report.get("reason_code", "runtime_guard_failed")))
    return dict(report.get("stats") if isinstance(report.get("stats"), dict) else {})
