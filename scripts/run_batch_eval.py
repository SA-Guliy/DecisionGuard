#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.generate_synthetic_history import build_batch_eval_cases
from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar

try:
    from src.architecture_v3 import FPR_CALIBRATION_POLICY_PATH as _ARCH_FPR_CALIBRATION_POLICY_PATH
    from src.architecture_v3 import load_json_with_integrity
except Exception:
    _ARCH_FPR_CALIBRATION_POLICY_PATH = ROOT / "configs/contracts/fpr_calibration_policy_v1.json"

    def load_json_with_integrity(path: Path) -> dict[str, Any]:
        ok, reason = verify_sha256_sidecar(path, required=True)
        if not ok:
            raise RuntimeError(f"missing_contract_or_artifact:{path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError(f"invalid_contract_payload:{path}")
        return payload

try:
    from src.batch_summary_freshness import compute_records_quality_complete
except Exception:
    def compute_records_quality_complete(records: list[Any]) -> bool:
        return isinstance(records, list)

try:
    from src.model_policy import (
        COMMANDER_GROQ_REASONING_CHAIN,
        DOCTOR_GROQ_REASONING_CHAIN,
        is_reasoning_model,
        model_class_for,
        normalize_reasoning_chain,
    )
except Exception:
    DOCTOR_GROQ_REASONING_CHAIN = (
        "llama-3.3-70b-versatile",
        "openai/gpt-oss-120b",
        "qwen/qwen3-32b",
    )
    COMMANDER_GROQ_REASONING_CHAIN = (
        "openai/gpt-oss-120b",
        "llama-3.3-70b-versatile",
        "qwen/qwen3-32b",
    )

    def model_class_for(model_name: str | None) -> str:
        return "reasoning" if str(model_name or "").strip() else "unknown"

    def is_reasoning_model(model_name: str | None) -> bool:
        return bool(str(model_name or "").strip())

    def normalize_reasoning_chain(
        models: list[str] | tuple[str, ...],
        *,
        blocked_models: set[str] | None = None,
    ) -> tuple[str, ...]:
        blocked = {str(x).strip() for x in (blocked_models or set()) if str(x).strip()}
        out: list[str] = []
        seen: set[str] = set()
        for raw in models:
            model = str(raw or "").strip()
            if not model or model in seen or model in blocked:
                continue
            if not is_reasoning_model(model):
                continue
            out.append(model)
            seen.add(model)
        return tuple(out)

FPR_CALIBRATION_POLICY_PATH = Path(_ARCH_FPR_CALIBRATION_POLICY_PATH)


TRANSPORT_POLICY_PATH = ROOT / "configs/contracts/batch_record_transport_policy_v2.json"
BATCH_RECORD_CONTRACT_PATH = ROOT / "configs/contracts/batch_record_v2.json"
BATCH_SUMMARY_CONTRACT_PATH = ROOT / "configs/contracts/batch_summary_v2.json"
FPR_REMEDIATION_POLICY_PATH = ROOT / "configs/contracts/fpr_remediation_policy_v1.json"
REASONING_QUALITY_POLICY_V2_PATH = ROOT / "configs/contracts/reasoning_quality_policy_v2.json"
GROQ_CHAT_COMPLETIONS_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
_TYPE_MAP: dict[str, type] = {
    "str": str,
    "bool": bool,
    "int": int,
    "float": (int, float),
    "dict": dict,
    "list": list,
}


def _ensure_groq_secrets() -> Path:
    secrets_path = Path(os.path.expanduser("~/.groq_secrets"))
    if not secrets_path.exists() or not secrets_path.is_file():
        raise SystemExit("ConfigurationError: Missing ~/.groq_secrets")
    values = dotenv_values(secrets_path)
    key = str(values.get("GROQ_API_KEY", "")).strip()
    if not key:
        raise SystemExit("ConfigurationError: GROQ_API_KEY is missing in ~/.groq_secrets")
    if not (key.startswith("gsk_") and len(key) >= 20):
        raise SystemExit("ConfigurationError: Invalid GROQ_API_KEY format in ~/.groq_secrets")
    return secrets_path


def _load_groq_api_key_from_secrets(secrets_path: Path) -> str:
    values = dotenv_values(secrets_path)
    key = str(values.get("GROQ_API_KEY", "")).strip()
    if not key:
        raise RuntimeError(f"missing_groq_api_key:{secrets_path}")
    return key


def _cloud_preflight_artifact_path(batch_id: str) -> Path:
    return ROOT / f"data/agent_quality/{batch_id}_cloud_preflight.json"


def _attempt_summary_path(batch_id: str, attempt_index: int) -> Path:
    return ROOT / f"data/batch_eval/{batch_id}_summary.attempt_{int(attempt_index)}.json"


def _path_ref(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except Exception:
        return str(path)


def _run_release_candidate_cloud_preflight(
    *,
    batch_id: str,
    backend: str,
    secrets_path: Path,
    doctor_chain: tuple[str, ...],
    commander_chain: tuple[str, ...],
    timeout_sec: float = 20.0,
) -> tuple[dict[str, Any], Path]:
    now_iso = datetime.now(timezone.utc).isoformat()
    artifact_path = _cloud_preflight_artifact_path(batch_id)
    if str(backend).lower() != "groq":
        payload = {
            "version": "cloud_preflight_v1",
            "batch_id": str(batch_id),
            "backend": str(backend),
            "generated_at": now_iso,
            "status": "fail",
            "error_code": "RUNTIME_ENV_NETWORK_BLOCKED",
            "reason": "unsupported_backend_for_release_candidate_preflight",
            "checks": [],
            "roles": {
                "doctor_chain_pass": False,
                "commander_chain_pass": False,
            },
        }
        save_path = artifact_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(save_path)
        return payload, save_path

    api_key = _load_groq_api_key_from_secrets(secrets_path)
    doctor_models = normalize_reasoning_chain(doctor_chain, blocked_models=set())
    commander_models = normalize_reasoning_chain(commander_chain, blocked_models=set())
    models = sorted(set(doctor_models + commander_models))
    checks: list[dict[str, Any]] = []

    for model in models:
        row: dict[str, Any] = {
            "model": str(model),
            "http_status": None,
            "error_type": "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pass": False,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": str(model),
            "messages": [{"role": "user", "content": "cloud preflight"}],
            "temperature": 0,
            "max_tokens": 8,
        }
        try:
            resp = requests.post(
                GROQ_CHAT_COMPLETIONS_ENDPOINT,
                headers=headers,
                json=payload,
                timeout=timeout_sec,
            )
            row["http_status"] = int(resp.status_code)
            row["pass"] = int(resp.status_code) < 400
            if not row["pass"]:
                row["error_type"] = f"http_{int(resp.status_code)}"
        except requests.exceptions.RequestException as exc:
            row["error_type"] = type(exc).__name__
            row["pass"] = False
        except Exception as exc:
            row["error_type"] = type(exc).__name__
            row["pass"] = False
        checks.append(row)

    pass_by_model = {
        str(row.get("model", "")).strip(): bool(row.get("pass", False))
        for row in checks
        if str(row.get("model", "")).strip()
    }
    doctor_pass = any(pass_by_model.get(str(m), False) for m in doctor_models)
    commander_pass = any(pass_by_model.get(str(m), False) for m in commander_models)
    status = "pass" if (doctor_pass and commander_pass) else "fail"
    payload = {
        "version": "cloud_preflight_v1",
        "batch_id": str(batch_id),
        "backend": str(backend),
        "generated_at": now_iso,
        "status": status,
        "error_code": "" if status == "pass" else "RUNTIME_ENV_NETWORK_BLOCKED",
        "checks": checks,
        "roles": {
            "doctor_chain_pass": bool(doctor_pass),
            "commander_chain_pass": bool(commander_pass),
            "doctor_models_checked": doctor_models,
            "commander_models_checked": commander_models,
        },
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(artifact_path)
    return payload, artifact_path


def _is_rate_limit_error(text: str) -> bool:
    t = str(text or "").lower()
    return (" 429" in t) or ("too many requests" in t) or ("rate limit" in t)


_DEBUG_CLOUD_ERROR_RE = re.compile(r"\[DEBUG CLOUD ERROR\]\s+Model\s+(.+?)\s+failed:\s+(.+)$", re.IGNORECASE)


def _extract_rate_limited_models(log_text: str) -> set[str]:
    out: set[str] = set()
    for line in str(log_text or "").splitlines():
        m = _DEBUG_CLOUD_ERROR_RE.search(str(line).strip())
        if not m:
            continue
        model = str(m.group(1) or "").strip()
        reason = str(m.group(2) or "").strip()
        if model and _is_rate_limit_error(reason):
            out.add(model)
    return out


def _active_cooldown_blocklist(cooldowns: dict[str, float], now_ts: float) -> set[str]:
    return {
        str(model).strip()
        for model, until_ts in cooldowns.items()
        if str(model).strip() and float(until_ts or 0.0) > float(now_ts)
    }


def _resolve_reasoning_model_pair(
    *,
    chain: tuple[str, ...],
    blocked_models: set[str],
) -> tuple[str, str]:
    filtered = normalize_reasoning_chain(chain, blocked_models=blocked_models)
    if not filtered:
        raise RuntimeError("no_reasoning_model_available_after_cooldown")
    primary = filtered[0]
    fallback = filtered[1] if len(filtered) > 1 else filtered[0]
    return primary, fallback


def _release_candidate_non_reasoning_fallback(payload: dict[str, Any]) -> bool:
    for key in ("doctor_usage", "commander_usage"):
        node = payload.get(key)
        if not isinstance(node, dict):
            continue
        model = str(node.get("model", "")).strip()
        if not model:
            continue
        if not is_reasoning_model(model):
            return True
    return False


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _build_wave_fingerprint(args: argparse.Namespace) -> str:
    material = {
        "backend": str(args.backend),
        "dataset": str(args.dataset),
        "max_cases": int(args.max_cases),
        "top_k": int(args.top_k),
        "release_candidate": int(args.release_candidate),
        "require_cloud_path_min": int(args.require_cloud_path_min),
        "max_retries": int(args.max_retries),
        "backoff_base_seconds": float(args.backoff_base_seconds),
        "sleep_seconds": float(args.sleep_seconds),
        "scripts": {},
    }
    fingerprint_paths = [
        ROOT / "scripts/run_batch_eval.py",
        ROOT / "scripts/run_poc_e2e.py",
        FPR_REMEDIATION_POLICY_PATH,
        REASONING_QUALITY_POLICY_V2_PATH,
    ]
    for p in fingerprint_paths:
        if p.exists():
            material["scripts"][str(p.relative_to(ROOT))] = _sha256_file(p)
    raw = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _attempt_ledger_path(batch_id: str) -> Path:
    return ROOT / f"data/batch_eval/{batch_id}_run_attempts.json"


def _load_attempt_ledger(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": "wave_attempt_ledger_v1", "attempts": []}
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        raise SystemExit(f"RETRY_POLICY_BLOCKED:attempt_ledger_integrity:{reason}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"RETRY_POLICY_BLOCKED:attempt_ledger_invalid_json:{path}:{exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"RETRY_POLICY_BLOCKED:attempt_ledger_invalid_object:{path}")
    attempts = payload.get("attempts")
    if not isinstance(attempts, list):
        raise SystemExit(f"RETRY_POLICY_BLOCKED:attempt_ledger_attempts_not_list:{path}")
    return payload


def _write_attempt_ledger(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(path)


def _load_fpr_calibration_policy_block() -> dict[str, Any]:
    try:
        payload = load_json_with_integrity(FPR_CALIBRATION_POLICY_PATH)
    except Exception as exc:
        raise SystemExit(f"RETRY_POLICY_BLOCKED:calibration_policy_load_failed:{FPR_CALIBRATION_POLICY_PATH}:{exc}")
    policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
    if not isinstance(policy, dict):
        raise SystemExit(f"RETRY_POLICY_BLOCKED:calibration_policy_invalid:{FPR_CALIBRATION_POLICY_PATH}")
    return policy


def _count_cloud_api_calls(payload: dict[str, Any]) -> int:
    calls = 0
    for key in ("captain_usage", "doctor_usage", "commander_usage"):
        node = payload.get(key)
        if not isinstance(node, dict):
            continue
        if bool(node.get("cloud_path")) and int(node.get("total_tokens") or 0) > 0:
            calls += 1
    return calls


def _artifact_has_rate_limit_error(payload: dict[str, Any]) -> bool:
    flags = payload.get("runtime_flags") if isinstance(payload.get("runtime_flags"), dict) else {}
    notes = flags.get("cloud_failure_notes") if isinstance(flags.get("cloud_failure_notes"), list) else []
    if any(_is_rate_limit_error(str(x)) for x in notes):
        return True
    for key in ("captain_usage", "doctor_usage", "commander_usage"):
        node = payload.get(key)
        if not isinstance(node, dict):
            continue
        reason = str(node.get("reason") or node.get("backend_error") or "")
        if _is_rate_limit_error(reason):
            return True
    return False


def _resolve_limit_value(cli_value: int, policy_value: Any, default: int) -> int:
    if int(cli_value) >= 0:
        return int(cli_value)
    try:
        return int(policy_value)
    except Exception:
        return int(default)


def _load_transport_policy_contract() -> dict[str, Any]:
    if not TRANSPORT_POLICY_PATH.exists():
        raise SystemExit(f"Missing transport policy contract: {TRANSPORT_POLICY_PATH}")
    ok, reason = verify_sha256_sidecar(TRANSPORT_POLICY_PATH, required=True)
    if not ok:
        raise SystemExit(f"Transport policy integrity error: {reason}")
    try:
        payload = json.loads(TRANSPORT_POLICY_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Invalid transport policy JSON: {TRANSPORT_POLICY_PATH}: {exc}") from exc
    policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
    if not bool(policy.get("batch_record_out_required", False)):
        raise SystemExit("Transport policy violation: batch_record_out_required must be true")
    if not bool(policy.get("stdout_ingest_forbidden", False)):
        raise SystemExit("Transport policy violation: stdout_ingest_forbidden must be true")
    return payload


def _load_batch_record_contract() -> dict[str, Any]:
    if not BATCH_RECORD_CONTRACT_PATH.exists():
        raise SystemExit(f"Missing batch record contract: {BATCH_RECORD_CONTRACT_PATH}")
    ok, reason = verify_sha256_sidecar(BATCH_RECORD_CONTRACT_PATH, required=True)
    if not ok:
        raise SystemExit(f"Batch record contract integrity error: {reason}")
    try:
        payload = json.loads(BATCH_RECORD_CONTRACT_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Invalid batch record contract JSON: {BATCH_RECORD_CONTRACT_PATH}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid batch record contract payload: {BATCH_RECORD_CONTRACT_PATH}")
    return payload


def _load_batch_summary_contract() -> dict[str, Any]:
    if not BATCH_SUMMARY_CONTRACT_PATH.exists():
        raise SystemExit(f"Missing batch summary contract: {BATCH_SUMMARY_CONTRACT_PATH}")
    ok, reason = verify_sha256_sidecar(BATCH_SUMMARY_CONTRACT_PATH, required=True)
    if not ok:
        raise SystemExit(f"Batch summary contract integrity error: {reason}")
    try:
        payload = json.loads(BATCH_SUMMARY_CONTRACT_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Invalid batch summary contract JSON: {BATCH_SUMMARY_CONTRACT_PATH}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid batch summary contract payload: {BATCH_SUMMARY_CONTRACT_PATH}")
    return payload


def _get_path_value(payload: dict[str, Any], path: str) -> Any:
    cur: Any = payload
    for key in str(path).split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _validate_batch_record_payload(record: dict[str, Any], contract: dict[str, Any]) -> None:
    expected_version = str(contract.get("record_version", "")).strip()
    if expected_version and str(record.get("version", "")).strip() != expected_version:
        raise RuntimeError(
            f"Batch record schema error: version mismatch expected={expected_version} actual={record.get('version')}"
        )
    required_top = contract.get("required_top_level", [])
    if isinstance(required_top, list):
        missing = [k for k in required_top if k not in record]
        if missing:
            raise RuntimeError(f"Batch record schema error: missing_top_level={','.join(missing)}")
    required_nested = contract.get("required_nested", {})
    if isinstance(required_nested, dict):
        for parent, fields in required_nested.items():
            node = record.get(parent)
            if not isinstance(node, dict):
                raise RuntimeError(f"Batch record schema error: nested_parent_not_dict={parent}")
            if isinstance(fields, list):
                missing_nested = [k for k in fields if k not in node]
                if missing_nested:
                    raise RuntimeError(
                        f"Batch record schema error: missing_nested={parent}:{','.join(missing_nested)}"
                    )
    typed_fields = contract.get("typed_fields", {})
    if isinstance(typed_fields, dict):
        for field_path, typ_name in typed_fields.items():
            expected_type = _TYPE_MAP.get(str(typ_name).strip())
            if expected_type is None:
                continue
            value = _get_path_value(record, str(field_path))
            if value is None:
                raise RuntimeError(f"Batch record schema error: missing_typed_field={field_path}")
            if not isinstance(value, expected_type):
                raise RuntimeError(
                    f"Batch record schema error: type_mismatch={field_path} expected={typ_name} actual={type(value).__name__}"
                )


def _validate_batch_summary_payload(summary: dict[str, Any], contract: dict[str, Any]) -> None:
    expected_version = str(contract.get("summary_version", "")).strip()
    if expected_version and str(summary.get("summary_version", "")).strip() != expected_version:
        raise RuntimeError(
            f"Batch summary schema error: version mismatch expected={expected_version} actual={summary.get('summary_version')}"
        )
    required_top = contract.get("required_top_level") if isinstance(contract.get("required_top_level"), list) else []
    missing_top = [k for k in required_top if k not in summary]
    if missing_top:
        raise RuntimeError(f"Batch summary schema error: missing_top_level={','.join(missing_top)}")
    required_record = (
        contract.get("required_record_fields") if isinstance(contract.get("required_record_fields"), list) else []
    )
    records = summary.get("records") if isinstance(summary.get("records"), list) else []
    for idx, row in enumerate(records):
        if not isinstance(row, dict):
            raise RuntimeError(f"Batch summary schema error: record_not_object:index={idx}")
        missing = [k for k in required_record if k not in row]
        if missing:
            raise RuntimeError(
                f"Batch summary schema error: missing_record_fields:index={idx}:fields={','.join(missing)}"
            )


def _cloud_path_verification_meta(required_cloud_min: int, cloud_path_completed: int) -> dict[str, Any]:
    required_min = max(0, int(required_cloud_min))
    completed = max(0, int(cloud_path_completed))
    passed = completed >= required_min
    status = "verified" if passed else "insufficient_cloud_path"
    benchmark_origin = "fresh_runtime" if passed else "runtime_unverified_cloud_path"
    return {
        "required_cloud_path_min": required_min,
        "cloud_path_completed_cases": completed,
        "cloud_path_verification_passed": bool(passed),
        "cloud_path_verification_status": status,
        "benchmark_origin": benchmark_origin,
    }


def _staging_record_path(
    batch_id: str,
    run_id: str,
    staging_root: str,
    record_suffix: str,
    *,
    attempt_index: int,
) -> Path:
    root = ROOT / str(staging_root).strip()
    return root / batch_id / f"attempt_{int(attempt_index)}" / f"{run_id}{record_suffix}"


def _classify_artifact_api_failure(payload: dict[str, Any], *, backend: str) -> tuple[bool, bool, str]:
    flags = payload.get("runtime_flags") if isinstance(payload.get("runtime_flags"), dict) else {}
    captain_backend_error = bool(flags.get("captain_backend_error"))
    captain_cloud_error = bool(flags.get("captain_cloud_error"))
    backend_error = bool(flags.get("backend_error"))
    retryable = bool(flags.get("retryable_api_error"))
    provisional_local = bool(flags.get("provisional_local_fallback"))
    provisional_review_required = bool(flags.get("provisional_review_required"))
    fallback_agents = flags.get("fallback_agents") if isinstance(flags.get("fallback_agents"), list) else []
    reason = str(flags.get("captain_error_reason") or "")

    usage_nodes: list[dict[str, Any]] = []
    for key in ("captain_usage", "doctor_usage", "commander_usage"):
        node = payload.get(key)
        if isinstance(node, dict):
            usage_nodes.append(node)
    all_tokens_zero = (
        str(backend).lower() == "groq"
        and bool(usage_nodes)
        and all(int(node.get("total_tokens") or 0) == 0 for node in usage_nodes)
    )

    # Treat as API failure only when chain could not produce a valid completed run.
    # Provisional local fallback runs are completed and should not be counted as FAILED_API.
    failed_api = bool(
        (captain_backend_error and not provisional_local and not provisional_review_required)
        or (
            all_tokens_zero
            and not provisional_local
            and not provisional_review_required
            and backend_error
            and not bool(fallback_agents)
        )
    )
    retryable_api = bool(retryable or _is_rate_limit_error(reason))
    if all_tokens_zero and not reason:
        reason = "all_usage_tokens_zero"
    if not reason and captain_cloud_error and provisional_local:
        reason = "cloud_error_recovered_via_provisional_fallback"
    return failed_api, retryable_api, reason


def _run_chain_once(
    *,
    run_id: str,
    query: str,
    backend: str,
    top_k: int,
    batch_record_out: Path,
    release_candidate: bool,
    blocked_models: set[str] | None = None,
    doctor_model: str | None = None,
    doctor_fallback_model: str | None = None,
    commander_model: str | None = None,
    commander_fallback_model: str | None = None,
) -> tuple[int, str, str, float]:
    cmd = [
        sys.executable,
        "scripts/run_poc_e2e.py",
        "--run-id",
        run_id,
        "--backend",
        backend,
        "--top-k",
        str(top_k),
        "--query",
        query,
        "--write-card",
        "0",
        "--release-candidate",
        ("1" if bool(release_candidate) else "0"),
        "--batch-record-out",
        str(batch_record_out),
    ]
    blocked = sorted(str(x).strip() for x in (blocked_models or set()) if str(x).strip())
    if blocked:
        cmd.extend(["--blocked-models", ",".join(blocked)])
    if doctor_model:
        cmd.extend(["--doctor-model", str(doctor_model).strip()])
    if doctor_fallback_model:
        cmd.extend(["--doctor-fallback-model", str(doctor_fallback_model).strip()])
    if commander_model:
        cmd.extend(["--commander-model", str(commander_model).strip()])
    if commander_fallback_model:
        cmd.extend(["--commander-fallback-model", str(commander_fallback_model).strip()])
    env = dict(os.environ)
    env["LLM_ALLOW_REMOTE"] = "1"
    started = time.perf_counter()
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, env=env)
    elapsed = time.perf_counter() - started
    return proc.returncode, proc.stdout, proc.stderr, elapsed


def _load_artifact(path: Path, *, batch_record_contract: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"Missing artifact: {path}")
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        raise RuntimeError(f"Artifact integrity error ({path}): {reason}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid artifact payload type: {path}")
    _validate_batch_record_payload(payload, batch_record_contract)
    return payload


def _case_cost(payload: dict[str, Any]) -> float:
    total = 0.0
    for key in ("captain_usage", "doctor_usage", "commander_usage"):
        node = payload.get(key) if isinstance(payload.get(key), dict) else {}
        total += float(node.get("cost_usd_estimate") or 0.0)
    return round(total, 6)


def _case_cloud_path_used(payload: dict[str, Any]) -> bool:
    for key in ("captain_usage", "doctor_usage", "commander_usage"):
        node = payload.get(key)
        if not isinstance(node, dict):
            continue
        if bool(node.get("cloud_path")):
            return True
    return False


def _derive_hold_reason_code(payload: dict[str, Any], decision: str) -> str:
    decision_u = str(decision or "").upper()
    if decision_u == "GO":
        return "NONE"
    blocked_by = payload.get("blocked_by")
    if isinstance(blocked_by, list):
        for item in blocked_by:
            code = str(item).strip().upper()
            if code:
                return code
    blockers = payload.get("review_blockers")
    if isinstance(blockers, list):
        for item in blockers:
            code = str(item).strip().upper()
            if code:
                return code
    commander = payload.get("commander") if isinstance(payload.get("commander"), dict) else {}
    rationale = commander.get("rationale_bullets") if isinstance(commander.get("rationale_bullets"), list) else []
    joined = " ".join(str(x).lower() for x in rationale)
    if "guardrail" in joined or "breach" in joined:
        return "GUARDRAIL_BREACH_EVIDENCE"
    if "underpowered" in joined or "sample" in joined:
        return "UNDERPOWERED"
    return "POLICY_HOLD_GENERIC"


def _stat_evidence_ref(run_id: str, payload: dict[str, Any]) -> str:
    explicit = str(payload.get("stat_evidence_ref") or "").strip()
    if explicit:
        return explicit
    candidate = ROOT / f"data/agent_context/{run_id}_stat_evidence_bundle_v1.json"
    if candidate.exists():
        return str(candidate.relative_to(ROOT))
    return ""


def _counterfactual_go_check(payload: dict[str, Any], decision: str) -> dict[str, Any]:
    decision_u = str(decision or "").upper()
    reasoning = payload.get("reasoning") if isinstance(payload.get("reasoning"), dict) else {}
    note = str(reasoning.get("why_not_opposite_decision") or "").strip()
    if decision_u == "GO":
        return {
            "status": "not_applicable_for_go",
            "evidence_present": bool(note),
            "note": note[:220],
        }
    return {
        "status": "checked_for_non_go",
        "evidence_present": bool(note),
        "note": note[:220],
    }


def _build_template_regression_tracking(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    def _safe_rows(predicate) -> int:
        return sum(1 for r in records if isinstance(r, dict) and predicate(r))

    def _inventory_match(row: dict[str, Any]) -> bool:
        q = str(row.get("query", "")).lower()
        return "reorder" in q or "replenish" in q or "inventory" in q

    def _assortment_match(row: dict[str, Any]) -> bool:
        q = str(row.get("query", "")).lower()
        return "assortment" in q or "exposure" in q or "premium sku" in q

    return {
        "inventory_reorder": {
            "safe_cases": _safe_rows(lambda r: (not bool(r.get("expected_block"))) and _inventory_match(r)),
            "false_positive_non_go": _safe_rows(
                lambda r: (not bool(r.get("expected_block"))) and _inventory_match(r) and bool(r.get("predicted_block"))
            ),
        },
        "assortment_exposure": {
            "safe_cases": _safe_rows(lambda r: (not bool(r.get("expected_block"))) and _assortment_match(r)),
            "false_positive_non_go": _safe_rows(
                lambda r: (not bool(r.get("expected_block"))) and _assortment_match(r) and bool(r.get("predicted_block"))
            ),
        },
    }


def _build_false_positive_breakdown_by_reason(records: list[dict[str, Any]]) -> dict[str, int]:
    breakdown: dict[str, int] = {}
    for row in records:
        if not isinstance(row, dict):
            continue
        if bool(row.get("expected_block")):
            continue
        if not bool(row.get("predicted_block")):
            continue
        reason = str(row.get("hold_reason_code", "")).strip().upper() or "UNKNOWN"
        breakdown[reason] = int(breakdown.get(reason, 0) or 0) + 1
    return dict(sorted(breakdown.items()))


def _build_false_positive_breakdown_by_template(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    tracking = _build_template_regression_tracking(records)
    out: dict[str, dict[str, int]] = {}
    for key, row in tracking.items():
        if not isinstance(row, dict):
            continue
        out[str(key)] = {
            "safe_cases": int(row.get("safe_cases", 0) or 0),
            "false_positive_non_go": int(row.get("false_positive_non_go", 0) or 0),
        }
    return out


def _build_fpr_non_go_by_template(records: list[dict[str, Any]]) -> dict[str, dict[str, float | int | None]]:
    tracking = _build_false_positive_breakdown_by_template(records)
    out: dict[str, dict[str, float | int | None]] = {}
    for key, row in tracking.items():
        safe_cases = int(row.get("safe_cases", 0) or 0)
        false_pos = int(row.get("false_positive_non_go", 0) or 0)
        rate = (false_pos / safe_cases) if safe_cases > 0 else None
        out[str(key)] = {
            "safe_cases": safe_cases,
            "false_positive_non_go": false_pos,
            "fpr_non_go": round(rate, 4) if isinstance(rate, float) else None,
        }
    return out


def _build_fpr_non_go_by_hold_reason_code(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, float | int | None]]:
    safe_total = sum(1 for row in records if isinstance(row, dict) and (not bool(row.get("expected_block"))))
    counts: dict[str, int] = {}
    for row in records:
        if not isinstance(row, dict):
            continue
        if bool(row.get("expected_block")):
            continue
        if not bool(row.get("predicted_block")):
            continue
        code = str(row.get("hold_reason_code", "")).strip().upper() or "UNKNOWN"
        counts[code] = int(counts.get(code, 0) or 0) + 1
    out: dict[str, dict[str, float | int | None]] = {}
    for code, count in sorted(counts.items()):
        rate = (count / safe_total) if safe_total > 0 else None
        out[code] = {
            "false_positive_non_go": int(count),
            "safe_cases_total": int(safe_total),
            "fpr_non_go": round(rate, 4) if isinstance(rate, float) else None,
        }
    return out


def _safe_case_block_evidence_missing(payload: dict[str, Any], *, expected_block: bool, predicted_block: bool) -> bool:
    if bool(expected_block) or (not bool(predicted_block)):
        return False
    meta = payload.get("safe_case_block_evidence")
    if isinstance(meta, dict) and bool(meta.get("required", False)):
        return not bool(meta.get("passed", False))
    reasoning = payload.get("reasoning") if isinstance(payload.get("reasoning"), dict) else {}
    observed = reasoning.get("observed_facts") if isinstance(reasoning.get("observed_facts"), list) else []
    observed_count = len([x for x in observed if str(x).strip()])
    causal_ok = bool(str(reasoning.get("causal_interpretation", "")).strip())
    counterfactual_ok = bool(str(reasoning.get("counterfactual", "")).strip())
    guardrail_rows = payload.get("guardrail_status_check") if isinstance(payload.get("guardrail_status_check"), list) else []
    has_guardrail_breach = any(
        isinstance(row, dict)
        and str(row.get("status", "")).strip().upper() == "BREACH"
        and bool(row.get("blocks_rollout", False))
        for row in guardrail_rows
    )
    return (observed_count < 2) or (not causal_ok) or (not counterfactual_ok) or (not has_guardrail_breach)


def _extract_commander_payload(case_payload: dict[str, Any]) -> dict[str, Any]:
    commander = case_payload.get("commander")
    return commander if isinstance(commander, dict) else {}


def _extract_methodology_state(case_payload: dict[str, Any]) -> str:
    commander = _extract_commander_payload(case_payload)
    methodology = commander.get("methodology_check") if isinstance(commander.get("methodology_check"), dict) else {}
    return str(methodology.get("measurement_state", "")).strip().upper()


def _extract_ab_status(case_payload: dict[str, Any]) -> str:
    commander = _extract_commander_payload(case_payload)
    methodology = commander.get("methodology_check") if isinstance(commander.get("methodology_check"), dict) else {}
    return str(methodology.get("ab_status", "")).strip().upper()


def _extract_blocked_by(case_payload: dict[str, Any]) -> list[str]:
    commander = _extract_commander_payload(case_payload)
    blocked = commander.get("blocked_by") if isinstance(commander.get("blocked_by"), list) else []
    out = [str(x).strip() for x in blocked if str(x).strip()]
    return out[:20]


def _extract_guardrail_breach_count(case_payload: dict[str, Any]) -> int:
    commander = _extract_commander_payload(case_payload)
    rows = commander.get("guardrail_status_check") if isinstance(commander.get("guardrail_status_check"), list) else []
    return sum(
        1
        for row in rows
        if isinstance(row, dict)
        and str(row.get("status", "")).strip().upper() == "BREACH"
        and bool(row.get("blocks_rollout", False))
    )


def _extract_reasoning_scores(case_payload: dict[str, Any]) -> tuple[float | None, float | None]:
    commander = _extract_commander_payload(case_payload)
    def _to_float(v: Any) -> float | None:
        try:
            return float(v)
        except Exception:
            return None
    return _to_float(commander.get("reasoning_completeness_score")), _to_float(commander.get("staff_reasoning_score"))


def _extract_safe_case_evidence_issues(case_payload: dict[str, Any]) -> list[str]:
    commander = _extract_commander_payload(case_payload)
    meta = commander.get("safe_case_block_evidence") if isinstance(commander.get("safe_case_block_evidence"), dict) else {}
    rows = meta.get("issues") if isinstance(meta.get("issues"), list) else []
    return [str(x).strip() for x in rows if str(x).strip()][:20]


def _extract_safe_case_demotion_meta(case_payload: dict[str, Any]) -> tuple[bool, str, str]:
    commander = _extract_commander_payload(case_payload)
    safe_meta = (
        commander.get("safe_case_block_evidence")
        if isinstance(commander.get("safe_case_block_evidence"), dict)
        else {}
    )
    demotion_applied = bool(
        commander.get("safe_case_non_go_demotion_applied")
        if "safe_case_non_go_demotion_applied" in commander
        else bool(safe_meta.get("remediation_applied", False))
    )
    demotion_reason = str(
        commander.get("demotion_reason_code")
        if "demotion_reason_code" in commander
        else ("safe_case_block_without_evidence" if demotion_applied else "none")
    ).strip()
    if not demotion_reason:
        demotion_reason = "none"
    blocking_evidence_strength = str(
        commander.get("blocking_evidence_strength")
        if "blocking_evidence_strength" in commander
        else safe_meta.get("blocking_evidence_strength", "unknown")
    ).strip()
    if not blocking_evidence_strength:
        blocking_evidence_strength = "unknown"
    return demotion_applied, demotion_reason, blocking_evidence_strength


def _safe_non_go_demoted_to_go(case_payload: dict[str, Any], *, expected_block: bool, decision: str) -> bool:
    if bool(expected_block):
        return False
    if str(decision or "").upper() != "GO":
        return False
    commander = _extract_commander_payload(case_payload)
    meta = commander.get("safe_case_block_evidence") if isinstance(commander.get("safe_case_block_evidence"), dict) else {}
    return bool(meta.get("required", False)) and bool(meta.get("remediation_applied", False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch evaluation for Sprint-2 E2E chain with rate-limited Groq calls.")
    parser.add_argument("--batch-id", default=f"batch_eval_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
    parser.add_argument("--backend", choices=["groq", "auto"], default="groq")
    parser.add_argument("--dataset", choices=["baseline", "ood"], default="baseline")
    parser.add_argument("--max-cases", type=int, default=20)
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--sleep-seconds", type=float, default=1.5, help="Rate-limit pause between chain runs.")
    parser.add_argument("--max-retries", type=int, default=3, help="Retries on HTTP 429 / rate-limit.")
    parser.add_argument("--backoff-base-seconds", type=float, default=2.0, help="Base for exponential backoff.")
    parser.add_argument("--max-total-cost-usd", type=float, default=3.0, help="Budget guardrail for full batch.")
    parser.add_argument(
        "--release-candidate",
        type=int,
        choices=[0, 1],
        default=0,
        help="Mark summary as release candidate (0/1).",
    )
    parser.add_argument(
        "--require-cloud-path-min",
        type=int,
        default=0,
        help="Fail run if fewer than this number of completed cases used real cloud LLM path.",
    )
    parser.add_argument(
        "--max-rate-limit-errors",
        type=int,
        default=-1,
        help="Hard stop budget for rate-limit errors (<=0 disables). -1 means policy default.",
    )
    parser.add_argument(
        "--max-wave-attempts",
        type=int,
        default=-1,
        help="Maximum full-wave attempts per batch_id. -1 means policy default.",
    )
    parser.add_argument(
        "--max-cloud-calls-per-wave",
        type=int,
        default=-1,
        help="Maximum cloud API calls per wave. -1 means policy default.",
    )
    parser.add_argument(
        "--allow-rerun-same-fingerprint",
        type=int,
        choices=[0, 1],
        default=0,
        help="Allow rerun with identical code+policy+args fingerprint (requires --rerun-reason).",
    )
    parser.add_argument(
        "--rerun-reason",
        default="",
        help="Required when --allow-rerun-same-fingerprint=1.",
    )
    args = parser.parse_args()
    transport_contract = _load_transport_policy_contract()
    transport_policy = transport_contract.get("policy") if isinstance(transport_contract.get("policy"), dict) else {}
    staging_root = str(transport_policy.get("staging_root", "data/batch_eval/staging")).strip() or "data/batch_eval/staging"
    record_suffix = str(transport_policy.get("record_suffix", "_batch_record_v2.json")).strip() or "_batch_record_v2.json"
    if record_suffix.endswith("_poc_sprint2.json"):
        raise SystemExit("Transport policy violation: staging record suffix must not be *_poc_sprint2.json")
    if "batch_record_v2" not in record_suffix:
        raise SystemExit("Transport policy violation: record_suffix must include batch_record_v2")
    batch_record_contract = _load_batch_record_contract()
    batch_summary_contract = _load_batch_summary_contract()

    calibration_policy = _load_fpr_calibration_policy_block()
    max_rate_limit_errors = _resolve_limit_value(
        args.max_rate_limit_errors, calibration_policy.get("max_rate_limit_errors"), 2
    )
    max_wave_attempts = _resolve_limit_value(args.max_wave_attempts, calibration_policy.get("max_wave_attempts"), 3)
    max_cloud_calls_per_wave = _resolve_limit_value(
        args.max_cloud_calls_per_wave, calibration_policy.get("max_cloud_calls_per_wave"), 300
    )
    model_cooldown_seconds = _resolve_limit_value(
        -1, calibration_policy.get("model_cooldown_seconds"), 900
    )
    release_reasoning_only = bool(calibration_policy.get("release_candidate_reasoning_only_fallback", True))
    enforce_rerun_fingerprint_guard = bool(calibration_policy.get("enforce_rerun_fingerprint_guard", True))

    wave_fingerprint = _build_wave_fingerprint(args)
    attempt_ledger_path = _attempt_ledger_path(str(args.batch_id))
    attempt_ledger = _load_attempt_ledger(attempt_ledger_path)
    attempt_rows = attempt_ledger.get("attempts") if isinstance(attempt_ledger.get("attempts"), list) else []
    attempt_index = len(attempt_rows) + 1
    completed_same_fingerprint = [
        row
        for row in attempt_rows
        if isinstance(row, dict)
        and str(row.get("fingerprint", "")).strip() == wave_fingerprint
        and str(row.get("status", "")).strip().lower() == "completed"
    ]
    if max_wave_attempts > 0 and len(attempt_rows) >= int(max_wave_attempts):
        raise SystemExit(
            f"RETRY_POLICY_BLOCKED:wave_attempt_budget_exhausted:batch_id={args.batch_id}:"
            f"attempts={len(attempt_rows)}:limit={int(max_wave_attempts)}"
        )
    if (
        int(args.release_candidate) == 1
        and enforce_rerun_fingerprint_guard
        and completed_same_fingerprint
        and int(args.allow_rerun_same_fingerprint) == 0
    ):
        raise SystemExit(
            "RETRY_POLICY_BLOCKED:same_fingerprint_rerun_blocked:"
            f"batch_id={args.batch_id}:fingerprint={wave_fingerprint}"
        )
    if int(args.allow_rerun_same_fingerprint) == 1 and not str(args.rerun_reason or "").strip():
        raise SystemExit("RETRY_POLICY_BLOCKED:rerun_reason_required")

    attempt_rows.append(
        {
            "attempt_index": int(attempt_index),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "running",
            "fingerprint": wave_fingerprint,
            "release_candidate": bool(int(args.release_candidate)),
            "allow_rerun_same_fingerprint": bool(int(args.allow_rerun_same_fingerprint)),
            "rerun_reason": str(args.rerun_reason or "").strip(),
        }
    )
    attempt_ledger["version"] = "wave_attempt_ledger_v1"
    attempt_ledger["batch_id"] = str(args.batch_id)
    attempt_ledger["attempts"] = attempt_rows
    _write_attempt_ledger(attempt_ledger_path, attempt_ledger)

    secrets_path = _ensure_groq_secrets()
    preflight_payload: dict[str, Any] | None = None
    preflight_artifact_path: Path | None = None
    if int(args.release_candidate) == 1:
        preflight_payload, preflight_artifact_path = _run_release_candidate_cloud_preflight(
            batch_id=str(args.batch_id),
            backend=str(args.backend),
            secrets_path=secrets_path,
            doctor_chain=tuple(DOCTOR_GROQ_REASONING_CHAIN),
            commander_chain=tuple(COMMANDER_GROQ_REASONING_CHAIN),
        )
        if str(preflight_payload.get("status", "")).strip().lower() != "pass":
            if attempt_rows and isinstance(attempt_rows[-1], dict):
                attempt_rows[-1].update(
                    {
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "status": "failed_preflight",
                        "stop_code": "RUNTIME_ENV_NETWORK_BLOCKED",
                        "stop_reason": "release_candidate_cloud_preflight_failed",
                        "cloud_preflight_artifact": _path_ref(preflight_artifact_path)
                        if isinstance(preflight_artifact_path, Path)
                        else "",
                    }
                )
                attempt_ledger["attempts"] = attempt_rows
                _write_attempt_ledger(attempt_ledger_path, attempt_ledger)
            raise SystemExit(
                "RUNTIME_ENV_NETWORK_BLOCKED:"
                f"batch_id={args.batch_id}:"
                f"artifact={preflight_artifact_path}"
            )

    # Ensure SoT/index exists and is up to date.
    gen_cmd = [
        sys.executable,
        "scripts/generate_synthetic_history.py",
        "--run-demo",
        "0",
        "--out-sot",
        "data/poc/history_sot_v1.json",
        "--out-index",
        "data/poc/history_vector_index_v1.json",
    ]
    gen_proc = subprocess.run(gen_cmd, cwd=ROOT, text=True, capture_output=True)
    if gen_proc.returncode != 0:
        raise SystemExit(f"Synthetic history generation failed:\n{gen_proc.stdout}\n{gen_proc.stderr}")

    cases = build_batch_eval_cases(count=max(1, int(args.max_cases)), dataset=args.dataset)
    total_cost = 0.0
    total_elapsed = 0.0
    completed = 0
    failed = 0
    failed_api = 0

    safe_total = 0
    risky_total = 0
    false_positive = 0
    false_negative = 0
    provisional_completed = 0
    cloud_path_completed = 0
    safe_non_go_demoted_to_go_count = 0
    safe_non_go_evidence_fail_count = 0
    review_supported_total = 0
    review_refuted_total = 0
    review_untestable_total = 0
    review_quality_score_sum = 0.0
    review_quality_score_count = 0
    review_unavailable_cases = 0
    rate_limit_error_count = 0
    rate_limit_by_model: dict[str, int] = {}
    model_cooldown_until: dict[str, float] = {}
    cooldown_applied = False
    model_attempt_journal: list[dict[str, Any]] = []
    cloud_calls_total = 0
    stop_error_code = ""
    stop_reason = ""

    records: list[dict[str, Any]] = []
    print(f"batch_id={args.batch_id} cases={len(cases)} secrets={secrets_path}")
    for i, case in enumerate(cases, start=1):
        if stop_error_code:
            break
        if total_cost >= float(args.max_total_cost_usd):
            print(f"[stop] budget limit reached total_cost={total_cost}")
            break

        case_id = str(case.get("case_id") or f"case_{i:03d}")
        query = str(case.get("query") or "").strip()
        expected_block = bool(case.get("expected_block"))
        run_id = f"{args.batch_id}_{case_id}"
        attempts = 0
        case_error = ""
        case_payload: dict[str, Any] | None = None
        case_elapsed = 0.0

        while attempts <= int(args.max_retries):
            attempts += 1
            blocked_models = _active_cooldown_blocklist(model_cooldown_until, time.time())
            try:
                doctor_model, doctor_fallback_model = _resolve_reasoning_model_pair(
                    chain=tuple(DOCTOR_GROQ_REASONING_CHAIN),
                    blocked_models=blocked_models,
                )
                commander_model, commander_fallback_model = _resolve_reasoning_model_pair(
                    chain=tuple(COMMANDER_GROQ_REASONING_CHAIN),
                    blocked_models=blocked_models,
                )
            except RuntimeError:
                stop_error_code = "RETRY_POLICY_BLOCKED"
                stop_reason = (
                    "no_reasoning_models_available_due_cooldown:"
                    f"batch_id={args.batch_id}:run_id={run_id}"
                )
                case_error = stop_reason
                break
            model_attempt_journal.append(
                {
                    "run_id": run_id,
                    "attempt": int(attempts),
                    "doctor_from_model": doctor_model,
                    "doctor_to_model": doctor_fallback_model,
                    "doctor_model_class": model_class_for(doctor_model),
                    "commander_from_model": commander_model,
                    "commander_to_model": commander_fallback_model,
                    "commander_model_class": model_class_for(commander_model),
                    "blocked_models": sorted(blocked_models),
                }
            )
            case_record_path = _staging_record_path(
                args.batch_id,
                run_id,
                staging_root,
                record_suffix,
                attempt_index=attempt_index,
            )
            case_record_path.parent.mkdir(parents=True, exist_ok=True)
            rc, out, err, elapsed = _run_chain_once(
                run_id=run_id,
                query=query,
                backend=args.backend,
                top_k=args.top_k,
                batch_record_out=case_record_path,
                release_candidate=bool(int(args.release_candidate)),
                blocked_models=blocked_models,
                doctor_model=doctor_model,
                doctor_fallback_model=doctor_fallback_model,
                commander_model=commander_model,
                commander_fallback_model=commander_fallback_model,
            )
            case_elapsed += elapsed
            if rc == 0:
                try:
                    case_payload = _load_artifact(case_record_path, batch_record_contract=batch_record_contract)
                except Exception as exc:
                    failed += 1
                    records.append(
                        {
                            "run_id": run_id,
                            "case_id": case_id,
                            "expected_block": expected_block,
                            "decision": "FAILED_RECORD",
                            "predicted_block": True,
                            "hold_reason_code": "FAILED_RECORD",
                            "safe_case_non_go_demotion_applied": False,
                            "demotion_reason_code": "FAILED_RECORD",
                            "blocking_evidence_strength": "unknown",
                            "stat_evidence_ref": "",
                            "top_matches": [],
                            "counterfactual_go_check": {
                                "status": "not_available",
                                "evidence_present": False,
                                "note": "record_failed_before_decision",
                            },
                            "status": "FAILED_RECORD",
                            "attempts": attempts,
                            "elapsed_sec": round(case_elapsed, 3),
                            "error_tail": str(exc)[:500],
                            "record_path": str(case_record_path),
                        }
                    )
                    print(f"[fail_record] {run_id} attempts={attempts} reason={str(exc)[:160]}")
                    case_payload = None
                    break
                if _artifact_has_rate_limit_error(case_payload):
                    rate_limit_error_count += 1
                    limited_models = _extract_rate_limited_models(f"{out}\n{err}")
                    if not limited_models:
                        # Fallback: attribute to active selected reasoning models for this attempt.
                        limited_models = {
                            str(doctor_model).strip(),
                            str(commander_model).strip(),
                        }
                    now_ts = time.time()
                    for model in sorted(m for m in limited_models if m):
                        rate_limit_by_model[model] = int(rate_limit_by_model.get(model, 0) or 0) + 1
                        if model_cooldown_seconds > 0:
                            model_cooldown_until[model] = max(
                                float(model_cooldown_until.get(model, 0.0) or 0.0),
                                now_ts + float(model_cooldown_seconds),
                            )
                            cooldown_applied = True
                    if (
                        int(args.release_candidate) == 1
                        and max_rate_limit_errors > 0
                        and rate_limit_error_count >= int(max_rate_limit_errors)
                    ):
                        stop_error_code = "RETRY_POLICY_BLOCKED"
                        stop_reason = (
                            "rate_limit_retry_budget_exceeded:"
                            f"batch_id={args.batch_id}:run_id={run_id}:"
                            f"observed={rate_limit_error_count}:limit={int(max_rate_limit_errors)}"
                        )
                        case_error = stop_reason
                        case_payload = None
                        break
                if (
                    int(args.release_candidate) == 1
                    and release_reasoning_only
                    and _release_candidate_non_reasoning_fallback(case_payload)
                ):
                    stop_error_code = "RETRY_POLICY_BLOCKED"
                    stop_reason = (
                        "release_candidate_non_reasoning_fallback_detected:"
                        f"batch_id={args.batch_id}:run_id={run_id}"
                    )
                    case_error = stop_reason
                    case_payload = None
                    break
                is_api_failed, is_retryable_api, api_reason = _classify_artifact_api_failure(
                    case_payload, backend=args.backend
                )
                if is_api_failed and is_retryable_api and attempts <= int(args.max_retries):
                    wait_s = float(args.backoff_base_seconds) * (2 ** (attempts - 1))
                    print(f"[retry] {run_id} artifact_api_error attempt={attempts} wait={wait_s:.1f}s")
                    time.sleep(wait_s)
                    case_payload = None
                    continue
                if is_api_failed:
                    failed += 1
                    failed_api += 1
                    records.append(
                        {
                            "run_id": run_id,
                            "case_id": case_id,
                            "expected_block": expected_block,
                            "decision": "FAILED_API",
                            "predicted_block": True,
                            "hold_reason_code": "FAILED_API",
                            "safe_case_non_go_demotion_applied": False,
                            "demotion_reason_code": "FAILED_API",
                            "blocking_evidence_strength": "unknown",
                            "stat_evidence_ref": "",
                            "top_matches": [],
                            "counterfactual_go_check": {
                                "status": "not_available",
                                "evidence_present": False,
                                "note": "api_failure_before_decision",
                            },
                            "status": "FAILED_API",
                            "attempts": attempts,
                            "elapsed_sec": round(case_elapsed, 3),
                            "error_tail": api_reason[:500],
                        }
                    )
                    print(f"[fail_api] {run_id} attempts={attempts} reason={api_reason[:160]}")
                    case_payload = None
                break

            merged = f"{out}\n{err}"
            if _is_rate_limit_error(merged) and attempts <= int(args.max_retries):
                rate_limit_error_count += 1
                limited_models = _extract_rate_limited_models(merged)
                if not limited_models:
                    limited_models = {
                        str(doctor_model).strip(),
                        str(commander_model).strip(),
                    }
                now_ts = time.time()
                for model in sorted(m for m in limited_models if m):
                    rate_limit_by_model[model] = int(rate_limit_by_model.get(model, 0) or 0) + 1
                    if model_cooldown_seconds > 0:
                        model_cooldown_until[model] = max(
                            float(model_cooldown_until.get(model, 0.0) or 0.0),
                            now_ts + float(model_cooldown_seconds),
                        )
                        cooldown_applied = True
                if (
                    int(args.release_candidate) == 1
                    and max_rate_limit_errors > 0
                    and rate_limit_error_count >= int(max_rate_limit_errors)
                ):
                    stop_error_code = "RETRY_POLICY_BLOCKED"
                    stop_reason = (
                        "rate_limit_retry_budget_exceeded:"
                        f"batch_id={args.batch_id}:run_id={run_id}:"
                        f"observed={rate_limit_error_count}:limit={int(max_rate_limit_errors)}"
                    )
                    case_error = stop_reason
                    break
                wait_s = float(args.backoff_base_seconds) * (2 ** (attempts - 1))
                print(f"[retry] {run_id} rate-limited attempt={attempts} wait={wait_s:.1f}s")
                time.sleep(wait_s)
                continue
            case_error = merged.strip()[-500:]
            break

        if case_payload is None:
            if records and records[-1].get("run_id") == run_id and str(records[-1].get("status", "")) in {"FAILED_API", "FAILED_RECORD"}:
                if stop_error_code:
                    print(f"[stop] {stop_reason}")
                    break
                if i < len(cases):
                    time.sleep(max(0.0, float(args.sleep_seconds)))
                continue
            failed += 1
            records.append(
                {
                    "run_id": run_id,
                    "case_id": case_id,
                    "expected_block": expected_block,
                    "decision": "FAILED_RUNTIME",
                    "predicted_block": True,
                    "hold_reason_code": "FAILED_RUNTIME",
                    "safe_case_non_go_demotion_applied": False,
                    "demotion_reason_code": "FAILED_RUNTIME",
                    "blocking_evidence_strength": "unknown",
                    "stat_evidence_ref": "",
                    "top_matches": [],
                    "counterfactual_go_check": {
                        "status": "not_available",
                        "evidence_present": False,
                        "note": "runtime_failure_before_decision",
                    },
                    "status": "FAILED_RUNTIME",
                    "attempts": attempts,
                    "elapsed_sec": round(case_elapsed, 3),
                    "error_tail": case_error,
                }
            )
            print(f"[fail] {run_id} attempts={attempts}")
            if stop_error_code:
                print(f"[stop] {stop_reason}")
                break
        else:
            completed += 1
            total_elapsed += case_elapsed
            decision = str(((case_payload.get("commander") or {}).get("decision") or "HOLD_NEED_DATA")).upper()
            predicted_block = decision != "GO"
            runtime_flags = case_payload.get("runtime_flags") if isinstance(case_payload.get("runtime_flags"), dict) else {}
            provisional_local = bool(runtime_flags.get("provisional_local_fallback"))
            if provisional_local:
                provisional_completed += 1
            cloud_path_used = _case_cloud_path_used(case_payload)
            if cloud_path_used:
                cloud_path_completed += 1
            cloud_calls_total += _count_cloud_api_calls(case_payload)
            review_unavailable = bool(case_payload.get("verification_unavailable", False))
            review_supported = int(case_payload.get("supported_count", 0) or 0)
            review_refuted = int(case_payload.get("refuted_count", 0) or 0)
            review_untestable = int(case_payload.get("untestable_count", 0) or 0)
            try:
                review_quality_score = float(case_payload.get("verification_quality_score", 0.0) or 0.0)
            except Exception:
                review_quality_score = 0.0
            review_quality_score = max(0.0, min(1.0, review_quality_score))
            if review_unavailable:
                review_unavailable_cases += 1
            else:
                review_supported_total += review_supported
                review_refuted_total += review_refuted
                review_untestable_total += review_untestable
                review_quality_score_sum += review_quality_score
                review_quality_score_count += 1
            cost = _case_cost(case_payload)
            total_cost = round(total_cost + cost, 6)

            profile = str(case.get("profile") or "").lower()
            reasoning = case_payload.get("reasoning") if isinstance(case_payload.get("reasoning"), dict) else {}
            confidence = reasoning.get("confidence") if isinstance(reasoning.get("confidence"), dict) else {}
            evidence_quality = (
                reasoning.get("evidence_quality") if isinstance(reasoning.get("evidence_quality"), dict) else {}
            )
            if expected_block:
                risky_total += 1
                if not predicted_block:
                    false_negative += 1
            else:
                safe_total += 1
                if predicted_block:
                    false_positive += 1
            safe_case_block_evidence_missing = _safe_case_block_evidence_missing(
                case_payload,
                expected_block=expected_block,
                predicted_block=predicted_block,
            )
            if safe_case_block_evidence_missing:
                safe_non_go_evidence_fail_count += 1
            if _safe_non_go_demoted_to_go(case_payload, expected_block=expected_block, decision=decision):
                safe_non_go_demoted_to_go_count += 1
            methodology_state = _extract_methodology_state(case_payload)
            ab_status = _extract_ab_status(case_payload)
            blocked_by = _extract_blocked_by(case_payload)
            guardrail_breach_count = _extract_guardrail_breach_count(case_payload)
            reasoning_completeness_score, staff_reasoning_score = _extract_reasoning_scores(case_payload)
            safe_case_evidence_issues = _extract_safe_case_evidence_issues(case_payload)
            (
                safe_case_demotion_applied,
                demotion_reason_code,
                blocking_evidence_strength,
            ) = _extract_safe_case_demotion_meta(case_payload)

            records.append(
                {
                    "run_id": run_id,
                    "case_id": case_id,
                    "profile": profile,
                    "query": query,
                    "expected_block": expected_block,
                    "decision": decision,
                    "executive_summary": str(((case_payload.get("commander") or {}).get("executive_summary") or "")).strip(),
                    "go_no_go_rationale": list((case_payload.get("commander") or {}).get("rationale_bullets") or []),
                    "risk_signals": list((case_payload.get("doctor") or {}).get("risk_signals") or []),
                    "recommended_actions": list((case_payload.get("doctor") or {}).get("recommended_actions") or []),
                    "commander_next_steps": list((case_payload.get("commander") or {}).get("next_steps") or []),
                    "top_match": case_payload.get("top_match") if isinstance(case_payload.get("top_match"), dict) else {},
                    "top_matches": case_payload.get("top_matches") if isinstance(case_payload.get("top_matches"), list) else [],
                    "reasoning_observed_facts": list(reasoning.get("observed_facts") or []),
                    "reasoning_causal_interpretation": str(reasoning.get("causal_interpretation") or "").strip(),
                    "reasoning_why_not_opposite_decision": str(
                        reasoning.get("why_not_opposite_decision") or ""
                    ).strip(),
                    "reasoning_counterfactual": str(reasoning.get("counterfactual") or "").strip(),
                    "reasoning_confidence": confidence if isinstance(confidence, dict) else {},
                    "reasoning_evidence_quality": evidence_quality if isinstance(evidence_quality, dict) else {},
                    "reasoning_decision_tradeoffs": list(reasoning.get("decision_tradeoffs") or []),
                    "reasoning_mitigations": list(reasoning.get("mitigations") or []),
                    "reasoning_uncertainty_gaps": list(reasoning.get("uncertainty_gaps") or []),
                    "predicted_block": predicted_block,
                    "methodology_state": methodology_state,
                    "ab_status": ab_status,
                    "blocked_by": blocked_by,
                    "guardrail_breach_count": int(guardrail_breach_count),
                    "reasoning_completeness_score": reasoning_completeness_score,
                    "staff_reasoning_score": staff_reasoning_score,
                    "hold_reason_code": _derive_hold_reason_code(case_payload, decision),
                    "safe_case_block_evidence_missing": bool(safe_case_block_evidence_missing),
                    "safe_case_block_evidence_issues": safe_case_evidence_issues,
                    "safe_case_non_go_demotion_applied": bool(safe_case_demotion_applied),
                    "demotion_reason_code": str(demotion_reason_code),
                    "blocking_evidence_strength": str(blocking_evidence_strength),
                    "stat_evidence_ref": _stat_evidence_ref(run_id, case_payload),
                    "counterfactual_go_check": _counterfactual_go_check(case_payload, decision),
                    "provisional_local_fallback": provisional_local,
                    "cloud_path_used": cloud_path_used,
                    "supported_count": review_supported,
                    "refuted_count": review_refuted,
                    "untestable_count": review_untestable,
                    "verification_quality_score": round(review_quality_score, 4),
                    "verification_unavailable": review_unavailable,
                    "attempts": attempts,
                    "elapsed_sec": round(case_elapsed, 3),
                    "cost_usd_estimate": cost,
                }
            )
            print(
                f"[ok] {run_id} decision={decision} expected_block={expected_block} "
                f"cost={cost} elapsed={case_elapsed:.2f}s attempts={attempts} provisional={provisional_local}"
            )
            if (
                int(args.release_candidate) == 1
                and max_cloud_calls_per_wave > 0
                and cloud_calls_total > int(max_cloud_calls_per_wave)
            ):
                stop_error_code = "RETRY_POLICY_BLOCKED"
                stop_reason = (
                    "cloud_call_budget_exceeded:"
                    f"batch_id={args.batch_id}:observed={cloud_calls_total}:"
                    f"limit={int(max_cloud_calls_per_wave)}"
                )
                print(f"[stop] {stop_reason}")
                break

        if i < len(cases):
            time.sleep(max(0.0, float(args.sleep_seconds)))

    avg_time = (total_elapsed / completed) if completed > 0 else 0.0
    fpr_non_go = (false_positive / safe_total) if safe_total > 0 else None
    stop_false_positive = sum(
        1
        for r in records
        if isinstance(r, dict)
        and str(r.get("status", "")).upper() not in {"FAILED_RUNTIME", "FAILED_API", "FAILED_RECORD"}
        and (not bool(r.get("expected_block")))
        and str(r.get("decision", "")).upper() == "STOP_ROLLOUT"
    )
    fpr_stop_only = (stop_false_positive / safe_total) if safe_total > 0 else None
    fnr = (false_negative / risky_total) if risky_total > 0 else None
    availability = (completed / (completed + failed_api)) if (completed + failed_api) > 0 else None
    verification_quality_score = (
        round(review_quality_score_sum / review_quality_score_count, 4)
        if review_quality_score_count > 0
        else None
    )
    required_cloud_min = max(0, int(args.require_cloud_path_min))
    cloud_path_verification = _cloud_path_verification_meta(required_cloud_min, cloud_path_completed)

    template_regression_tracking = _build_template_regression_tracking(records)
    records_quality_complete = compute_records_quality_complete(records)
    safe_case_block_evidence_missing_count = sum(
        1
        for row in records
        if isinstance(row, dict)
        and (not bool(row.get("expected_block")))
        and bool(row.get("predicted_block"))
        and bool(row.get("safe_case_block_evidence_missing", False))
    )
    safe_case_non_go_demotion_applied_count = sum(
        1 for row in records if isinstance(row, dict) and bool(row.get("safe_case_non_go_demotion_applied", False))
    )
    demotion_reason_breakdown: dict[str, int] = {}
    blocking_evidence_strength_breakdown: dict[str, int] = {}
    for row in records:
        if not isinstance(row, dict):
            continue
        reason = str(row.get("demotion_reason_code", "")).strip().upper() or "NONE"
        demotion_reason_breakdown[reason] = int(demotion_reason_breakdown.get(reason, 0) or 0) + 1
        strength = str(row.get("blocking_evidence_strength", "")).strip().lower() or "unknown"
        blocking_evidence_strength_breakdown[strength] = int(
            blocking_evidence_strength_breakdown.get(strength, 0) or 0
        ) + 1
    summary = {
        "summary_version": "batch_summary_v2",
        "batch_id": args.batch_id,
        "wave_run_fingerprint": wave_fingerprint,
        "wave_attempt_index": int(attempt_index),
        "wave_attempts_seen_before_start": int(attempt_index - 1),
        "max_wave_attempts": int(max_wave_attempts),
        "max_rate_limit_errors": int(max_rate_limit_errors),
        "max_cloud_calls_per_wave": int(max_cloud_calls_per_wave),
        "model_cooldown_seconds": int(model_cooldown_seconds),
        "release_candidate_reasoning_only_fallback": bool(release_reasoning_only),
        "cloud_preflight_required": bool(int(args.release_candidate) == 1),
        "cloud_preflight_status": (
            str(preflight_payload.get("status", "")).strip().lower()
            if isinstance(preflight_payload, dict)
            else "skipped"
        ),
        "cloud_preflight_artifact": (
            _path_ref(preflight_artifact_path)
            if isinstance(preflight_artifact_path, Path)
            else ""
        ),
        "rate_limit_error_count": int(rate_limit_error_count),
        "rate_limit_by_model": {str(k): int(v) for k, v in sorted(rate_limit_by_model.items())},
        "cooldown_applied": bool(cooldown_applied),
        "model_attempt_journal": model_attempt_journal[:200],
        "cloud_calls_total": int(cloud_calls_total),
        "retry_budget_stop_code": str(stop_error_code or ""),
        "retry_budget_stop_reason": str(stop_reason or ""),
        "retry_budget_stop_triggered": bool(stop_error_code),
        "benchmark_origin": cloud_path_verification["benchmark_origin"],
        "generated_by": "scripts/run_batch_eval.py",
        "legacy_upgraded": False,
        "records_quality_complete": bool(records_quality_complete),
        "dataset": args.dataset,
        "release_candidate": bool(int(args.release_candidate)),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "max_cases_requested": len(cases),
        "completed_cases": completed,
        "failed_cases": failed,
        "failed_api_cases": failed_api,
        "total_cost_usd_estimate": round(total_cost, 6),
        "average_time_sec": round(avg_time, 3),
        "false_positive_rate": (round(fpr_non_go, 4) if fpr_non_go is not None else None),
        "false_negative_rate": (round(fnr, 4) if fnr is not None else None),
        "fpr_non_go": (round(fpr_non_go, 4) if fpr_non_go is not None else None),
        "fpr_stop_only": (round(fpr_stop_only, 4) if fpr_stop_only is not None else None),
        "availability_kpi": (round(availability, 4) if availability is not None else None),
        "provisional_completed_cases": provisional_completed,
        "cloud_path_completed_cases": cloud_path_completed,
        "cloud_path_verification_required_min": cloud_path_verification["required_cloud_path_min"],
        "cloud_path_verification_status": cloud_path_verification["cloud_path_verification_status"],
        "cloud_path_verification_passed": cloud_path_verification["cloud_path_verification_passed"],
        "supported_count": review_supported_total,
        "refuted_count": review_refuted_total,
        "untestable_count": review_untestable_total,
        "verification_quality_score": verification_quality_score,
        "verification_quality_cases": review_quality_score_count,
        "verification_unavailable_cases": review_unavailable_cases,
        "safe_non_go_demoted_to_go_count": int(safe_non_go_demoted_to_go_count),
        "safe_non_go_evidence_fail_count": int(safe_non_go_evidence_fail_count),
        "safe_case_non_go_demotion_applied_count": int(safe_case_non_go_demotion_applied_count),
        "safe_cases": safe_total,
        "risky_cases": risky_total,
        "record_format": "batch_record_v2",
        "record_suffix": record_suffix,
        "records_source": "summary.records_from_staging",
        "summary_source_of_truth": f"data/batch_eval/{args.batch_id}_summary.json",
        "staging_root": f"{staging_root}/{args.batch_id}/attempt_{int(attempt_index)}",
        "template_regression_tracking": template_regression_tracking,
        "false_positive_breakdown_by_reason": _build_false_positive_breakdown_by_reason(records),
        "false_positive_breakdown_by_template": _build_false_positive_breakdown_by_template(records),
        "fpr_non_go_by_template": _build_fpr_non_go_by_template(records),
        "fpr_non_go_by_hold_reason_code": _build_fpr_non_go_by_hold_reason_code(records),
        "demotion_reason_breakdown": dict(sorted(demotion_reason_breakdown.items())),
        "blocking_evidence_strength_breakdown": dict(sorted(blocking_evidence_strength_breakdown.items())),
        "safe_case_block_evidence_missing_count": int(safe_case_block_evidence_missing_count),
        "records": records,
    }
    _validate_batch_summary_payload(summary, batch_summary_contract)

    out_path = ROOT / f"data/batch_eval/{args.batch_id}_summary.json"
    attempt_out_path = _attempt_summary_path(str(args.batch_id), int(attempt_index))
    summary["summary_source_of_truth"] = str(out_path.relative_to(ROOT))
    summary["summary_latest_path"] = str(out_path.relative_to(ROOT))
    summary["summary_attempt_path"] = str(attempt_out_path.relative_to(ROOT))
    summary["summary_attempt_history"] = [
        str(row.get("summary_attempt_path"))
        for row in attempt_rows
        if isinstance(row, dict) and str(row.get("summary_attempt_path", "")).strip()
    ] + [str(attempt_out_path.relative_to(ROOT))]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out_path)
    attempt_out_path.parent.mkdir(parents=True, exist_ok=True)
    attempt_out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(attempt_out_path)

    print("\n=== Batch Eval Summary ===")
    print(f"batch_id                : {args.batch_id}")
    print(f"dataset                 : {args.dataset}")
    print(f"completed / failed      : {completed} / {failed}")
    print(f"failed_api_cases        : {failed_api}")
    print(f"Total Cost (USD)        : {summary['total_cost_usd_estimate']}")
    print(f"Average Time (sec)      : {summary['average_time_sec']}")
    fpr_text = f"{summary['fpr_non_go']} ({false_positive}/{safe_total})" if safe_total > 0 else "N/A (0/0)"
    fpr_stop_text = (
        f"{summary['fpr_stop_only']} ({stop_false_positive}/{safe_total})" if safe_total > 0 else "N/A (0/0)"
    )
    fnr_text = f"{summary['false_negative_rate']} ({false_negative}/{risky_total})" if risky_total > 0 else "N/A (0/0)"
    availability_text = (
        f"{summary['availability_kpi']} ({completed}/{completed + failed_api})"
        if (completed + failed_api) > 0
        else "N/A (0/0)"
    )
    print(f"False Positive Rate     : {fpr_text}")
    print(f"FPR Stop-Only           : {fpr_stop_text}")
    print(f"False Negative Rate     : {fnr_text}")
    print(f"Availability KPI        : {availability_text}")
    print(f"provisional_completed   : {provisional_completed}")
    print(f"cloud_path_completed   : {cloud_path_completed}")
    print(f"summary_artifact        : {out_path}")
    print(f"summary_attempt_artifact: {attempt_out_path}")
    print(f"summary_artifact_sidecar: {out_path}.sha256")
    print(
        "cloud_path_verification : "
        f"status={summary['cloud_path_verification_status']} "
        f"required_min={summary['cloud_path_verification_required_min']} "
        f"observed={summary['cloud_path_completed_cases']} "
        f"benchmark_origin={summary['benchmark_origin']}"
    )
    print(
        "retry_budget            : "
        f"rate_limit_errors={summary['rate_limit_error_count']} "
        f"cloud_calls_total={summary['cloud_calls_total']} "
        f"stop_triggered={summary['retry_budget_stop_triggered']}"
    )
    print(
        "model_failover          : "
        f"cooldown_applied={summary['cooldown_applied']} "
        f"rate_limit_by_model={json.dumps(summary['rate_limit_by_model'], ensure_ascii=False)}"
    )

    final_status = "completed"
    if stop_error_code:
        final_status = "stopped_retry_budget"
    elif required_cloud_min > 0 and cloud_path_completed < required_cloud_min:
        final_status = "failed_cloud_path_verification"

    if attempt_rows and isinstance(attempt_rows[-1], dict):
        attempt_rows[-1].update(
            {
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": final_status,
                "summary_path": str(out_path.relative_to(ROOT)),
                "summary_attempt_path": str(attempt_out_path.relative_to(ROOT)),
                "rate_limit_error_count": int(rate_limit_error_count),
                "cloud_calls_total": int(cloud_calls_total),
                "stop_code": str(stop_error_code or ""),
                "stop_reason": str(stop_reason or ""),
                "cloud_preflight_artifact": (
                    _path_ref(preflight_artifact_path)
                    if isinstance(preflight_artifact_path, Path)
                    else ""
                ),
            }
        )
        attempt_ledger["attempts"] = attempt_rows
        _write_attempt_ledger(attempt_ledger_path, attempt_ledger)

    if stop_error_code:
        raise SystemExit(f"{stop_error_code}:{stop_reason}")

    if required_cloud_min > 0 and cloud_path_completed < required_cloud_min:
        raise SystemExit(
            f"CloudPathVerificationError: required>={required_cloud_min} "
            f"but observed={cloud_path_completed}. Prompt tuning not verified on real cloud path."
        )


if __name__ == "__main__":
    main()
