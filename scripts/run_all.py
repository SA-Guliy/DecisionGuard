#!/usr/bin/env python3
"""
Single end-to-end runner:
load RAW (optional) -> simulate -> DQ -> Captain Sanity LLM.
Runtime is non-admin and never performs DDL.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import create_engine, text
from src.agent_llm_auth import core_agent_llm_authenticity
from src.client_db_config import (
    client_db_service,
    expected_db,
    expected_user,
    resolve_pg_url,
    runtime_db_env,
)
from src.paths import security_report_json
from src.runtime_controls import (
    enforce_runtime_limits_for_run,
    get_retry_budget_status,
    load_feature_state_contract,
    load_retry_policy_contract,
    load_runtime_limits_contract,
    register_retry_outcome,
    write_retry_guard_report,
)
from src.architecture_v3 import (
    REQUIRED_GATE_ORDER,
    GATE_SEQUENCE,
    RECONCILIATION_POLICY_PATH,
    captain_artifact_path,
    gate_result_path,
    load_json_with_integrity,
    stat_evidence_bundle_path,
    validate_v3_contract_set,
    write_gate_result,
)
from src.stat_engine import compute_stat_evidence
from src.domain_template import (
    ConfigurationError as DomainTemplateConfigurationError,
    load_domain_template,
    load_experiment_variants,
)
from src.run_all_cli import build_run_all_parser, resolve_run_all_runtime_config
from src.run_summary import print_run_completion_summary
from src.security_profile import load_security_profile
from src.security_utils import enforce_service_dsn_policy, redact_text as _redact_text_shared, write_sha256_sidecar
from src.paired_registry import (
    CTRL_FOUNDATION_ALLOWED_STEPS,
    PAIRED_AGGRESSIVE_DECISIONS,
    PairedRunStatus,
    apply_status_transition,
    effective_paired_status,
    is_partial_like,
    load_registry_for_run,
    mark_treatment_failed_then_partial,
    normalize_registry_key,
    paired_registry_path,
    save_registry,
)

LOADER_SERVICE = client_db_service("loader")
APP_SERVICE = client_db_service("app")
ADMIN_SERVICE = client_db_service("admin")
EXPECTED_DB = expected_db()
EXPECTED_APP_USER = expected_user("app")
EXPECTED_LOADER_USER = expected_user("loader")
MAX_VERBOSE_CHARS = 10000
VERBOSE_TAIL_LINES = 30
_RUN_ALL_SCRIPT_RE = re.compile(r"scripts/[A-Za-z0-9_./-]+\.py")
_FORBIDDEN_RUNTIME_CLOUD_PATTERNS = (
    re.compile(r"^\s*from\s+src\.llm_client\s+import\s+get_llm_backend", re.MULTILINE),
    re.compile(r"(^|[^\"'])_client\.chat\.completions\.create\(", re.MULTILINE),
    re.compile(r"(^|[^\"'])api\.openai\.com", re.MULTILINE),
)
_REQUIRED_GATE_EXECUTION_LOG: list[str] = []
_GOAL1_CONTRACT_REQUIRED_COLUMNS: dict[str, tuple[str, ...]] = {
    "step1_replenishment_log": ("batch_id", "supplier_id", "purchase_order_id"),
    "step1_writeoff_log": ("batch_id", "supplier_id", "purchase_order_id"),
}
_LOCKED_HISTORICAL_DIR = Path("not_delete_historical_patterns/metrics_snapshots")
_LOCKED_HISTORICAL_MIN_PAIRS = 2
_CTRL_FOUNDATION_ACTIVE = False
_CTRL_FOUNDATION_EXECUTED_STEPS: list[str] = []

def _strict_runtime() -> bool:
    return os.getenv("DS_STRICT_RUNTIME", "0") == "1"


def _effective_hypothesis_review_flag(args: argparse.Namespace, security_profile: dict[str, Any]) -> int:
    raw = int(getattr(args, "enable_hypothesis_review_v1", -1))
    if raw in {0, 1}:
        return raw
    profile_name = str((security_profile or {}).get("name", "")).strip().lower()
    if _strict_runtime() or profile_name in {"production", "strict", "prod"}:
        return 1
    return 0


def _assert_local_dsn(pg_url: str) -> None:
    if os.getenv("ALLOW_NONLOCALHOST", "0") == "1":
        return
    if "service=" in pg_url:
        return
    if "@localhost" in pg_url or "@127.0.0.1" in pg_url or "@::1" in pg_url:
        return
    raise SystemExit("Refusing non-localhost DSN. Set ALLOW_NONLOCALHOST=1 to override.")


def _service_dsn(service_name: str, *, role: str) -> str:
    return resolve_pg_url(role=role, fallback_service=service_name)


def _engine(pg_url: str):
    return create_engine(pg_url)


def _app_db_env() -> dict[str, str]:
    return runtime_db_env("app")


def _loader_db_env() -> dict[str, str]:
    return runtime_db_env("loader")


def _redact_text(value: str) -> str:
    return _redact_text_shared(value)


def _enforce_runtime_secret_policy() -> None:
    for env_key in ("PG_DSN", "DATABASE_URL"):
        raw = str(os.getenv(env_key, "") or "").strip()
        if not raw:
            continue
        enforce_service_dsn_policy(raw, env_key)


def _preflight_validate_domain_template_or_exit(template_path: str) -> None:
    try:
        payload = load_domain_template(template_path)
    except DomainTemplateConfigurationError as exc:
        raise SystemExit(f"ConfigurationError: {exc}")
    version = str(payload.get("version", "")).strip().lower()
    if version != "domain_template.v2":
        raise SystemExit(
            f"ConfigurationError: Unsupported Domain Template version '{version or 'unknown'}'. "
            "Expected domain_template.v2"
        )
    print(
        "domain_template_preflight_ok "
        f"template_id={payload.get('template_id')} "
        f"version={payload.get('version')} "
        f"source={payload.get('source_path')}"
    )


def _enforce_runtime_feature_policy(feature_state: dict[str, Any]) -> None:
    weak_runtime = str(feature_state.get("weak_path_runtime", "DISABLED")).upper()
    reconciliation_runtime = str(feature_state.get("reconciliation_runtime", "NOT_IMPLEMENTED")).upper()
    auto_decision_change = str(feature_state.get("auto_decision_change", "FORBIDDEN")).upper()
    weak_ceiling = str(feature_state.get("default_weak_path_ceiling", "HOLD_NEED_DATA")).upper()
    if weak_runtime == "DISABLED":
        for env_key in ("WEAK_PATH_RUNTIME", "ENABLE_WEAK_PATH_RUNTIME"):
            if str(os.getenv(env_key, "")).strip() in {"1", "true", "TRUE", "on", "ON"}:
                raise SystemExit(f"{env_key}=1 is forbidden by feature_state weak_path_runtime=DISABLED")
    if reconciliation_runtime == "NOT_IMPLEMENTED":
        for env_key in ("RECONCILIATION_RUNTIME", "ENABLE_RECONCILIATION_RUNTIME"):
            if str(os.getenv(env_key, "")).strip() in {"1", "true", "TRUE", "on", "ON"}:
                raise SystemExit(f"{env_key}=1 is forbidden by feature_state reconciliation_runtime=NOT_IMPLEMENTED")
    if auto_decision_change == "FORBIDDEN":
        for env_key in ("AUTO_DECISION_CHANGE", "ENABLE_AUTO_DECISION_CHANGE"):
            if str(os.getenv(env_key, "")).strip() in {"1", "true", "TRUE", "on", "ON"}:
                raise SystemExit(f"{env_key}=1 is forbidden by feature_state auto_decision_change=FORBIDDEN")
    os.environ["DS_FEATURE_WEAK_PATH_RUNTIME"] = weak_runtime
    os.environ["DS_FEATURE_RECONCILIATION_RUNTIME"] = reconciliation_runtime
    os.environ["DS_FEATURE_AUTO_DECISION_CHANGE"] = auto_decision_change
    os.environ["DS_FEATURE_WEAK_CEILING"] = weak_ceiling


def _runtime_scope_scripts_from_run_all() -> list[Path]:
    run_all_path = Path("scripts/run_all.py")
    if not run_all_path.exists():
        return []
    try:
        text = run_all_path.read_text(encoding="utf-8")
    except Exception:
        return []
    out: list[Path] = []
    seen: set[str] = set()
    for rel in sorted(set(_RUN_ALL_SCRIPT_RE.findall(text))):
        if rel.startswith("scripts/admin_"):
            continue
        if rel in seen:
            continue
        p = Path(rel)
        if p.exists() and p.is_file():
            out.append(p)
            seen.add(rel)
    return out


def _enforce_runtime_cloud_gateway_policy_or_exit() -> None:
    findings: list[str] = []
    for path in _runtime_scope_scripts_from_run_all():
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            findings.append(f"runtime_script_unreadable:{path}")
            continue
        for pat in _FORBIDDEN_RUNTIME_CLOUD_PATTERNS:
            if pat.search(text):
                findings.append(f"direct_cloud_call_forbidden:{path}:{pat.pattern}")
    if findings:
        print(
            f"ERROR SANITIZATION_REQUIRED_FOR_CLOUD runtime_scope_policy_violation findings={findings[:8]}",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _enforce_run_all_gate_order_contract_or_exit() -> None:
    required = [str(x).strip() for x in REQUIRED_GATE_ORDER if str(x).strip()]
    gate_seq = [str(x).strip() for x in GATE_SEQUENCE if str(x).strip()]
    idx = -1
    for gate in required:
        try:
            pos = gate_seq.index(gate, idx + 1)
        except ValueError:
            print(
                f"ERROR gate_order_invalid missing_or_out_of_order_gate={gate} required_order={required} gate_sequence={gate_seq}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        idx = pos


def _record_required_gate_execution(gate_name: str) -> None:
    gate = str(gate_name or "").strip()
    if gate in REQUIRED_GATE_ORDER:
        _REQUIRED_GATE_EXECUTION_LOG.append(gate)


def _assert_required_gate_execution_order_or_exit() -> None:
    if _REQUIRED_GATE_EXECUTION_LOG != REQUIRED_GATE_ORDER:
        print(
            "ERROR gate_order_invalid "
            f"executed_required_gates={_REQUIRED_GATE_EXECUTION_LOG} required={REQUIRED_GATE_ORDER}",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _enforce_runtime_limits_for_run_or_exit(
    run_id: str,
    runtime_limits: dict[str, Any],
    feature_state: dict[str, Any],
) -> None:
    try:
        stats = enforce_runtime_limits_for_run(
            run_id,
            runtime_limits,
            feature_state,
        )
    except RuntimeError as exc:
        print(f"ERROR runtime_limits_enforcement_failed reason={exc}", file=sys.stderr)
        raise SystemExit(1)
    print(
        f"runtime_limits_enforced events_total={stats.get('events_total', 0)} "
        f"weak={stats.get('weak_events', 0)} "
        f"reconciliation_requests={stats.get('reconciliation_requests', 0)} "
        f"reconciliation_results={stats.get('reconciliation_results', 0)}"
    )


def _write_orchestrator_safe_decision_artifact(
    run_id: str,
    *,
    reason_code: str,
    safe_decision: str = "HOLD_NEED_DATA",
) -> Path:
    out_path = Path(f"data/agent_reports/{run_id}_orchestrator_safe_decision.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": "scripts/run_all.py",
        "decision": safe_decision,
        "normalized_decision": safe_decision,
        "status": "SAFE_STOP",
        "reason_code": reason_code,
        "blocked_by": [reason_code],
        "contract_version": "orchestrator_safe_decision.v1",
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out_path)
    return out_path


def _load_json_optional_with_integrity(path: Path) -> dict[str, Any] | None:
    try:
        return load_json_with_integrity(path)
    except Exception:
        return None


def _detect_provisional_fallback_state(run_id: str) -> dict[str, Any]:
    captain = _load_json_optional_with_integrity(captain_artifact_path(run_id)) or {}
    doctor = _load_json_optional_with_integrity(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
    commander = _load_json_optional_with_integrity(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}

    fallback_agents: list[str] = []
    fallback_reasons: dict[str, str] = {}
    fallback_tiers: dict[str, str] = {}

    cap_prov = captain.get("llm_provenance", {}) if isinstance(captain.get("llm_provenance"), dict) else {}
    cap_used_fallback = (
        bool(captain.get("provisional_local_fallback", False))
        or bool(captain.get("needs_cloud_reconciliation", False))
        or bool(cap_prov.get("needs_cloud_reconciliation", False))
    )
    if cap_used_fallback:
        fallback_agents.append("captain")
        fallback_reasons["captain"] = str(captain.get("fallback_reason") or cap_prov.get("fallback_reason") or "unknown")
        fallback_tiers["captain"] = str(captain.get("fallback_tier") or "deterministic")

    doc_prov = doctor.get("llm_provenance", {}) if isinstance(doctor.get("llm_provenance"), dict) else {}
    doc_hyp = doc_prov.get("hypothesis_generation", {}) if isinstance(doc_prov.get("hypothesis_generation"), dict) else {}
    doc_hsum = doc_prov.get("human_summary", {}) if isinstance(doc_prov.get("human_summary"), dict) else {}
    doc_used_fallback = (
        bool(doctor.get("provisional_local_fallback", False))
        or bool(doctor.get("needs_cloud_reconciliation", False))
        or bool(doc_hyp.get("needs_cloud_reconciliation", False))
        or bool(doc_hsum.get("needs_cloud_reconciliation", False))
        or str(doctor.get("model_used", "")).strip().lower() == "local_mock"
    )
    if doc_used_fallback:
        fallback_agents.append("doctor")
        fallback_reasons["doctor"] = str(
            doctor.get("fallback_reason")
            or doc_hyp.get("fallback_reason")
            or doc_hsum.get("fallback_reason")
            or "unknown"
        )
        fallback_tiers["doctor"] = str(doctor.get("fallback_tier") or "deterministic")

    cmd_prov = (
        commander.get("llm_decision_provenance", {})
        if isinstance(commander.get("llm_decision_provenance"), dict)
        else {}
    )
    cmd_used_fallback = (
        bool(commander.get("provisional_local_fallback", False))
        or bool(commander.get("needs_cloud_reconciliation", False))
        or bool(cmd_prov.get("needs_cloud_reconciliation", False))
        or str(commander.get("commander_model", "")).strip().lower() == "local_mock"
    )
    if cmd_used_fallback:
        fallback_agents.append("commander")
        fallback_reasons["commander"] = str(commander.get("fallback_reason") or cmd_prov.get("fallback_reason") or "unknown")
        fallback_tiers["commander"] = str(commander.get("fallback_tier") or "deterministic")

    fallback_agents = sorted(set(fallback_agents))
    return {
        "provisional_local_fallback": bool(fallback_agents),
        "needs_cloud_reconciliation": bool(fallback_agents),
        "fallback_agents": fallback_agents,
        "fallback_reasons": fallback_reasons,
        "fallback_tiers": fallback_tiers,
    }


def _write_reconciliation_job(run_id: str, state: dict[str, Any], reconciliation_policy: dict[str, Any]) -> Path:
    out_path = Path(f"data/reconciliation/{run_id}_reconciliation_job.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": "reconciliation_job_v1",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "PENDING",
        "batch_id": run_id,
        "provisional_local_fallback": bool(state.get("provisional_local_fallback", False)),
        "needs_cloud_reconciliation": bool(state.get("needs_cloud_reconciliation", False)),
        "fallback_agents": [str(x) for x in state.get("fallback_agents", []) if str(x).strip()],
        "fallback_reasons": (
            state.get("fallback_reasons")
            if isinstance(state.get("fallback_reasons"), dict)
            else {}
        ),
        "fallback_tiers": (
            state.get("fallback_tiers")
            if isinstance(state.get("fallback_tiers"), dict)
            else {}
        ),
        "required_actions": [
            "run_reconciliation_worker",
            "replay_cloud_llm_calls_for_fallback_agents",
            "verify_reconciliation_result_integrity",
        ],
        "policy_ref": str(RECONCILIATION_POLICY_PATH),
        "policy_version": str(reconciliation_policy.get("version", "")),
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out_path)
    return out_path


def _ensure_provisional_reconciliation_or_exit(
    *,
    run_id: str,
    log_file: Path,
    feature_state: dict[str, Any],
) -> None:
    policy = load_json_with_integrity(RECONCILIATION_POLICY_PATH)
    state = _detect_provisional_fallback_state(run_id)
    provisional_required = bool(state.get("provisional_local_fallback", False))
    if not provisional_required:
        return
    if bool(policy.get("provisional_requires_reconciliation", False)) is not True:
        print("ERROR reconciliation_policy invalid: provisional_requires_reconciliation=false", file=sys.stderr)
        raise SystemExit(1)
    if bool(policy.get("reconciliation_job_required", False)) is not True:
        print("ERROR reconciliation_policy invalid: reconciliation_job_required=false", file=sys.stderr)
        raise SystemExit(1)
    job_path = _write_reconciliation_job(run_id, state, policy)
    print(
        "reconciliation_job_created "
        f"path={job_path} fallback_agents={','.join(state.get('fallback_agents', [])) or 'none'}"
    )
    _run_step(
        _py(
            "scripts/run_reconciliation_worker.py",
            "--run-id",
            run_id,
            "--batch-id",
            run_id,
            "--backend",
            "groq",
            "--dry-run",
            "0",
            "--max-pending-hours",
            str(int(policy.get("max_pending_hours", 24) or 24)),
            "--out-json",
            f"data/reconciliation/{run_id}_reconciliation_worker.json",
        ),
        "run_reconciliation_worker",
        log_file,
    )
    runtime_state = str(feature_state.get("reconciliation_runtime", "NOT_IMPLEMENTED")).upper()
    if runtime_state not in {"NOT_IMPLEMENTED", "IMPLEMENTED"}:
        print("ERROR invalid feature_state reconciliation_runtime", file=sys.stderr)
        raise SystemExit(1)


def _enforce_retry_budget_before_llm_or_exit(
    run_id: str,
    retry_policy: dict[str, Any],
    *,
    step_name: str,
) -> None:
    status = get_retry_budget_status(run_id, retry_policy)
    if bool(status.get("allowed", False)):
        return
    reason = str(status.get("reason", "retry_policy_blocked"))
    reason_code = str(status.get("reason_code", reason) or reason)
    state = status.get("state") if isinstance(status.get("state"), dict) else {}
    write_retry_guard_report(
        run_id,
        status="FAIL",
        reason=f"{reason_code}:{step_name}",
        retry_policy=retry_policy,
        state=state,
    )
    safe_decision = str(status.get("safe_decision", "HOLD_NEED_DATA") or "HOLD_NEED_DATA")
    safe_artifact = _write_orchestrator_safe_decision_artifact(
        run_id,
        reason_code=f"retry_policy_blocked:{reason_code}:{step_name}",
        safe_decision=safe_decision,
    )
    print(
        f"ERROR retry_policy_blocked step={step_name} reason={reason_code} safe_decision={safe_decision} "
        f"safe_artifact={safe_artifact}",
        file=sys.stderr,
    )
    raise SystemExit(1)


def _run_llm_step_budgeted(
    *,
    run_id: str,
    retry_policy: dict[str, Any],
    cmd: list[str],
    step_name: str,
    log_file: Path,
    extra_env: dict[str, str] | None = None,
) -> None:
    def _stop_on_retry_state_integrity_error(reason_code: str) -> None:
        write_retry_guard_report(
            run_id,
            status="FAIL",
            reason=f"{reason_code}:{step_name}",
            retry_policy=retry_policy,
            state={"run_id": run_id},
        )
        safe_decision = str(retry_policy.get("safe_decision", "HOLD_NEED_DATA") or "HOLD_NEED_DATA")
        safe_artifact = _write_orchestrator_safe_decision_artifact(
            run_id,
            reason_code=f"retry_guard_failed:{reason_code}:{step_name}",
            safe_decision=safe_decision,
        )
        print(
            f"ERROR retry_guard_failed step={step_name} reason={reason_code} safe_decision={safe_decision} "
            f"safe_artifact={safe_artifact}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    _enforce_retry_budget_before_llm_or_exit(run_id, retry_policy, step_name=step_name)
    step_failed = False
    try:
        _run_step(cmd, step_name, log_file, extra_env)
    except SystemExit:
        step_failed = True

    if not step_failed:
        try:
            state = register_retry_outcome(run_id, retry_policy, success=True)
        except RuntimeError as exc:
            _stop_on_retry_state_integrity_error(str(exc) or "retry_state_integrity_error")
        write_retry_guard_report(
            run_id,
            status="PASS",
            reason=f"ok:{step_name}",
            retry_policy=retry_policy,
            state=state,
        )
        return

    try:
        state = register_retry_outcome(
            run_id,
            retry_policy,
            success=False,
            failure_reason=f"{step_name}_failed",
        )
    except RuntimeError as exc:
        _stop_on_retry_state_integrity_error(str(exc) or "retry_state_integrity_error")
    write_retry_guard_report(
        run_id,
        status="FAIL",
        reason=f"{step_name}_failed",
        retry_policy=retry_policy,
        state=state,
    )
    raise SystemExit(1)


def _print_core_agent_llm_authenticity(summary: dict[str, Any]) -> None:
    print(
        "core_agent_llm_authenticity "
        f"llm_path_reached_agents={summary.get('llm_path_reached_agents_count', 0)}/3 "
        f"real_llm_agents={summary.get('real_llm_agents_count', 0)}/3 "
        f"captain={int(bool(((summary.get('captain') or {}).get('real_llm'))))}/{int(bool(((summary.get('captain') or {}).get('llm_path_reached'))))} "
        f"doctor={int(bool(((summary.get('doctor') or {}).get('real_llm'))))}/{int(bool(((summary.get('doctor') or {}).get('llm_path_reached'))))} "
        f"commander={int(bool(((summary.get('commander') or {}).get('real_llm'))))}/{int(bool(((summary.get('commander') or {}).get('llm_path_reached'))))}"
    )


def _validate_core_llm_authenticity(args: argparse.Namespace) -> None:
    core_llm_auth = core_agent_llm_authenticity(args.run_id)
    _print_core_agent_llm_authenticity(core_llm_auth)
    if int(args.require_real_llm_core_agents) == 1 and int(core_llm_auth.get("real_llm_agents_count", 0)) < 3:
        print(
            "ERROR: core agents are not all core-accepted real LLM outputs (Captain/Doctor/Commander). "
            "See llm_path_reached_agents vs real_llm_agents counters.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _append_step_log(log_file: Path, step_name: str, result: subprocess.CompletedProcess[str]) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as f:
        f.write(f"\n===== BEGIN step={step_name} rc={result.returncode} =====\n")
        if result.stdout:
            f.write("[stdout]\n")
            safe_stdout = _redact_text(result.stdout)
            f.write(safe_stdout)
            if not safe_stdout.endswith("\n"):
                f.write("\n")
        if result.stderr:
            f.write("[stderr]\n")
            safe_stderr = _redact_text(result.stderr)
            f.write(safe_stderr)
            if not safe_stderr.endswith("\n"):
                f.write("\n")
        f.write(f"===== END step={step_name} =====\n")


def _print_verbose_tail(stdout_text: str, step_name: str) -> None:
    if os.getenv("DS_VERBOSE_CHILD_STDOUT", "0") != "1":
        return
    if not stdout_text:
        return
    lines = stdout_text.splitlines()[-VERBOSE_TAIL_LINES:]
    tail = "\n".join(lines)
    tail = _redact_text(tail)
    if len(tail) > MAX_VERBOSE_CHARS:
        tail = tail[-MAX_VERBOSE_CHARS:]
    if tail:
        print(f"TAIL step={step_name}")
        print(tail)


def _run_step(cmd: list[str], step_name: str, log_file: Path, extra_env: dict[str, str] | None = None) -> None:
    global _CTRL_FOUNDATION_EXECUTED_STEPS
    if _CTRL_FOUNDATION_ACTIVE:
        allowed = set(CTRL_FOUNDATION_ALLOWED_STEPS)
        if step_name not in allowed:
            print(
                "ERROR CTRL_FOUNDATION_SCOPE_VIOLATION "
                f"step={step_name} forbidden_in_ctrl_foundation_scope allowed={sorted(allowed)}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        _CTRL_FOUNDATION_EXECUTED_STEPS.append(step_name)
    child_env = os.environ.copy()
    if extra_env:
        child_env.update(extra_env)
    result = subprocess.run(cmd, capture_output=True, text=True, env=child_env)
    _append_step_log(log_file, step_name, result)
    if result.returncode != 0:
        print(f"ERROR step={step_name} (exit code {result.returncode}). See {log_file}", file=sys.stderr)
        raise SystemExit(1)
    print(f"OK step={step_name}")
    _print_verbose_tail(result.stdout, step_name)


def _init_or_load_paired_registry(*, run_id: str, run_id_ctrl: str, experiment_id: str, mode: str) -> dict[str, Any] | None:
    if str(mode).strip().lower() != "paired":
        return None
    try:
        _ = paired_registry_path(experiment_id, run_id)
    except Exception as exc:
        raise SystemExit(f"PAIRED_REGISTRY_KEY_INVALID: {exc}")
    if normalize_registry_key(run_id_ctrl) == normalize_registry_key(run_id):
        raise SystemExit("PAIRED_RUN_ID_COLLISION: run_id_ctrl must not equal parent run_id")
    try:
        existing = load_registry_for_run(run_id, required=False)
    except Exception as exc:
        raise SystemExit(f"PAIRED_REGISTRY_KEY_INVALID: {exc}")
    if isinstance(existing, dict):
        return existing
    payload = {
        "version": "paired_registry_v1",
        "mode": "paired",
        "experiment_id": experiment_id,
        "parent_run_id": run_id,
        "ctrl_run_id": run_id_ctrl,
        "treatment_run_id": run_id,
        "paired_status": PairedRunStatus.COMPLETE.value,
        "error_code": "NONE",
        "reason": "paired_initialized",
        "paired_context_ref": _artifact_ref(Path(f"data/agent_context/{run_id}_paired_experiment_v2.json")),
        "audit_ref": "",
        "status_history": [],
    }
    save_registry(payload)
    return payload


def _save_paired_registry_update(payload: dict[str, Any]) -> dict[str, Any]:
    out_path = save_registry(payload)
    updated = load_json_with_integrity(out_path)
    return updated if isinstance(updated, dict) else payload


def _mark_ctrl_foundation_failed(
    registry_payload: dict[str, Any] | None,
    *,
    reason: str,
    audit_ref: str = "",
) -> dict[str, Any] | None:
    if not isinstance(registry_payload, dict):
        return None
    payload = apply_status_transition(
        registry_payload,
        to_status=PairedRunStatus.CTRL_FAILED.value,
        reason=str(reason or "ctrl_foundation_failed"),
        error_code="CTRL_FOUNDATION_SCOPE_VIOLATION",
    )
    if audit_ref:
        payload["audit_ref"] = audit_ref
    return _save_paired_registry_update(payload)


def _promote_partial_from_treatment_failure(
    registry_payload: dict[str, Any] | None,
    *,
    reason: str,
) -> dict[str, Any] | None:
    if not isinstance(registry_payload, dict):
        return None
    payload = mark_treatment_failed_then_partial(registry_payload, reason=reason)
    return _save_paired_registry_update(payload)


def _artifact_ref(path: Path) -> str:
    return f"artifact:{str(path)}"


def _write_paired_experiment_context(
    *,
    run_id: str,
    experiment_id: str,
    ctrl_run_id: str,
    treatment_run_id: str,
    paired_status: str,
    audit_ref: str = "",
    partial_reason: str = "",
    failure_reason: str = "",
    failed_step: str = "",
    decision_ceiling: str = "",
) -> Path:
    out = Path(f"data/agent_context/{run_id}_paired_experiment_v2.json")
    status = str(paired_status or "").strip().upper()
    payload: dict[str, Any] = {
        "version": "paired_experiment_v2",
        "run_id": run_id,
        "experiment_id": experiment_id,
        "ctrl_run_id": ctrl_run_id,
        "treatment_run_id": treatment_run_id,
        "paired_status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if status == PairedRunStatus.COMPLETE.value:
        payload["layer1"] = {
            "ctrl_metrics_snapshot_ref": _artifact_ref(Path(f"data/metrics_snapshots/{ctrl_run_id}.json")),
            "treatment_metrics_snapshot_ref": _artifact_ref(Path(f"data/metrics_snapshots/{treatment_run_id}.json")),
            "ctrl_foundation_audit_ref": audit_ref,
        }
        payload["layer2"] = {
            "ctrl_ab_ref": _artifact_ref(Path(f"data/ab_reports/{ctrl_run_id}_{experiment_id}_ab.json")),
            "treatment_ab_ref": _artifact_ref(Path(f"data/ab_reports/{treatment_run_id}_{experiment_id}_ab.json")),
        }
        payload["merger_artifact_ref"] = _artifact_ref(out)
    elif status in {PairedRunStatus.PARTIAL.value, PairedRunStatus.TREATMENT_FAILED.value}:
        payload["partial_reason"] = str(partial_reason or "treatment_pipeline_incomplete")
        payload["decision_ceiling"] = "HOLD_NEED_DATA"
        payload["failed_step"] = str(failed_step or "treatment_pipeline")
    elif status == PairedRunStatus.CTRL_FAILED.value:
        payload["failure_reason"] = str(failure_reason or "ctrl_foundation_failed")
        payload["failed_step"] = str(failed_step or "ctrl_foundation")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out)
    return out


def _sync_paired_registry_refs(
    registry_payload: dict[str, Any] | None,
    *,
    status: str,
    error_code: str,
    reason: str,
    audit_ref: str = "",
    paired_context_ref: str = "",
) -> dict[str, Any] | None:
    if not isinstance(registry_payload, dict):
        return None
    payload = apply_status_transition(
        registry_payload,
        to_status=str(status or registry_payload.get("paired_status", "")).strip().upper(),
        reason=str(reason or registry_payload.get("reason", "paired_runtime_update")).strip(),
        error_code=str(error_code or registry_payload.get("error_code", "NONE")).strip().upper(),
    )
    if audit_ref:
        payload["audit_ref"] = audit_ref
    if paired_context_ref:
        payload["paired_context_ref"] = paired_context_ref
    return _save_paired_registry_update(payload)


def _run_ctrl_foundation_only(
    *,
    args: argparse.Namespace,
    exp_id: str,
    run_id_ctrl: str,
    log_file: Path,
    app_engine: Any,
    ctrl_variant: dict[str, Any] | None = None,
) -> Path:
    global _CTRL_FOUNDATION_ACTIVE
    global _CTRL_FOUNDATION_EXECUTED_STEPS
    ctrl_args = argparse.Namespace(**vars(args))
    ctrl_args.run_id = run_id_ctrl
    if isinstance(ctrl_variant, dict):
        if str(ctrl_variant.get("mode_tag", "")).strip():
            ctrl_args.mode_tag = str(ctrl_variant.get("mode_tag"))
        if ctrl_variant.get("horizon_days") is not None:
            try:
                ctrl_args.horizon_days = int(ctrl_variant.get("horizon_days"))
            except Exception:
                pass
        if ctrl_variant.get("seed") is not None:
            try:
                ctrl_args.seed = int(ctrl_variant.get("seed"))
            except Exception:
                pass
        overrides = ctrl_variant.get("overrides")
        if isinstance(overrides, dict):
            for key, value in overrides.items():
                key_str = str(key)
                if hasattr(ctrl_args, key_str):
                    setattr(ctrl_args, key_str, value)
    _CTRL_FOUNDATION_EXECUTED_STEPS = []
    _CTRL_FOUNDATION_ACTIVE = True
    audit_path = Path(f"data/agent_quality/{run_id_ctrl}_ctrl_foundation_audit.json")
    try:
        _run_simulation_and_foundation_steps(
            args=ctrl_args,
            exp_id=exp_id,
            log_file=log_file,
            app_engine=app_engine,
        )
        _run_metrics_and_ab_steps(
            args=ctrl_args,
            exp_id=exp_id,
            log_file=log_file,
        )
        executed = list(_CTRL_FOUNDATION_EXECUTED_STEPS)
        payload = {
            "version": "ctrl_foundation_audit_v1",
            "run_id": run_id_ctrl,
            "status": "PASS",
            "error_code": "NONE",
            "executed_steps": executed,
            "allowed_steps": list(CTRL_FOUNDATION_ALLOWED_STEPS),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(audit_path)
        return audit_path
    except SystemExit:
        payload = {
            "version": "ctrl_foundation_audit_v1",
            "run_id": run_id_ctrl,
            "status": "FAIL",
            "error_code": "CTRL_FOUNDATION_SCOPE_VIOLATION",
            "executed_steps": list(_CTRL_FOUNDATION_EXECUTED_STEPS),
            "allowed_steps": list(CTRL_FOUNDATION_ALLOWED_STEPS),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(audit_path)
        raise
    finally:
        _CTRL_FOUNDATION_ACTIVE = False


def _enforce_forced_ceiling_on_commander(run_id: str, *, reason: str, paired_status: str) -> None:
    path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
    if not path.exists():
        return
    try:
        payload = load_json_with_integrity(path)
    except Exception:
        return
    decision = str(payload.get("normalized_decision", payload.get("decision", ""))).upper()
    if decision not in set(PAIRED_AGGRESSIVE_DECISIONS):
        return
    payload["decision"] = "HOLD_NEED_DATA"
    payload["normalized_decision"] = "HOLD_NEED_DATA"
    blocked_by = payload.get("blocked_by")
    if not isinstance(blocked_by, list):
        blocked_by = []
    marker = f"paired_partial_forced_ceiling:{reason}"
    if marker not in blocked_by:
        blocked_by.append(marker)
    payload["blocked_by"] = blocked_by
    payload["paired_status"] = str(paired_status or "")
    payload["forced_decision_ceiling"] = "HOLD_NEED_DATA"
    payload["forced_decision_reason"] = reason
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(path)


def _enforce_paired_partial_ceiling_or_exit(
    *,
    run_id: str,
    paired_mode: bool,
    paired_registry_payload: dict[str, Any] | None,
) -> None:
    if not paired_mode or not isinstance(paired_registry_payload, dict):
        return
    status = effective_paired_status(str(paired_registry_payload.get("paired_status", "")))
    if not is_partial_like(status):
        return
    commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
    commander_payload = _load_json_optional_with_integrity(commander_path) or {}
    decision = str(commander_payload.get("normalized_decision", commander_payload.get("decision", ""))).strip().upper()
    if decision in {"GO", "RUN_AB", "ROLLOUT_CANDIDATE"}:
        _write_orchestrator_safe_decision_artifact(
            run_id,
            reason_code="PAIRED_PARTIAL_CEILING_VIOLATION",
            safe_decision="HOLD_NEED_DATA",
        )
        print(
            "ERROR PAIRED_PARTIAL_CEILING_VIOLATION "
            f"paired_status={status} decision={decision}",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _write_gate_result_safe(
    run_id: str,
    *,
    gate_name: str,
    status: str,
    error_code: str,
    blocked_by: list[str] | None = None,
    required_actions: list[str] | None = None,
    details: dict[str, Any] | None = None,
    critical: bool = False,
) -> None:
    try:
        write_gate_result(
            run_id,
            gate_name=gate_name,
            status=status,
            error_code=error_code,
            blocked_by=blocked_by or [],
            required_actions=required_actions or [],
            details=details or {},
        )
    except Exception as exc:
        if critical:
            print(f"ERROR failed to write gate_result gate={gate_name} err={exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"WARN failed to write gate_result gate={gate_name} err={exc}", file=sys.stderr)


def _run_gate_step(
    *,
    run_id: str,
    gate_name: str,
    step_name: str,
    cmd: list[str],
    log_file: Path,
    error_code_on_fail: str = "CONTEXT_CONFLICT",
    extra_env: dict[str, str] | None = None,
    fail_closed: bool = True,
    critical_gate: bool = True,
    enabled: bool = True,
) -> bool:
    if not enabled:
        return False
    _record_required_gate_execution(gate_name)
    try:
        _run_step(cmd, step_name, log_file, extra_env)
    except SystemExit:
        _write_gate_result_safe(
            run_id,
            gate_name=gate_name,
            status="FAIL",
            error_code=error_code_on_fail,
            blocked_by=[f"{gate_name}_failed"],
            required_actions=[f"fix_{gate_name}_inputs_and_rerun"],
            critical=critical_gate,
        )
        if fail_closed:
            raise
        return False
    _write_gate_result_safe(
        run_id,
        gate_name=gate_name,
        status="PASS",
        error_code="NONE",
        critical=critical_gate,
    )
    return True


def _py(script_path: str, *args: Any) -> list[str]:
    cmd = ["python3", script_path]
    for a in args:
        cmd.append(str(a))
    return cmd


def _with_domain_template(cmd: list[str], args: argparse.Namespace) -> list[str]:
    template_path = str(getattr(args, "domain_template", "") or "").strip()
    if not template_path:
        return cmd
    return [*cmd, "--domain-template", template_path]


def _try_run_step(
    cmd: list[str],
    step_name: str,
    log_file: Path,
    *,
    extra_env: dict[str, str] | None = None,
    enabled: bool = True,
    success_note: str | None = None,
    fail_closed: bool = False,
) -> bool:
    if not enabled:
        return False
    try:
        _run_step(cmd, step_name, log_file, extra_env)
        if success_note:
            print(success_note)
        return True
    except SystemExit:
        if fail_closed:
            print(f"ERROR step={step_name} failed (fail-closed). See {log_file}", file=sys.stderr)
            raise SystemExit(1)
        print(f"WARN step={step_name} failed. See {log_file}")
        return False


def _run_py_step_specs(
    *,
    run_id: str,
    log_file: Path,
    step_specs: list[dict[str, Any]],
) -> None:
    for spec in step_specs:
        step_name = str(spec["step_name"])
        script_path = str(spec["script"])
        extra_args = spec.get("args", [])
        args_list = extra_args if isinstance(extra_args, list) else [extra_args]
        include_run_id = bool(spec.get("include_run_id", True))
        enabled = bool(spec.get("enabled", True))
        success_note = spec.get("success_note")
        fail_closed = bool(spec.get("fail_closed", False))
        base_args: list[Any] = ["--run-id", run_id] if include_run_id else []
        _try_run_step(
            _py(script_path, *base_args, *args_list),
            step_name,
            log_file,
            enabled=enabled,
            success_note=str(success_note) if success_note else None,
            fail_closed=fail_closed,
        )


def _run_raw_reload_if_requested(
    *,
    args: argparse.Namespace,
    log_file: Path,
    loader_dsn: str,
) -> None:
    if not args.reload_raw:
        return
    loader_engine = _engine(loader_dsn)
    _check_db_identity(loader_engine, EXPECTED_DB, EXPECTED_LOADER_USER)
    load_cmd = [
        "python3",
        "scripts/load_raw.py",
        "--raw-dir",
        str(args.raw_dir),
    ]
    if args.allow_truncate_raw == 1:
        load_cmd.extend(["--allow-truncate-raw", "1"])
    _run_step(
        load_cmd,
        "load_raw",
        log_file,
        _loader_db_env(),
    )


def _read_valid_orders_count(app_engine: Any, run_id: str, *, clean_layer_enabled: bool) -> int | str:
    if not clean_layer_enabled:
        return "SKIP"
    with app_engine.begin() as conn:
        return conn.execute(
            text("SELECT COUNT(*) FROM step1.vw_valid_orders WHERE run_id = :r"),
            {"r": run_id},
        ).scalar() or 0


def _check_db_identity(engine, expected_db: str, expected_user: str) -> None:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT current_database() AS db, current_user AS usr
                """
            )
        ).mappings().first()
    if row is None:
        raise SystemExit("ERROR: could not verify DB identity")
    if row["db"] != expected_db:
        raise SystemExit("ERROR: unexpected database")
    if row["usr"] != expected_user:
        raise SystemExit("ERROR: unexpected database role")
    print(f"db identity ok: db={row['db']} user={row['usr']}")


def _check_views(engine) -> tuple[bool, list[str]]:
    required = [
        "step1.vw_valid_orders",
        "step1.vw_valid_order_items",
        "step1.vw_valid_customer_daily",
    ]
    missing: list[str] = []
    with engine.begin() as conn:
        for name in required:
            exists = conn.execute(text("SELECT to_regclass(:n)"), {"n": name}).scalar()
            if exists is None:
                missing.append(name)
    return (len(missing) == 0, missing)


def _missing_columns(conn, schema_name: str, table_name: str, required: tuple[str, ...]) -> list[str]:
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
    existing = {str(r[0]) for r in rows}
    return [c for c in required if c not in existing]


def _preflight_validate_goal1_schema_contract_or_exit(engine) -> None:
    schema_name = "step1"
    missing_specs: list[tuple[str, list[str]]] = []
    with engine.begin() as conn:
        for table_name, required_cols in _GOAL1_CONTRACT_REQUIRED_COLUMNS.items():
            fq_name = f"{schema_name}.{table_name}"
            exists = conn.execute(text("SELECT to_regclass(:n)"), {"n": fq_name}).scalar()
            if exists is None:
                missing_specs.append((fq_name, ["<table_missing>"]))
                continue
            missing = _missing_columns(conn, schema_name, table_name, required_cols)
            if missing:
                missing_specs.append((fq_name, missing))
    if missing_specs:
        details = "; ".join([f"{name}:{','.join(cols)}" for name, cols in missing_specs])
        print(
            "ERROR schema_preflight_failed "
            f"goal1_contract_missing={details} "
            "required_for=goal1_batch_join_coverage",
            file=sys.stderr,
        )
        print(
            "ACTION: apply migration "
            "'psql -d darkstore -f v1/sql/migrations/008_step1_goal1_contract_upgrade.sql' "
            "with admin role before running run_all.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print("schema_preflight_ok goal1_contract=PASS")


def _count_json_sidecar_pairs(root: Path) -> int:
    if not root.exists():
        return 0
    count = 0
    for payload in root.glob("*.json"):
        sidecar = payload.with_suffix(".json.sha256")
        if sidecar.exists():
            count += 1
    return count


def _preflight_validate_locked_historical_corpus_or_exit() -> None:
    pairs = _count_json_sidecar_pairs(_LOCKED_HISTORICAL_DIR)
    if pairs < _LOCKED_HISTORICAL_MIN_PAIRS:
        print(
            "ERROR historical_corpus_preflight_failed "
            f"locked_dir={_LOCKED_HISTORICAL_DIR} json_sidecar_pairs={pairs} "
            f"required_min={_LOCKED_HISTORICAL_MIN_PAIRS}",
            file=sys.stderr,
        )
        print(
            "ACTION: restore canonical historical snapshots into "
            "'not_delete_historical_patterns/metrics_snapshots' with .sha256 sidecars.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(f"historical_corpus_preflight_ok locked_pairs={pairs}")


def _run_simulation_and_foundation_steps(
    *,
    args: argparse.Namespace,
    exp_id: str,
    log_file: Path,
    app_engine: Any,
) -> tuple[bool, list[str]]:
    sim_cmd = [
        "python3",
        "scripts/run_simulation_v1.py",
        "--run-id",
        args.run_id,
        "--enable-customer-dynamics",
        str(args.enable_customer_dynamics),
        "--mode-tag",
        args.mode_tag,
        "--horizon-days",
        str(args.horizon_days),
        "--seed",
        str(args.seed),
        "--allow-overwrite-run",
        str(args.allow_overwrite_run),
        "--overwrite-reason",
        args.overwrite_reason,
        "--experiment-id",
        exp_id,
        "--experiment-unit",
        args.experiment_unit,
        "--experiment-treat-pct",
        str(args.experiment_treat_pct),
        "--experiment-salt",
        str(args.experiment_salt),
        "--enable-supply-realism",
        str(args.enable_supply_realism),
        "--enable-ops-noise",
        str(args.enable_ops_noise),
        "--enable-demand-shocks",
        str(args.enable_demand_shocks),
        "--enable-competitor-prices",
        str(args.enable_competitor_prices),
        "--perishable-remove-buffer-days",
        str(args.perishable_remove_buffer_days),
    ]
    _run_step(sim_cmd, "run_simulation", log_file, _app_db_env())
    _run_step(["python3", "scripts/run_dq.py", "--run-id", args.run_id], "run_dq", log_file, _app_db_env())

    views_ready, missing_views = _check_views(app_engine)
    clean_layer_enabled = views_ready
    if not views_ready:
        print("NOTE: views missing -> clean layer disabled. Run admin setup:")
        print(f"python3 scripts/admin_setup_views.py --pgservice {ADMIN_SERVICE} --expected-db {EXPECTED_DB}")
        print("SKIP step=clean_layer_metrics reason=views_missing")
        if _strict_runtime():
            raise SystemExit(1)
    return clean_layer_enabled, missing_views


def _run_metrics_and_ab_steps(
    *,
    args: argparse.Namespace,
    exp_id: str,
    log_file: Path,
) -> None:
    _run_step(
        _with_domain_template(["python3", "scripts/make_metrics_snapshot_v1.py", "--run-id", args.run_id], args),
        "make_metrics_snapshot_v1",
        log_file,
        _app_db_env(),
    )
    _try_run_step(
        ["python3", "scripts/run_synthetic_bias_audit.py", "--run-id", args.run_id],
        "run_synthetic_bias_audit",
        log_file,
    )
    if not exp_id:
        return
    _run_step(
        [
            "python3",
            "scripts/run_ab_preflight.py",
            "--run-id",
            args.run_id,
            "--experiment-id",
            exp_id,
            "--pgservice",
            APP_SERVICE,
        ],
        "run_ab_preflight",
        log_file,
        _app_db_env(),
    )
    _run_step(
        [
            "python3",
            "scripts/run_ab_analysis.py",
            "--run-id",
            args.run_id,
            "--experiment-id",
            exp_id,
            "--pgservice",
            APP_SERVICE,
            "--primary-metric",
            args.ab_primary_metric,
            "--bootstrap-iters",
            str(args.ab_bootstrap_iters),
            "--allow-assignment-recovery",
            str(args.allow_assignment_recovery),
        ],
        "run_ab_analysis",
        log_file,
        _app_db_env(),
    )


def _run_core_agents_and_proof_steps(
    *,
    args: argparse.Namespace,
    exp_id: str,
    log_file: Path,
    llm_env: dict[str, str] | None,
    retry_policy: dict[str, Any],
    hypothesis_review_flag: int = 0,
    paired_mode: bool = False,
    paired_status: str = "",
    paired_registry_payload: dict[str, Any] | None = None,
) -> None:
    try:
        _run_llm_step_budgeted(
            run_id=args.run_id,
            retry_policy=retry_policy,
            cmd=_with_domain_template(
                ["python3", "scripts/run_captain_sanity_llm.py", "--run-id", args.run_id, "--backend", args.backend],
                args,
            ),
            step_name="run_captain_sanity_llm",
            log_file=log_file,
            extra_env=llm_env,
        )
    except SystemExit:
        _write_gate_result_safe(
            args.run_id,
            gate_name="captain",
            status="FAIL",
            error_code="CONTEXT_CONFLICT",
            blocked_by=["captain_failed"],
            required_actions=["fix_captain_inputs_and_rerun"],
            critical=True,
        )
        raise
    _write_gate_result_safe(args.run_id, gate_name="captain", status="PASS", error_code="NONE", critical=True)

    _run_gate_step(
        run_id=args.run_id,
        gate_name="context_frame",
        step_name="run_context_frame",
        cmd=_py("scripts/run_context_frame.py", "--run-id", args.run_id),
        log_file=log_file,
        error_code_on_fail="CONTEXT_CONFLICT",
    )
    _run_gate_step(
        run_id=args.run_id,
        gate_name="historical_retrieval_gate",
        step_name="run_historical_retrieval_gate",
        cmd=_py("scripts/run_historical_retrieval_gate.py", "--run-id", args.run_id),
        log_file=log_file,
        error_code_on_fail="HISTORICAL_CONTEXT_MISSING",
    )

    try:
        control_run_id = ""
        if paired_mode and isinstance(paired_registry_payload, dict):
            control_run_id = str(paired_registry_payload.get("ctrl_run_id", "")).strip()
        doctor_cmd = [
            "python3",
            "scripts/run_doctor_variance.py",
            "--run-id",
            args.run_id,
            "--backend",
            args.backend,
            "--enable-deepseek-doctor",
            str(args.enable_deepseek_doctor),
            "--enable-react-doctor",
            str(args.enable_react_doctor),
            "--react-max-steps",
            str(args.react_max_steps),
            "--react-timeout-sec",
            str(args.react_timeout_sec),
        ]
        if control_run_id:
            doctor_cmd.extend(["--control-run-id", control_run_id])
        _run_llm_step_budgeted(
            run_id=args.run_id,
            retry_policy=retry_policy,
            cmd=_with_domain_template(doctor_cmd, args),
            step_name="run_doctor_variance",
            log_file=log_file,
            extra_env=llm_env,
        )
    except SystemExit:
        _write_gate_result_safe(
            args.run_id,
            gate_name="doctor",
            status="FAIL",
            error_code="CONTEXT_CONFLICT",
            blocked_by=["doctor_failed"],
            required_actions=["fix_doctor_inputs_and_rerun"],
            critical=True,
        )
        raise
    _write_gate_result_safe(args.run_id, gate_name="doctor", status="PASS", error_code="NONE", critical=True)
    _record_required_gate_execution("doctor")
    _run_gate_step(
        run_id=args.run_id,
        gate_name="handoff_contract_guard",
        step_name="run_handoff_contract_guard",
        cmd=_py("scripts/run_handoff_contract_guard.py", "--run-id", args.run_id),
        log_file=log_file,
        error_code_on_fail="CONTEXT_CONFLICT",
    )
    _run_gate_step(
        run_id=args.run_id,
        gate_name="experiment_duration_gate",
        step_name="run_experiment_duration_gate",
        cmd=_py(
            "scripts/run_experiment_duration_gate.py",
            "--run-id",
            args.run_id,
            "--experiment-id",
            exp_id,
        ),
        log_file=log_file,
        error_code_on_fail="EXPERIMENT_DURATION_INSUFFICIENT",
    )

    anti_goodhart_cmd = ["python3", "scripts/run_anti_goodhart_verdict.py", "--run-id", args.run_id]
    if exp_id:
        anti_goodhart_cmd.extend(["--experiment-id", exp_id])
    _record_required_gate_execution("anti_goodhart_sot")
    anti_goodhart_partial_override = False
    try:
        _run_step(anti_goodhart_cmd, "run_anti_goodhart_verdict", log_file)
    except SystemExit:
        gate_payload: dict[str, Any] | None = None
        try:
            gate_payload = load_json_with_integrity(gate_result_path(args.run_id, "anti_goodhart_sot"))
        except Exception:
            gate_payload = None
        gate_code = str((gate_payload or {}).get("error_code", "")).strip().upper()
        allow_partial_override = False
        effective_status = str(paired_status or "").strip().upper()
        if paired_mode and gate_code == "AB_ARTIFACT_REQUIRED":
            if effective_status in {PairedRunStatus.TREATMENT_FAILED.value, PairedRunStatus.PARTIAL.value}:
                allow_partial_override = True
            elif effective_status == PairedRunStatus.COMPLETE.value and isinstance(paired_registry_payload, dict):
                paired_registry_payload = _promote_partial_from_treatment_failure(
                    paired_registry_payload,
                    reason="treatment_failed_before_anti_goodhart_ab_required",
                )
                paired_status = str((paired_registry_payload or {}).get("paired_status", "")).strip().upper() or "PARTIAL"
                allow_partial_override = True
        if allow_partial_override and gate_code == "AB_ARTIFACT_REQUIRED":
            anti_goodhart_partial_override = True
            ctrl_run_id = str((paired_registry_payload or {}).get("ctrl_run_id", "")).strip() if isinstance(
                paired_registry_payload, dict
            ) else ""
            partial_ctx = _write_paired_experiment_context(
                run_id=args.run_id,
                experiment_id=exp_id,
                ctrl_run_id=ctrl_run_id or f"{args.run_id}_ctrl",
                treatment_run_id=args.run_id,
                paired_status=PairedRunStatus.PARTIAL.value,
                partial_reason="anti_goodhart_missing_ab_artifact",
                failed_step="anti_goodhart_sot",
                decision_ceiling="HOLD_NEED_DATA",
            )
            paired_registry_payload = _sync_paired_registry_refs(
                paired_registry_payload,
                status=PairedRunStatus.PARTIAL.value,
                error_code="AB_ARTIFACT_REQUIRED",
                reason="anti_goodhart_missing_ab_artifact",
                paired_context_ref=_artifact_ref(partial_ctx),
            )
            _write_gate_result_safe(
                args.run_id,
                gate_name="anti_goodhart_sot",
                status="PASS",
                error_code="NONE",
                blocked_by=[],
                required_actions=["enforce_forced_ceiling_hold_need_data"],
                details={
                    "paired_override": True,
                    "paired_status": paired_status or "PARTIAL",
                    "forced_ceiling": "HOLD_NEED_DATA",
                    "original_error_code": "AB_ARTIFACT_REQUIRED",
                },
                critical=True,
            )
            print(
                "WARN anti_goodhart override applied: paired partial mode + AB_ARTIFACT_REQUIRED -> continue with forced ceiling"
            )
        else:
            raise

    evaluator_cmd = ["python3", "scripts/run_experiment_evaluator.py", "--run-id", args.run_id]
    if exp_id:
        evaluator_cmd.extend(["--experiment-id", exp_id])
    evaluator_cmd = _with_domain_template(evaluator_cmd, args)
    _run_gate_step(
        run_id=args.run_id,
        gate_name="evaluator",
        step_name="run_experiment_evaluator",
        cmd=evaluator_cmd,
        log_file=log_file,
        error_code_on_fail="CONTEXT_CONFLICT",
    )

    if exp_id:
        _try_run_step(
            [
                "python3",
                "scripts/build_cohort_evidence_pack.py",
                "--run-id",
                args.run_id,
                "--experiment-id",
                exp_id,
                "--pgservice",
                APP_SERVICE,
            ],
            "build_cohort_evidence_pack",
            log_file,
            extra_env=_app_db_env(),
        )

    try:
        _run_llm_step_budgeted(
            run_id=args.run_id,
            retry_policy=retry_policy,
            cmd=_with_domain_template(
                [
                    "python3",
                    "scripts/run_commander_priority.py",
                    "--run-id",
                    args.run_id,
                    "--backend",
                    args.backend,
                    "--experiment-id",
                    exp_id,
                    "--enable-react-commander",
                    str(args.enable_react_commander),
                    "--react-max-steps",
                    str(args.react_commander_max_steps),
                    "--enable-hypothesis-review-v1",
                    str(int(hypothesis_review_flag)),
                ],
                args,
            ),
            step_name="run_commander_priority",
            log_file=log_file,
            extra_env=llm_env,
        )
    except SystemExit:
        _write_gate_result_safe(
            args.run_id,
            gate_name="commander",
            status="FAIL",
            error_code="CONTEXT_CONFLICT",
            blocked_by=["commander_failed"],
            required_actions=["fix_commander_inputs_and_rerun"],
            critical=True,
        )
        raise
    _write_gate_result_safe(args.run_id, gate_name="commander", status="PASS", error_code="NONE", critical=True)
    _record_required_gate_execution("commander")
    if anti_goodhart_partial_override or bool(paired_mode and is_partial_like(paired_status)):
        paired_status_forced = str(paired_status or "").strip().upper()
        if not is_partial_like(paired_status_forced):
            paired_status_forced = PairedRunStatus.PARTIAL.value
        _enforce_forced_ceiling_on_commander(
            args.run_id,
            reason="paired_partial_ab_artifact_required",
            paired_status=paired_status_forced,
        )
    _run_gate_step(
        run_id=args.run_id,
        gate_name="historical_retrieval_conformance_gate",
        step_name="run_historical_retrieval_conformance_gate",
        cmd=_py("scripts/run_historical_retrieval_conformance_gate.py", "--run-id", args.run_id),
        log_file=log_file,
        error_code_on_fail="HISTORICAL_CONTEXT_UNUSED",
    )

    _try_run_step(_py("scripts/build_action_trace.py", "--run-id", args.run_id), "build_action_trace", log_file)
    _run_step(_py("scripts/build_evidence_pack.py", "--run-id", args.run_id), "build_evidence_pack", log_file)


def _run_core_proof_path(
    *,
    args: argparse.Namespace,
    exp_id: str,
    log_file: Path,
    llm_env: dict[str, str] | None,
    app_engine: Any,
    runtime_limits: dict[str, Any],
    feature_state: dict[str, Any],
    retry_policy: dict[str, Any],
    hypothesis_review_flag: int = 0,
    paired_mode: bool = False,
    paired_status: str = "",
    paired_registry_payload: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    clean_layer_enabled, missing_views = _run_simulation_and_foundation_steps(
        args=args,
        exp_id=exp_id,
        log_file=log_file,
        app_engine=app_engine,
    )
    _enforce_runtime_limits_for_run_or_exit(args.run_id, runtime_limits, feature_state)
    _run_metrics_and_ab_steps(args=args, exp_id=exp_id, log_file=log_file)
    _enforce_runtime_limits_for_run_or_exit(args.run_id, runtime_limits, feature_state)
    _run_core_agents_and_proof_steps(
        args=args,
        exp_id=exp_id,
        log_file=log_file,
        llm_env=llm_env,
        retry_policy=retry_policy,
        hypothesis_review_flag=hypothesis_review_flag,
        paired_mode=paired_mode,
        paired_status=paired_status,
        paired_registry_payload=paired_registry_payload,
    )
    return clean_layer_enabled, missing_views


def _run_transparency_tail(
    *,
    args: argparse.Namespace,
    exp_id: str,
    log_file: Path,
    llm_env: dict[str, str] | None,
    lightweight: bool,
    retry_policy: dict[str, Any],
    hypothesis_review_flag: int = 0,
) -> None:
    _run_py_step_specs(
        run_id=args.run_id,
        log_file=log_file,
        step_specs=[
            {"step_name": "run_narrative_analyst", "script": "scripts/run_narrative_analyst.py"},
            {"step_name": "validate_narrative_grounding", "script": "scripts/validate_narrative_grounding.py"},
            {"step_name": "build_vector_quality_signals", "script": "scripts/build_vector_quality_signals.py"},
        ],
    )

    if not lightweight:
        _run_llm_step_budgeted(
            run_id=args.run_id,
            retry_policy=retry_policy,
            cmd=_with_domain_template(
                _py(
                    "scripts/run_commander_priority.py",
                    "--run-id",
                    args.run_id,
                    "--backend",
                    args.backend,
                    "--experiment-id",
                    exp_id,
                    "--enable-hypothesis-review-v1",
                    str(int(hypothesis_review_flag)),
                ),
                args,
            ),
            step_name="refresh_commander_approvals",
            log_file=log_file,
            extra_env=llm_env,
        )
    _run_py_step_specs(
        run_id=args.run_id,
        log_file=log_file,
        step_specs=[
            {"step_name": "eval_agents_v2", "script": "scripts/eval_agents_v2.py", "enabled": not lightweight},
        ],
    )


def _run_security_and_reports_tail(
    *,
    args: argparse.Namespace,
    log_file: Path,
) -> list[str]:
    security_cmd = [
        "python3",
        "scripts/run_security_check.py",
        "--run-id",
        args.run_id,
        "--pgservice",
        APP_SERVICE,
        "--expected-db",
        EXPECTED_DB,
        "--out-json",
        str(security_report_json(args.run_id)),
    ]
    security_cmd.append("--strict")
    _run_step(security_cmd, "run_security_check", log_file)
    security_report = security_report_json(args.run_id)
    if security_report.exists():
        try:
            security_payload = json.loads(security_report.read_text(encoding="utf-8"))
            print(
                f"security_policy_passed={int(bool(security_payload.get('passed', False)))} "
                f"violations={len(security_payload.get('violations', []))}"
            )
        except Exception:
            print("security_policy_passed=unknown")

    build_reports_cmd = _py("scripts/build_reports.py", "--run-id", args.run_id)
    _try_run_step(
        build_reports_cmd,
        "build_reports",
        log_file,
        success_note=f"Report generated at reports/L1_ops/{args.run_id}/",
    )
    return build_reports_cmd


def _run_eval_publish_tail(
    *,
    args: argparse.Namespace,
    log_file: Path,
    lightweight: bool,
    build_reports_cmd: list[str],
    security_profile: dict[str, Any],
    feature_state: dict[str, Any],
) -> None:
    _run_py_step_specs(
        run_id=args.run_id,
        log_file=log_file,
        step_specs=[
            {"step_name": "build_retail_mbr", "script": "scripts/build_retail_mbr.py"},
            {"step_name": "run_agent_governance", "script": "scripts/run_agent_governance.py"},
            {"step_name": "run_adversarial_eval_suite", "script": "scripts/run_adversarial_eval_suite.py"},
            {
                "step_name": "make_agent_effectiveness_report",
                "script": "scripts/make_agent_effectiveness_report.py",
                "enabled": not lightweight,
            },
            {"step_name": "run_agent_value_eval", "script": "scripts/run_agent_value_eval.py"},
        ],
    )
    # Reconciliation requires outcomes-ledger/context produced in eval stage.
    _ensure_provisional_reconciliation_or_exit(
        run_id=args.run_id,
        log_file=log_file,
        feature_state=feature_state,
    )

    _try_run_step(build_reports_cmd, "build_reports_refresh", log_file, enabled=not lightweight)
    _run_py_step_specs(
        run_id=args.run_id,
        log_file=log_file,
        step_specs=[
            {
                "step_name": "make_agent_quality_report_v2",
                "script": "scripts/make_agent_quality_report_v2.py",
                "enabled": not lightweight,
            }
        ],
    )

    realism_cmd = ["python3", "scripts/make_realism_report.py", "--run-id", args.run_id]
    base_run_id = os.getenv("BASE_RUN_ID", "").strip()
    if base_run_id:
        realism_cmd.extend(["--base-run-id", base_run_id])
    _try_run_step(realism_cmd, "make_realism_report", log_file, enabled=not lightweight)

    _run_py_step_specs(
        run_id=args.run_id,
        log_file=log_file,
        step_specs=[
            {"step_name": "make_agent_quality_report", "script": "scripts/make_agent_quality_report.py", "enabled": not lightweight},
            {"step_name": "build_agent_report", "script": "scripts/build_agent_report.py", "enabled": not lightweight},
            {"step_name": "check_contracts", "script": "scripts/check_contracts.py", "enabled": not lightweight},
            {"step_name": "check_decision_contracts", "script": "scripts/check_decision_contracts.py", "enabled": not lightweight},
            {
                "step_name": "make_agent_quality_summary",
                "script": "scripts/make_agent_quality_summary.py",
                "args": ["--limit", 30],
                "enabled": not lightweight,
                "include_run_id": False,
            },
            {"step_name": "build_human_reports_hub", "script": "scripts/build_human_reports_hub.py"},
            {
                "step_name": "build_weekly_pack",
                "script": "scripts/build_weekly_pack.py",
                "enabled": int(args.build_weekly) == 1 and not lightweight,
                "include_run_id": False,
            },
            {
                "step_name": "build_exec_brief",
                "script": "scripts/build_exec_brief.py",
                "enabled": int(args.build_exec) == 1 and not lightweight,
            },
            {
                "step_name": "integrity_finalize",
                "script": "scripts/integrity_finalize.py",
                "fail_closed": bool(security_profile.get("fail_closed_integrity_finalize", True)),
            },
        ],
    )
    _run_gate_step(
        run_id=args.run_id,
        gate_name="quality_invariants",
        step_name="run_quality_invariants",
        cmd=_py("scripts/run_quality_invariants.py", "--run-id", args.run_id),
        log_file=log_file,
        error_code_on_fail="METHODOLOGY_INVARIANT_BROKEN",
    )
    _run_gate_step(
        run_id=args.run_id,
        gate_name="reasoning_score_policy",
        step_name="run_reasoning_score_policy",
        cmd=_py("scripts/run_reasoning_score_policy.py", "--run-id", args.run_id),
        log_file=log_file,
        error_code_on_fail="METHODOLOGY_INVARIANT_BROKEN",
    )
    _run_gate_step(
        run_id=args.run_id,
        gate_name="governance_ceiling",
        step_name="run_governance_ceiling_refresh",
        cmd=_py("scripts/run_governance_ceiling.py", "--run-id", args.run_id),
        log_file=log_file,
        error_code_on_fail="GOVERNANCE_REVIEW_REQUIRED",
    )

    _run_gate_step(
        run_id=args.run_id,
        gate_name="acceptance",
        step_name="verify_acceptance",
        cmd=_py("scripts/verify_acceptance.py", "--run-id", args.run_id, "--require-pre-publish", 0),
        log_file=log_file,
        error_code_on_fail="METHODOLOGY_INVARIANT_BROKEN",
        enabled=True,
        fail_closed=bool(security_profile.get("fail_closed_verify_acceptance", True)),
    )
    _run_gate_step(
        run_id=args.run_id,
        gate_name="pre_publish",
        step_name="pre_publish_audit",
        cmd=_py(
            "scripts/pre_publish_audit.py",
            "--run-id",
            args.run_id,
            "--out-json",
            f"data/agent_quality/{args.run_id}_pre_publish_audit.json",
        ),
        log_file=log_file,
        error_code_on_fail="GOVERNANCE_REVIEW_REQUIRED",
        fail_closed=bool(security_profile.get("fail_closed_pre_publish_audit", True)),
    )
    _try_run_step(
        _py("scripts/build_cost_ledger.py", "--run-id", args.run_id),
        "build_cost_ledger",
        log_file,
        enabled=True,
    )
    _try_run_step(
        _py("scripts/publish_to_slack.py", "--run-id", args.run_id),
        "publish_to_slack",
        log_file,
        enabled=True,
    )
    _try_run_step(
        _py("scripts/publish_to_jira.py", "--run-id", args.run_id),
        "publish_to_jira",
        log_file,
        enabled=True,
    )
    _try_run_step(build_reports_cmd, "build_reports_post_gates", log_file, enabled=not lightweight)


def _run_reporting_tail(
    *,
    args: argparse.Namespace,
    exp_id: str,
    log_file: Path,
    llm_env: dict[str, str] | None,
    lightweight: bool,
    security_profile: dict[str, Any],
    feature_state: dict[str, Any],
    retry_policy: dict[str, Any],
    hypothesis_review_flag: int = 0,
) -> None:
    _run_transparency_tail(
        args=args,
        exp_id=exp_id,
        log_file=log_file,
        llm_env=llm_env,
        lightweight=lightweight,
        retry_policy=retry_policy,
        hypothesis_review_flag=hypothesis_review_flag,
    )
    build_reports_cmd = _run_security_and_reports_tail(args=args, log_file=log_file)
    _run_eval_publish_tail(
        args=args,
        log_file=log_file,
        lightweight=lightweight,
        build_reports_cmd=build_reports_cmd,
        security_profile=security_profile,
        feature_state=feature_state,
    )


def main() -> None:
    parser = build_run_all_parser()
    args = parser.parse_args()

    try:
        _REQUIRED_GATE_EXECUTION_LOG.clear()
        runtime = resolve_run_all_runtime_config(args)
        if runtime.domain_template:
            os.environ["DS_DOMAIN_TEMPLATE"] = runtime.domain_template
            os.environ["DS_DOMAIN_TEMPLATE_PATH"] = runtime.domain_template
            _preflight_validate_domain_template_or_exit(runtime.domain_template)
        _enforce_runtime_secret_policy()
        runtime_limits = load_runtime_limits_contract()
        feature_state = load_feature_state_contract()
        retry_policy = load_retry_policy_contract()
        _ = validate_v3_contract_set()
        _enforce_run_all_gate_order_contract_or_exit()
        _enforce_runtime_cloud_gateway_policy_or_exit()
        _enforce_runtime_feature_policy(feature_state)
        os.environ["DS_RUNTIME_LIMIT_CONCURRENCY"] = str(runtime_limits.get("concurrency", 1))
        os.environ["DS_RUNTIME_LIMIT_MAX_BATCH_SIZE"] = str(runtime_limits.get("max_batch_size", ""))
        os.environ["DS_RUNTIME_LIMIT_MAX_PAYLOAD_BYTES"] = str(runtime_limits.get("max_payload_bytes", ""))
        os.environ["DS_RUNTIME_LIMIT_MAX_RECONCILE_ATTEMPTS"] = str(runtime_limits.get("max_reconcile_attempts", ""))
        os.environ["DS_RUNTIME_LIMIT_RECONCILIATION_TTL_HOURS"] = str(runtime_limits.get("reconciliation_ttl_hours", ""))
        os.environ["DS_RUNTIME_LIMIT_SLA_MODE"] = str(runtime_limits.get("sla_mode", "batch_nightly"))
        os.environ["DS_RETRY_POLICY_MAX_LLM_CALLS_PER_RUN"] = str(retry_policy.get("max_llm_calls_per_run", ""))
        os.environ["DS_RETRY_POLICY_MAX_LLM_FAILURES_PER_RUN"] = str(retry_policy.get("max_llm_failures_per_run", ""))
        os.environ["DS_RETRY_POLICY_MAX_CONSECUTIVE_FAILS"] = str(
            retry_policy.get("max_consecutive_failures_before_open_circuit", "")
        )
        os.environ["DS_RETRY_POLICY_CIRCUIT_COOLDOWN_SECONDS"] = str(retry_policy.get("circuit_cooldown_seconds", ""))
        os.environ["DS_RETRY_POLICY_SAFE_DECISION"] = str(retry_policy.get("safe_decision", "HOLD_NEED_DATA"))
        print(
            f"runtime_limits concurrency={runtime_limits.get('concurrency')} "
            f"max_batch_size={runtime_limits.get('max_batch_size')} "
            f"max_payload_bytes={runtime_limits.get('max_payload_bytes')} "
            f"max_reconcile_attempts={runtime_limits.get('max_reconcile_attempts')} "
            f"reconciliation_ttl_hours={runtime_limits.get('reconciliation_ttl_hours')} "
            f"sla_mode={runtime_limits.get('sla_mode')}"
        )
        print(
            f"feature_state weak_path_runtime={feature_state.get('weak_path_runtime')} "
            f"reconciliation_runtime={feature_state.get('reconciliation_runtime')} "
            f"auto_decision_change={feature_state.get('auto_decision_change')} "
            f"default_weak_path_ceiling={feature_state.get('default_weak_path_ceiling')}"
        )
        print(
            f"retry_policy max_llm_calls_per_run={retry_policy.get('max_llm_calls_per_run')} "
            f"max_llm_failures_per_run={retry_policy.get('max_llm_failures_per_run')} "
            f"max_consecutive_failures_before_open_circuit={retry_policy.get('max_consecutive_failures_before_open_circuit')} "
            f"circuit_cooldown_seconds={retry_policy.get('circuit_cooldown_seconds')} "
            f"safe_decision={retry_policy.get('safe_decision')}"
        )
        if runtime.domain_template:
            print(f"domain_template_path={runtime.domain_template}")

        selected_profile = os.getenv("DS_SECURITY_PROFILE", "").strip().lower() or ("lightweight" if runtime.lightweight else "production")
        security_profile = load_security_profile(selected_profile)
        os.environ["DS_SECURITY_PROFILE"] = str(security_profile.get("name", selected_profile))
        os.environ["DS_INTEGRITY_MODE"] = str(security_profile.get("integrity_mode", "required"))
        os.environ["DS_STRICT_MANIFEST_SCOPE"] = "1" if bool(security_profile.get("strict_manifest_scope", True)) else "0"
        print(
            f"security_profile={security_profile.get('name')} "
            f"integrity_mode={security_profile.get('integrity_mode')} "
            f"strict_manifest_scope={int(bool(security_profile.get('strict_manifest_scope', True)))}"
        )
        hypothesis_review_flag = _effective_hypothesis_review_flag(args, security_profile)
        os.environ["DS_ENABLE_HYPOTHESIS_REVIEW_V1"] = str(int(hypothesis_review_flag))
        print(f"commander_hypothesis_review_v1={int(hypothesis_review_flag)}")

        app_dsn = _service_dsn(APP_SERVICE, role="app")
        loader_dsn = _service_dsn(LOADER_SERVICE, role="loader")
        _assert_local_dsn(app_dsn)
        _assert_local_dsn(loader_dsn)

        app_engine = _engine(app_dsn)
        _check_db_identity(app_engine, EXPECTED_DB, EXPECTED_APP_USER)
        _preflight_validate_goal1_schema_contract_or_exit(app_engine)
        _preflight_validate_locked_historical_corpus_or_exit()
        _run_raw_reload_if_requested(args=args, log_file=runtime.log_file, loader_dsn=loader_dsn)
        _enforce_runtime_limits_for_run_or_exit(args.run_id, runtime_limits, feature_state)
        paired_registry_payload = _init_or_load_paired_registry(
            run_id=args.run_id,
            run_id_ctrl=str(getattr(runtime, "run_id_ctrl", "") or f"{args.run_id}_ctrl"),
            experiment_id=runtime.exp_id,
            mode=str(getattr(runtime, "mode", "single") or "single"),
        )
        paired_mode = str(getattr(runtime, "mode", "single") or "single").strip().lower() == "paired"
        paired_status = (
            str((paired_registry_payload or {}).get("paired_status", "")).strip().upper()
            if isinstance(paired_registry_payload, dict)
            else ""
        )
        ctrl_audit_path: Path | None = None
        paired_variants = load_experiment_variants(runtime.domain_template) if paired_mode else None
        if paired_mode:
            ctrl_variant = (paired_variants or {}).get("ctrl") if isinstance(paired_variants, dict) else None
            treatment_variant = (paired_variants or {}).get("treatment") if isinstance(paired_variants, dict) else None
            try:
                ctrl_audit_path = _run_ctrl_foundation_only(
                    args=args,
                    exp_id=runtime.exp_id,
                    run_id_ctrl=str(getattr(runtime, "run_id_ctrl", "") or f"{args.run_id}_ctrl"),
                    log_file=runtime.log_file,
                    app_engine=app_engine,
                    ctrl_variant=ctrl_variant if isinstance(ctrl_variant, dict) else None,
                )
                paired_registry_payload = _sync_paired_registry_refs(
                    paired_registry_payload,
                    status=PairedRunStatus.COMPLETE.value,
                    error_code="NONE",
                    reason="paired_ctrl_foundation_ready",
                    audit_ref=_artifact_ref(ctrl_audit_path) if isinstance(ctrl_audit_path, Path) else "",
                )
                if isinstance(treatment_variant, dict):
                    if str(treatment_variant.get("mode_tag", "")).strip():
                        args.mode_tag = str(treatment_variant.get("mode_tag"))
                    if treatment_variant.get("horizon_days") is not None:
                        try:
                            args.horizon_days = int(treatment_variant.get("horizon_days"))
                        except Exception:
                            pass
                    if treatment_variant.get("seed") is not None:
                        try:
                            args.seed = int(treatment_variant.get("seed"))
                        except Exception:
                            pass
                    overrides = treatment_variant.get("overrides")
                    if isinstance(overrides, dict):
                        for key, value in overrides.items():
                            key_str = str(key)
                            if hasattr(args, key_str):
                                setattr(args, key_str, value)
            except SystemExit:
                failed_ctx = _write_paired_experiment_context(
                    run_id=args.run_id,
                    experiment_id=runtime.exp_id,
                    ctrl_run_id=str(getattr(runtime, "run_id_ctrl", "") or f"{args.run_id}_ctrl"),
                    treatment_run_id=args.run_id,
                    paired_status=PairedRunStatus.CTRL_FAILED.value,
                    audit_ref=_artifact_ref(ctrl_audit_path) if isinstance(ctrl_audit_path, Path) else "",
                    failure_reason="ctrl_foundation_failed_before_treatment",
                    failed_step="ctrl_foundation",
                )
                paired_registry_payload = _mark_ctrl_foundation_failed(
                    paired_registry_payload,
                    reason="ctrl_foundation_failed_before_treatment",
                    audit_ref=_artifact_ref(ctrl_audit_path) if isinstance(ctrl_audit_path, Path) else "",
                )
                paired_registry_payload = _sync_paired_registry_refs(
                    paired_registry_payload,
                    status=PairedRunStatus.CTRL_FAILED.value,
                    error_code="CTRL_FOUNDATION_SCOPE_VIOLATION",
                    reason="ctrl_foundation_failed_before_treatment",
                    audit_ref=_artifact_ref(ctrl_audit_path) if isinstance(ctrl_audit_path, Path) else "",
                    paired_context_ref=_artifact_ref(failed_ctx),
                )
                raise
        paired_status = (
            str((paired_registry_payload or {}).get("paired_status", "")).strip().upper()
            if isinstance(paired_registry_payload, dict)
            else paired_status
        )

        try:
            clean_layer_enabled, missing_views = _run_core_proof_path(
                args=args,
                exp_id=runtime.exp_id,
                log_file=runtime.log_file,
                llm_env=runtime.llm_env,
                app_engine=app_engine,
                runtime_limits=runtime_limits,
                feature_state=feature_state,
                retry_policy=retry_policy,
                hypothesis_review_flag=hypothesis_review_flag,
                paired_mode=paired_mode,
                paired_status=paired_status,
                paired_registry_payload=paired_registry_payload,
            )
            _enforce_runtime_limits_for_run_or_exit(args.run_id, runtime_limits, feature_state)
            _run_reporting_tail(
                args=args,
                exp_id=runtime.exp_id,
                log_file=runtime.log_file,
                llm_env=runtime.llm_env,
                lightweight=runtime.lightweight,
                security_profile=security_profile,
                feature_state=feature_state,
                retry_policy=retry_policy,
                hypothesis_review_flag=hypothesis_review_flag,
            )
        except SystemExit:
            if paired_mode:
                paired_registry_payload = _promote_partial_from_treatment_failure(
                    paired_registry_payload,
                    reason="treatment_pipeline_failed",
                )
                failed_ctx = _write_paired_experiment_context(
                    run_id=args.run_id,
                    experiment_id=runtime.exp_id,
                    ctrl_run_id=str(getattr(runtime, "run_id_ctrl", "") or f"{args.run_id}_ctrl"),
                    treatment_run_id=args.run_id,
                    paired_status=PairedRunStatus.TREATMENT_FAILED.value,
                    audit_ref=_artifact_ref(ctrl_audit_path) if isinstance(ctrl_audit_path, Path) else "",
                    partial_reason="treatment_pipeline_failed",
                    failed_step="treatment_pipeline",
                    decision_ceiling="HOLD_NEED_DATA",
                )
                paired_registry_payload = _sync_paired_registry_refs(
                    paired_registry_payload,
                    status=PairedRunStatus.TREATMENT_FAILED.value,
                    error_code="AB_ARTIFACT_REQUIRED",
                    reason="treatment_pipeline_failed",
                    audit_ref=_artifact_ref(ctrl_audit_path) if isinstance(ctrl_audit_path, Path) else "",
                    paired_context_ref=_artifact_ref(failed_ctx),
                )
            raise
        if paired_mode:
            try:
                latest_registry = load_registry_for_run(args.run_id, required=True)
            except Exception as exc:
                raise SystemExit(f"PAIRED_REGISTRY_KEY_INVALID: {exc}")
            if not isinstance(latest_registry, dict):
                raise SystemExit("PAIRED_REGISTRY_KEY_INVALID: missing_or_invalid_registry_payload")
            paired_registry_payload = latest_registry
            final_paired_status = (
                str((paired_registry_payload or {}).get("paired_status", "")).strip().upper()
                if isinstance(paired_registry_payload, dict)
                else ""
            )
            if final_paired_status == PairedRunStatus.COMPLETE.value:
                paired_context_path = _write_paired_experiment_context(
                    run_id=args.run_id,
                    experiment_id=runtime.exp_id,
                    ctrl_run_id=str(getattr(runtime, "run_id_ctrl", "") or f"{args.run_id}_ctrl"),
                    treatment_run_id=args.run_id,
                    paired_status=PairedRunStatus.COMPLETE.value,
                    audit_ref=_artifact_ref(ctrl_audit_path) if isinstance(ctrl_audit_path, Path) else "",
                )
                paired_registry_payload = _sync_paired_registry_refs(
                    paired_registry_payload,
                    status=PairedRunStatus.COMPLETE.value,
                    error_code="NONE",
                    reason="paired_complete",
                    audit_ref=_artifact_ref(ctrl_audit_path) if isinstance(ctrl_audit_path, Path) else "",
                    paired_context_ref=_artifact_ref(paired_context_path),
                )
                _ctrl_run_id_for_stat = str(getattr(runtime, "run_id_ctrl", "") or f"{args.run_id}_ctrl")
                _ctrl_snapshot_p = Path(f"data/metrics_snapshots/{_ctrl_run_id_for_stat}.json")
                _trt_snapshot_p = Path(f"data/metrics_snapshots/{args.run_id}.json")
                _stat_bundle_out = stat_evidence_bundle_path(args.run_id)
                try:
                    _stat_bundle = compute_stat_evidence(
                        _ctrl_snapshot_p,
                        _trt_snapshot_p,
                        str(runtime.domain_template or ""),
                        paired_status=PairedRunStatus.COMPLETE.value,
                    )
                    _stat_bundle_out.parent.mkdir(parents=True, exist_ok=True)
                    _stat_bundle_out.write_text(
                        json.dumps(_stat_bundle.to_dict(), ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    write_sha256_sidecar(_stat_bundle_out)
                    print(f"[stat_engine] stat_evidence_bundle written run_id={args.run_id}")
                except Exception as _stat_exc:
                    print(f"[stat_engine] WARNING: stat_evidence_bundle not written: {_stat_exc}")
                _try_run_step(
                    _py(
                        "scripts/update_history_corpus.py",
                        "--run-id",
                        args.run_id,
                    ),
                    "update_history_corpus",
                    runtime.log_file,
                    enabled=True,
                )
            _enforce_paired_partial_ceiling_or_exit(
                run_id=args.run_id,
                paired_mode=True,
                paired_registry_payload=paired_registry_payload,
            )
        _assert_required_gate_execution_order_or_exit()
        _enforce_runtime_limits_for_run_or_exit(args.run_id, runtime_limits, feature_state)
        _validate_core_llm_authenticity(args)

        valid_orders_count = _read_valid_orders_count(app_engine, args.run_id, clean_layer_enabled=clean_layer_enabled)

        print_run_completion_summary(
            run_id=args.run_id,
            experiment_id=runtime.exp_id,
            log_file=runtime.log_file,
            clean_layer_enabled=clean_layer_enabled,
            missing_views=missing_views,
            valid_orders_count=valid_orders_count,
        )
    except SystemExit:
        raise
    except Exception:
        print("ERROR: runtime failed. See application logs.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
