from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.paired_registry import (
    CTRL_FOUNDATION_ALLOWED_STEPS,
    PAIRED_RUN_STATUS_VALUES,
    PAIRED_STATUS_TRANSITIONS_ALLOWED,
)
from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar

CONTRACTS_DIR = Path("configs/contracts")
GATES_DIR = Path("data/gates")

ERROR_TAXONOMY_PATH = CONTRACTS_DIR / "error_taxonomy_v1.json"
GATE_RESULT_CONTRACT_PATH = CONTRACTS_DIR / "gate_result_v1.json"

REQUIRED_V3_CONTRACTS = {
    "context_frame": CONTRACTS_DIR / "context_frame_v1.json",
    "handoff_contract_guard": CONTRACTS_DIR / "handoff_contract_guard_v1.json",
    "historical_context_pack": CONTRACTS_DIR / "historical_context_pack_v1.json",
    "reasoning_memory_ledger": CONTRACTS_DIR / "reasoning_memory_ledger_v1.json",
    "doctor_hypothesis_review": CONTRACTS_DIR / "doctor_hypothesis_review_v1.json",
    "decision_outcomes_ledger": CONTRACTS_DIR / "decision_outcomes_ledger_v1.json",
    "offline_kpi_backtest": CONTRACTS_DIR / "offline_kpi_backtest_v1.json",
    "stat_evidence_bundle": CONTRACTS_DIR / "stat_evidence_bundle_v1.json",
    "reasoning_confidence_policy": CONTRACTS_DIR / "reasoning_confidence_policy_v1.json",
    "sanitization_transform": CONTRACTS_DIR / "sanitization_transform_v1.json",
    "sanitization_policy": CONTRACTS_DIR / "sanitization_policy_v2.json",
    "reconciliation_policy": CONTRACTS_DIR / "reconciliation_policy_v1.json",
    "paired_registry": CONTRACTS_DIR / "paired_registry_v1.json",
    "paired_experiment": CONTRACTS_DIR / "paired_experiment_v2.json",
    "experiment_duration_policy": CONTRACTS_DIR / "experiment_duration_policy_v1.json",
    "anti_goodhart_verdict": CONTRACTS_DIR / "anti_goodhart_verdict_v1.json",
    "quality_invariants": CONTRACTS_DIR / "quality_invariants_v1.json",
    "reasoning_score_policy": CONTRACTS_DIR / "reasoning_score_policy_v2.json",
    "governance_ceiling": CONTRACTS_DIR / "governance_ceiling_v1.json",
    "gate_result": GATE_RESULT_CONTRACT_PATH,
}

REQUIRED_ERROR_CODES = {
    "CONTEXT_CONFLICT",
    "HISTORICAL_CONTEXT_MISSING",
    "HISTORICAL_CONTEXT_INTEGRITY_FAIL",
    "HISTORICAL_CONTEXT_UNUSED",
    "SANITIZATION_REQUIRED_FOR_CLOUD",
    "SANITIZATION_MAP_POLICY_VIOLATION",
    "SANITIZATION_AUDIT_TRAIL_MISSING",
    "MAP_ENCRYPTION_VERIFIED",
    "PROVISIONAL_REQUIRES_RECONCILIATION",
    "EXPERIMENT_CONTEXT_REQUIRED",
    "EXPERIMENT_DURATION_INSUFFICIENT",
    "AB_ARTIFACT_REQUIRED",
    "ANTI_GOODHART_MISMATCH",
    "CTRL_FOUNDATION_SCOPE_VIOLATION",
    "PAIRED_RUN_ID_COLLISION",
    "PAIRED_REGISTRY_KEY_INVALID",
    "PAIRED_PARTIAL_CEILING_VIOLATION",
    "METHODOLOGY_INVARIANT_BROKEN",
    "MITIGATION_PROPOSALS_MISSING",
    "HYPOTHESIS_REVIEW_MISSING",
    "HYPOTHESIS_REVIEW_POLICY_VIOLATION",
    "HYPOTHESIS_REVIEW_INVALID_SCHEMA",
    "KPI_ONLINE_MISSING",
    "KPI_LEDGER_MISSING",
    "KPI_OUTCOMES_SCOPE_VIOLATION",
    "KPI_OFFLINE_STALE",
    "GOVERNANCE_REVIEW_REQUIRED",
}

AGENT_SEQUENCE = [
    "captain",
    "doctor",
    "evaluator",
    "commander",
]

GATE_SEQUENCE = [
    "context_frame",
    "historical_retrieval_gate",
    "doctor",
    "handoff_contract_guard",
    "experiment_duration_gate",
    "anti_goodhart_sot",
    "evaluator",
    "commander",
    "historical_retrieval_conformance_gate",
    "quality_invariants",
    "reasoning_score_policy",
    "governance_ceiling",
    "acceptance",
    "pre_publish",
]

REQUIRED_GATE_ORDER = [
    "context_frame",
    "historical_retrieval_gate",
    "doctor",
    "handoff_contract_guard",
    "experiment_duration_gate",
    "anti_goodhart_sot",
    "evaluator",
    "commander",
    "historical_retrieval_conformance_gate",
    "quality_invariants",
    "reasoning_score_policy",
    "governance_ceiling",
    "acceptance",
    "pre_publish",
]


SANITIZATION_TRANSFORM_PATH = CONTRACTS_DIR / "sanitization_transform_v1.json"
SANITIZATION_POLICY_PATH = CONTRACTS_DIR / "sanitization_policy_v2.json"
RECONCILIATION_POLICY_PATH = CONTRACTS_DIR / "reconciliation_policy_v1.json"
PAIRED_STATUS_ENUM = PAIRED_RUN_STATUS_VALUES
PAIRED_CTRL_FOUNDATION_ALLOWED_STEPS = CTRL_FOUNDATION_ALLOWED_STEPS
PAIRED_STATUS_LIFECYCLE_ALLOWED = PAIRED_STATUS_TRANSITIONS_ALLOWED


def historical_context_pack_path(run_id: str) -> Path:
    return Path(f"data/agent_context/{run_id}_historical_context_pack.json")


def reasoning_memory_ledger_path(run_id: str) -> Path:
    return Path(f"data/agent_context/{run_id}_reasoning_memory_ledger.json")


def historical_conformance_path(run_id: str) -> Path:
    return Path(f"data/agent_quality/{run_id}_historical_retrieval_conformance.json")


def decision_outcomes_ledger_path(run_id: str) -> Path:
    return Path(f"data/agent_eval/{run_id}_decision_outcomes_ledger.json")


def offline_kpi_backtest_path(run_id: str) -> Path:
    return Path(f"data/agent_eval/{run_id}_offline_kpi_backtest.json")


def stat_evidence_bundle_path(run_id: str) -> Path:
    return Path(f"data/agent_context/{run_id}_stat_evidence_bundle_v1.json")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json_with_integrity(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing_contract_or_artifact:{path}")
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        raise RuntimeError(f"integrity_error:{reason}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise RuntimeError(f"invalid_json:{path}")
    if not isinstance(payload, dict):
        raise RuntimeError(f"invalid_json_object:{path}")
    return payload


def load_json_optional_with_integrity(path: Path, *, required: bool = False) -> dict[str, Any] | None:
    if not path.exists():
        if required:
            raise RuntimeError(f"missing_contract_or_artifact:{path}")
        return None
    return load_json_with_integrity(path)


def save_json_with_sidecar(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(path)


def gate_result_path(run_id: str, gate_name: str) -> Path:
    safe_gate = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(gate_name))
    return GATES_DIR / f"{run_id}_{safe_gate}_gate_result.json"


def write_gate_result(
    run_id: str,
    *,
    gate_name: str,
    status: str,
    error_code: str,
    blocked_by: list[str] | None = None,
    required_actions: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> Path:
    status_norm = str(status or "").upper().strip()
    if status_norm not in {"PASS", "FAIL"}:
        status_norm = "FAIL"
    gate_name_norm = str(gate_name or "").strip()
    if not gate_name_norm:
        raise RuntimeError("gate_result_invalid_gate_name")
    error_code_norm = str(error_code or "NONE").strip().upper() or "NONE"
    if not check_error_code_allowed(error_code_norm):
        raise RuntimeError(f"gate_result_error_code_not_allowed:{error_code_norm}")
    payload: dict[str, Any] = {
        "version": "gate_result_v1",
        "run_id": run_id,
        "gate_name": gate_name_norm,
        "status": status_norm,
        "error_code": error_code_norm,
        "blocked_by": [str(x) for x in (blocked_by or []) if str(x).strip()][:20],
        "required_actions": [str(x) for x in (required_actions or []) if str(x).strip()][:20],
        "generated_at": _now_iso(),
    }
    if isinstance(details, dict) and details:
        payload["details"] = details
    out = gate_result_path(run_id, gate_name)
    save_json_with_sidecar(out, payload)
    return out


def load_error_taxonomy() -> dict[str, Any]:
    payload = load_json_with_integrity(ERROR_TAXONOMY_PATH)
    codes = payload.get("codes") if isinstance(payload.get("codes"), list) else []
    code_set = {str(x).strip().upper() for x in codes if str(x).strip()}
    missing = sorted(REQUIRED_ERROR_CODES - code_set)
    if missing:
        raise RuntimeError(f"missing_required_error_codes:{','.join(missing)}")
    return payload


def validate_v3_contract_set() -> dict[str, str]:
    result: dict[str, str] = {}
    for name, path in REQUIRED_V3_CONTRACTS.items():
        _ = load_json_with_integrity(path)
        result[name] = str(path)
    _ = load_error_taxonomy()
    return result


def check_error_code_allowed(code: str) -> bool:
    try:
        payload = load_error_taxonomy()
    except Exception:
        return False
    codes = payload.get("codes") if isinstance(payload.get("codes"), list) else []
    code_set = {str(x).strip().upper() for x in codes if str(x).strip()}
    return str(code or "").strip().upper() in code_set


def anti_goodhart_verdict_path(run_id: str) -> Path:
    return Path(f"data/agent_quality/{run_id}_anti_goodhart_verdict.json")


def load_anti_goodhart_verdict(run_id: str) -> dict[str, Any]:
    payload = load_json_with_integrity(anti_goodhart_verdict_path(run_id))
    if str(payload.get("source_of_truth", "")).strip() != "anti_goodhart_verdict_v1":
        raise RuntimeError("anti_goodhart_verdict_invalid_source")
    if "anti_goodhart_triggered" not in payload:
        raise RuntimeError("anti_goodhart_verdict_missing_trigger_flag")
    return payload


def context_frame_path(run_id: str) -> Path:
    return Path(f"data/agent_context/{run_id}_context_frame.json")


def captain_artifact_path(run_id: str) -> Path:
    return Path(f"data/llm_reports/{run_id}_captain.json")


def handoff_guard_path(run_id: str) -> Path:
    return Path(f"data/agent_quality/{run_id}_handoff_contract_guard.json")


def quality_invariants_path(run_id: str) -> Path:
    return Path(f"data/agent_quality/{run_id}_quality_invariants.json")


def reasoning_policy_path(run_id: str) -> Path:
    return Path(f"data/agent_quality/{run_id}_reasoning_score_policy.json")


def governance_ceiling_path(run_id: str) -> Path:
    return Path(f"data/agent_quality/{run_id}_governance_ceiling.json")


def paired_experiment_context_path(run_id: str) -> Path:
    return Path(f"data/agent_context/{run_id}_paired_experiment_v2.json")


def ctrl_foundation_audit_path(run_id: str) -> Path:
    return Path(f"data/agent_quality/{run_id}_ctrl_foundation_audit.json")


def list_gate_results(run_id: str) -> list[Path]:
    if not GATES_DIR.exists():
        return []
    return sorted(GATES_DIR.glob(f"{run_id}_*_gate_result.json"))


def load_gate_result(path: Path) -> dict[str, Any]:
    return load_json_with_integrity(path)
