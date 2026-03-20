from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.security_utils import verify_sha256_sidecar

DEFAULT_DECISIONS = {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}
DEFAULT_REASONING_CHECKS = (
    "trace_completeness_rate",
    "alternative_hypothesis_quality",
    "falsifiability_specificity",
    "decision_change_sensitivity",
)


def load_decision_contract(path: str = "") -> dict[str, Any]:
    p = Path(path) if str(path).strip() else Path("configs/contracts/decision_contract_v2.json")
    if not p.exists():
        raise RuntimeError(f"missing_contract_file:{p}")
    ok, reason = verify_sha256_sidecar(p, required=True)
    if not ok:
        raise RuntimeError(f"contract_integrity_error:{reason}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        raise RuntimeError(f"invalid_contract_json:{p}")


def allowed_decisions(contract: dict[str, Any]) -> set[str]:
    values = contract.get("decisions")
    if isinstance(values, list) and values:
        return {str(v).strip().upper() for v in values if str(v).strip()}
    return set(DEFAULT_DECISIONS)


def validate_decision(value: str, contract: dict[str, Any], field_name: str = "decision") -> None:
    val = str(value).strip().upper()
    if val not in allowed_decisions(contract):
        raise ValueError(f"invalid {field_name}: {value}")


def validate_required_fields(payload: dict[str, Any], contract: dict[str, Any], role: str) -> None:
    required = (
        contract.get("required_fields", {}).get(role, [])
        if isinstance(contract.get("required_fields"), dict)
        else []
    )
    if not isinstance(required, list):
        return
    for key in required:
        if key not in payload:
            raise ValueError(f"missing required field '{key}' for {role}")


def contract_reasoning_checks(contract: dict[str, Any]) -> list[str]:
    checks = (
        contract.get("reasoning_checks", {}).get("advisory_defaults", [])
        if isinstance(contract.get("reasoning_checks"), dict)
        else []
    )
    if isinstance(checks, list) and checks:
        return [str(c).strip() for c in checks if str(c).strip()]
    return list(DEFAULT_REASONING_CHECKS)


def validate_reasoning_checks(payload: dict[str, Any], contract: dict[str, Any]) -> None:
    checks = contract_reasoning_checks(contract)
    if not checks:
        return
    node = payload.get("reasoning_checks", {})
    if not isinstance(node, dict):
        raise ValueError("missing required field 'reasoning_checks'")
    missing: list[str] = []
    invalid: list[str] = []
    for key in checks:
        if key not in node:
            missing.append(key)
            continue
        raw = node.get(key)
        try:
            value = float(raw)
        except Exception:
            invalid.append(f"{key}:not_numeric")
            continue
        if not (0.0 <= value <= 1.0):
            invalid.append(f"{key}:out_of_range")
    if missing or invalid:
        msg: list[str] = []
        if missing:
            msg.append(f"missing reasoning_checks: {', '.join(missing)}")
        if invalid:
            msg.append(f"invalid reasoning_checks: {', '.join(invalid)}")
        raise ValueError("; ".join(msg))
