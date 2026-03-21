from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from src.paired_registry_utils import normalize_registry_key as _normalize_registry_key
from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar


PAIRED_REGISTRY_DIR = Path("data/paired_registry")

PAIRED_AGGRESSIVE_DECISIONS: tuple[str, ...] = (
    "GO",
    "RUN_AB",
    "ROLLOUT_CANDIDATE",
)

CTRL_FOUNDATION_ALLOWED_STEPS: tuple[str, ...] = (
    "run_simulation",
    "run_dq",
    "make_metrics_snapshot_v1",
    "run_synthetic_bias_audit",
    "run_ab_preflight",
    "run_ab_analysis",
)


class PairedRunStatus(str, Enum):
    COMPLETE = "COMPLETE"
    CTRL_FAILED = "CTRL_FAILED"
    TREATMENT_FAILED = "TREATMENT_FAILED"
    PARTIAL = "PARTIAL"


PAIRED_RUN_STATUS_VALUES: tuple[str, ...] = tuple(s.value for s in PairedRunStatus)
PAIRED_STATUS_TRANSITIONS_ALLOWED: tuple[tuple[str, str], ...] = (
    ("", PairedRunStatus.COMPLETE.value),
    (PairedRunStatus.COMPLETE.value, PairedRunStatus.COMPLETE.value),
    (PairedRunStatus.COMPLETE.value, PairedRunStatus.CTRL_FAILED.value),
    (PairedRunStatus.COMPLETE.value, PairedRunStatus.TREATMENT_FAILED.value),
    (PairedRunStatus.COMPLETE.value, PairedRunStatus.PARTIAL.value),
    (PairedRunStatus.TREATMENT_FAILED.value, PairedRunStatus.TREATMENT_FAILED.value),
    (PairedRunStatus.TREATMENT_FAILED.value, PairedRunStatus.PARTIAL.value),
    (PairedRunStatus.PARTIAL.value, PairedRunStatus.PARTIAL.value),
    (PairedRunStatus.CTRL_FAILED.value, PairedRunStatus.CTRL_FAILED.value),
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_registry_key(value: str) -> str:
    # Backward-compatible export; canonical implementation is in src.paired_registry_utils.
    return _normalize_registry_key(value)


def apply_status_transition(
    payload: dict[str, Any],
    *,
    to_status: str,
    reason: str,
    error_code: str = "",
) -> dict[str, Any]:
    out = dict(payload)
    status_to = str(to_status or "").strip().upper()
    if status_to not in set(PAIRED_RUN_STATUS_VALUES):
        raise RuntimeError(f"PAIRED_REGISTRY_INVALID_STATUS:{status_to}")
    status_from = str(out.get("paired_status", "")).strip().upper()
    transition = (status_from, status_to)
    if transition not in set(PAIRED_STATUS_TRANSITIONS_ALLOWED):
        raise RuntimeError(f"PAIRED_STATUS_TRANSITION_INVALID:{status_from}->{status_to}")

    history = out.get("status_history")
    if not isinstance(history, list):
        history = []
    if status_from != status_to:
        history.append(
            {
                "from": status_from or "",
                "to": status_to,
                "reason": str(reason or "paired_status_transition"),
                "changed_at": _now_iso(),
            }
        )
    out["status_history"] = history[-20:]
    out["paired_status"] = status_to
    out["reason"] = str(reason or out.get("reason", "paired_status_transition")).strip()
    if error_code:
        out["error_code"] = str(error_code).strip().upper()
    return out


def paired_registry_path(experiment_id: str, parent_run_id: str) -> Path:
    exp_key = normalize_registry_key(experiment_id)
    run_key = normalize_registry_key(parent_run_id)
    candidate = PAIRED_REGISTRY_DIR / f"{exp_key}__{run_key}.json"
    root = PAIRED_REGISTRY_DIR.resolve()
    resolved = candidate.resolve()
    if root not in resolved.parents:
        raise RuntimeError("PAIRED_REGISTRY_KEY_INVALID:resolved_outside_registry_root")
    return candidate


def _load_json_with_integrity(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"PAIRED_REGISTRY_MISSING:{path}")
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        raise RuntimeError(f"PAIRED_REGISTRY_INTEGRITY_ERROR:{reason}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("PAIRED_REGISTRY_INVALID_PAYLOAD")
    return payload


def load_registry_for_run(parent_run_id: str, *, required: bool = False) -> dict[str, Any] | None:
    run_key = normalize_registry_key(parent_run_id)
    if not PAIRED_REGISTRY_DIR.exists():
        if required:
            raise RuntimeError("PAIRED_REGISTRY_MISSING_DIR")
        return None
    matches = sorted(PAIRED_REGISTRY_DIR.glob(f"*__{run_key}.json"))
    if not matches:
        if required:
            raise RuntimeError("PAIRED_REGISTRY_NOT_FOUND_FOR_RUN")
        return None
    if len(matches) > 1:
        raise RuntimeError("PAIRED_REGISTRY_COLLISION_MULTIPLE_FILES")
    payload = _load_json_with_integrity(matches[0])
    if str(payload.get("mode", "")).strip().lower() != "paired":
        raise RuntimeError("PAIRED_REGISTRY_INVALID_MODE")
    status = str(payload.get("paired_status", "")).strip().upper()
    if status not in {s.value for s in PairedRunStatus}:
        raise RuntimeError("PAIRED_REGISTRY_INVALID_STATUS")
    return payload


def save_registry(payload: dict[str, Any]) -> Path:
    experiment_id = str(payload.get("experiment_id", "")).strip()
    parent_run_id = str(payload.get("parent_run_id", "")).strip()
    out = paired_registry_path(experiment_id, parent_run_id)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(payload)
    payload.setdefault("mode", "paired")
    payload.setdefault("created_at", _now_iso())
    payload["updated_at"] = _now_iso()
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out)
    return out


def effective_paired_status(status: str) -> str:
    status_up = str(status or "").strip().upper()
    if status_up in {s.value for s in PairedRunStatus}:
        return status_up
    return ""


def is_partial_like(status: str) -> bool:
    status_up = effective_paired_status(status)
    return status_up in {PairedRunStatus.PARTIAL.value, PairedRunStatus.TREATMENT_FAILED.value}


def mark_treatment_failed_then_partial(payload: dict[str, Any], *, reason: str) -> dict[str, Any]:
    out = apply_status_transition(
        payload,
        to_status=PairedRunStatus.TREATMENT_FAILED.value,
        reason=str(reason or "treatment_failed"),
        error_code="AB_ARTIFACT_REQUIRED",
    )
    return out
