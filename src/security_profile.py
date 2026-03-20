from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from src.security_utils import verify_sha256_sidecar

_DEFAULT_PATH = Path("configs/contracts/security_profile_contract_v1.json")


def _to_bool(value: Any, default: bool = False) -> bool:
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


def _normalize_integrity_mode(value: Any) -> str:
    mode = str(value or "").strip().lower()
    if mode in {"required", "best_effort"}:
        return mode
    return "best_effort"


def _load_contract(path: Path) -> dict[str, Any]:
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


def load_security_profile(
    profile_name: str = "",
    *,
    config_path: str = "",
) -> dict[str, Any]:
    payload = _load_contract(Path(config_path) if str(config_path).strip() else _DEFAULT_PATH)
    profiles = payload.get("profiles") if isinstance(payload.get("profiles"), dict) else {}

    selected = str(profile_name or os.getenv("DS_SECURITY_PROFILE") or "").strip().lower() or "production"
    if selected not in profiles:
        raise RuntimeError(f"unknown_security_profile:{selected}")

    cfg = profiles.get(selected) if isinstance(profiles.get(selected), dict) else {}
    manifest_scope = payload.get("manifest_scope") if isinstance(payload.get("manifest_scope"), dict) else {}
    ignore_globs = manifest_scope.get("ignore_globs") if isinstance(manifest_scope.get("ignore_globs"), list) else []
    dsn_policy = payload.get("dsn_policy") if isinstance(payload.get("dsn_policy"), dict) else {}

    return {
        "name": selected,
        "integrity_mode": _normalize_integrity_mode(cfg.get("integrity_mode")),
        "require_json_manifest": _to_bool(cfg.get("require_json_manifest"), True),
        "strict_manifest_scope": _to_bool(cfg.get("strict_manifest_scope"), True),
        "fail_closed_pre_publish_audit": _to_bool(cfg.get("fail_closed_pre_publish_audit"), True),
        "fail_closed_verify_acceptance": _to_bool(cfg.get("fail_closed_verify_acceptance"), True),
        "fail_closed_integrity_finalize": _to_bool(cfg.get("fail_closed_integrity_finalize"), True),
        "manifest_scope_ignore_globs": [str(x) for x in ignore_globs if str(x).strip()],
        "dsn_policy": {
            "service_based_required": _to_bool(dsn_policy.get("service_based_required"), True),
            "forbid_inline_credentials": _to_bool(dsn_policy.get("forbid_inline_credentials"), True),
        },
    }
