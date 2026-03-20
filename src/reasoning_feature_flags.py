from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from src.security_utils import verify_sha256_sidecar

_DEFAULT_PATH = Path("configs/contracts/reasoning_feature_flags_v1.json")


def _to_flag_int(value: Any, default: int = 0) -> int:
    if value is None:
        return int(default)
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return 1 if int(value) != 0 else 0
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return 1
    if text in {"0", "false", "no", "off"}:
        return 0
    return int(default)


def _load_defaults(path: Path) -> dict[str, int]:
    if not path.exists():
        raise RuntimeError(f"missing_contract_file:{path}")
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        raise RuntimeError(f"contract_integrity_error:{reason}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise RuntimeError(f"invalid_contract_json:{path}")
    flags = payload.get("flags", {}) if isinstance(payload, dict) else {}
    if not isinstance(flags, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in flags.items():
        name = str(key or "").strip()
        if not name:
            continue
        out[name] = _to_flag_int(value, 0)
    return out


def load_reasoning_feature_flags(
    runtime_defaults: dict[str, int] | None = None,
    *,
    config_path: str = "",
) -> dict[str, int]:
    defaults = dict(runtime_defaults or {})
    file_defaults = _load_defaults(Path(config_path) if str(config_path).strip() else _DEFAULT_PATH)
    merged: dict[str, int] = {}

    keys = set(defaults.keys()) | set(file_defaults.keys())
    for key in keys:
        merged[key] = _to_flag_int(file_defaults.get(key), defaults.get(key, 0))

    for key in list(merged.keys()):
        if key in os.environ:
            merged[key] = _to_flag_int(os.getenv(key), merged[key])

    return merged
