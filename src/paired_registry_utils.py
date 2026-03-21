from __future__ import annotations

import re

_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{3,80}$")
_CTRL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def normalize_registry_key(raw_key: str) -> str:
    key = str(raw_key or "").strip()
    if not key:
        raise RuntimeError("PAIRED_REGISTRY_KEY_INVALID:empty")
    if _CTRL_CHAR_RE.search(key):
        raise RuntimeError("PAIRED_REGISTRY_KEY_INVALID:control_chars_forbidden")
    if "/" in key or "\\" in key or ".." in key or key.startswith("."):
        raise RuntimeError("PAIRED_REGISTRY_KEY_INVALID:path_tokens_forbidden")
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", key).strip("._-")
    if not normalized:
        raise RuntimeError("PAIRED_REGISTRY_KEY_INVALID:normalized_empty")
    if len(normalized) < 3 or len(normalized) > 80:
        raise RuntimeError("PAIRED_REGISTRY_KEY_INVALID:length_out_of_bounds")
    if normalized.startswith(".") or ".." in normalized or "/" in normalized or "\\" in normalized:
        raise RuntimeError("PAIRED_REGISTRY_KEY_INVALID:normalized_path_tokens")
    if not _SAFE_KEY_RE.fullmatch(normalized):
        raise RuntimeError("PAIRED_REGISTRY_KEY_INVALID:charset_forbidden")
    return normalized
