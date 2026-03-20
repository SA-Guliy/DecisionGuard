from __future__ import annotations

import json
import re
from typing import Any


def strip_json_fence(text: str) -> str:
    t = str(text or "").strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines).strip()
    return t


def parse_json_object_loose(text: str) -> dict[str, Any] | None:
    txt = strip_json_fence(text)
    try:
        obj = json.loads(txt)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    start = txt.find("{")
    end = txt.rfind("}")
    if start >= 0 and end > start:
        try:
            obj = json.loads(txt[start : end + 1])
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None
    return None


def coerce_string(value: Any, *, default: str = "", max_len: int | None = None) -> str:
    if value is None:
        out = default
    elif isinstance(value, str):
        out = value.strip()
    else:
        try:
            out = json.dumps(value, ensure_ascii=False)
        except Exception:
            out = str(value)
        out = out.strip()
    if max_len is not None and len(out) > max_len:
        out = out[:max_len].rstrip()
    return out


def _split_listish_text(text: str) -> list[str]:
    t = str(text or "").strip()
    if not t:
        return []
    if t.startswith("[") and t.endswith("]"):
        try:
            parsed = json.loads(t)
            if isinstance(parsed, list):
                return [coerce_string(x) for x in parsed]
        except Exception:
            pass

    parts: list[str] = []
    for line in t.splitlines():
        s = line.strip()
        if not s:
            continue
        s = re.sub(r"^\s*[-*•]\s*", "", s)
        # If the model returns "1) foo" style bullets, strip the ordinal.
        s = re.sub(r"^\d+[\.\)]\s*", "", s)
        if ";" in s:
            parts.extend([p.strip() for p in s.split(";")])
        else:
            parts.append(s)
    return [p for p in parts if p]


def coerce_string_list(
    value: Any,
    *,
    max_items: int,
    max_item_len: int = 300,
) -> list[str]:
    items: list[Any]
    if value is None:
        items = []
    elif isinstance(value, list):
        items = value
    elif isinstance(value, tuple):
        items = list(value)
    elif isinstance(value, str):
        items = _split_listish_text(value)
    else:
        items = [value]
    out: list[str] = []
    for item in items:
        s = coerce_string(item, max_len=max_item_len).strip()
        if s:
            out.append(s)
        if len(out) >= max_items:
            break
    return out


def normalize_confidence_label(value: Any, *, default: str = "medium") -> str:
    txt = coerce_string(value, max_len=32).lower()
    if not txt:
        return default
    if txt in {"low", "medium", "high"}:
        return txt
    if "low" in txt:
        return "low"
    if "high" in txt:
        return "high"
    if "med" in txt:
        return "medium"
    try:
        num = float(txt)
        if num < 0.34:
            return "low"
        if num < 0.67:
            return "medium"
        return "high"
    except Exception:
        return default

