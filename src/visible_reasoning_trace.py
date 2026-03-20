from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from src.security_utils import verify_sha256_sidecar


ROOT = Path(__file__).resolve().parents[1]
TRACE_SCHEMA_PATH = ROOT / "configs/contracts/visible_reasoning_trace_v1.json"


@dataclass(frozen=True)
class VisibleReasoningTraceCaps:
    max_claims: int = 20
    max_gates: int = 30
    max_unknowns: int = 20
    max_evidence_refs_per_claim: int = 8
    max_alternatives_per_claim: int = 5
    max_claim_id_len: int = 120
    max_statement_len: int = 400
    max_ref_len: int = 240
    max_alternative_len: int = 220
    max_falsifiability_len: int = 320
    max_decision_impact_len: int = 320
    max_gate_len: int = 220
    max_unknown_len: int = 260


DEFAULT_TRACE_CAPS = VisibleReasoningTraceCaps()
_CACHED_SCHEMA: dict[str, Any] | None = None


def empty_visible_reasoning_trace() -> dict[str, Any]:
    return {"claims": [], "gates_checked": [], "unknowns": []}


def _cap_text(value: Any, max_len: int, redact_text: Callable[[str], str] | None = None) -> str:
    text = str(value or "").strip()
    if redact_text is not None and text:
        text = redact_text(text)
    if len(text) > max_len:
        text = text[:max_len].rstrip()
    return text


def _cap_list_of_strings(
    values: Any,
    *,
    max_items: int,
    max_item_len: int,
    redact_text: Callable[[str], str] | None = None,
) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for raw in values[:max_items]:
        text = _cap_text(raw, max_item_len, redact_text=redact_text)
        if text:
            out.append(text)
    return out


def _normalize_claim(
    raw: Any,
    *,
    claim_index: int,
    trace_prefix: str,
    caps: VisibleReasoningTraceCaps,
    redact_text: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    d = raw if isinstance(raw, dict) else {}
    claim_id = _cap_text(d.get("claim_id"), caps.max_claim_id_len, redact_text=redact_text)
    if not claim_id:
        claim_id = f"{trace_prefix}:claim:{claim_index}"
    statement = _cap_text(d.get("statement"), caps.max_statement_len, redact_text=redact_text)
    if not statement:
        statement = "No statement provided."
    falsifiability_test = _cap_text(
        d.get("falsifiability_test"),
        caps.max_falsifiability_len,
        redact_text=redact_text,
    )
    if not falsifiability_test:
        falsifiability_test = "Re-check the same evidence sources after input refresh."
    decision_impact = _cap_text(
        d.get("decision_impact"),
        caps.max_decision_impact_len,
        redact_text=redact_text,
    )
    if not decision_impact:
        decision_impact = "Advisory rationale only; business decision remains deterministic."
    evidence_refs = _cap_list_of_strings(
        d.get("evidence_refs"),
        max_items=caps.max_evidence_refs_per_claim,
        max_item_len=caps.max_ref_len,
        redact_text=redact_text,
    )
    alternatives = _cap_list_of_strings(
        d.get("alternatives_considered"),
        max_items=caps.max_alternatives_per_claim,
        max_item_len=caps.max_alternative_len,
        redact_text=redact_text,
    )
    if not alternatives:
        alternatives = ["unknown"]
    return {
        "claim_id": claim_id,
        "statement": statement,
        "evidence_refs": evidence_refs,
        "alternatives_considered": alternatives,
        "falsifiability_test": falsifiability_test,
        "decision_impact": decision_impact,
    }


def cap_visible_reasoning_trace(
    trace: Any,
    *,
    trace_prefix: str = "trace",
    caps: VisibleReasoningTraceCaps = DEFAULT_TRACE_CAPS,
    redact_text: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    source = trace if isinstance(trace, dict) else {}
    claims_in = source.get("claims", [])
    claims: list[dict[str, Any]] = []
    if isinstance(claims_in, list):
        for idx, raw_claim in enumerate(claims_in[: caps.max_claims], start=1):
            claims.append(
                _normalize_claim(
                    raw_claim,
                    claim_index=idx,
                    trace_prefix=trace_prefix,
                    caps=caps,
                    redact_text=redact_text,
                )
            )

    gates_checked = _cap_list_of_strings(
        source.get("gates_checked"),
        max_items=caps.max_gates,
        max_item_len=caps.max_gate_len,
        redact_text=redact_text,
    )
    unknowns = _cap_list_of_strings(
        source.get("unknowns"),
        max_items=caps.max_unknowns,
        max_item_len=caps.max_unknown_len,
        redact_text=redact_text,
    )
    return {"claims": claims, "gates_checked": gates_checked, "unknowns": unknowns}


def _load_trace_schema() -> dict[str, Any]:
    global _CACHED_SCHEMA
    if _CACHED_SCHEMA is None:
        if not TRACE_SCHEMA_PATH.exists():
            raise RuntimeError(f"missing_contract_file:{TRACE_SCHEMA_PATH}")
        ok, reason = verify_sha256_sidecar(TRACE_SCHEMA_PATH, required=True)
        if not ok:
            raise RuntimeError(f"contract_integrity_error:{reason}")
        try:
            _CACHED_SCHEMA = json.loads(TRACE_SCHEMA_PATH.read_text(encoding="utf-8"))
        except Exception:
            raise RuntimeError(f"invalid_contract_json:{TRACE_SCHEMA_PATH}")
    return _CACHED_SCHEMA


def validate_visible_reasoning_trace(trace: dict[str, Any]) -> None:
    if not isinstance(trace, dict):
        raise ValueError("visible_reasoning_trace must be a dict")
    required = ("claims", "gates_checked", "unknowns")
    for key in required:
        if key not in trace:
            raise ValueError(f"visible_reasoning_trace missing field '{key}'")
    if not isinstance(trace.get("claims"), list):
        raise ValueError("visible_reasoning_trace.claims must be a list")
    if not isinstance(trace.get("gates_checked"), list):
        raise ValueError("visible_reasoning_trace.gates_checked must be a list")
    if not isinstance(trace.get("unknowns"), list):
        raise ValueError("visible_reasoning_trace.unknowns must be a list")
    for idx, gate in enumerate(trace["gates_checked"]):
        if not isinstance(gate, str):
            raise ValueError(f"visible_reasoning_trace.gates_checked[{idx}] must be a string")
    for idx, unk in enumerate(trace["unknowns"]):
        if not isinstance(unk, str):
            raise ValueError(f"visible_reasoning_trace.unknowns[{idx}] must be a string")
    for idx, claim in enumerate(trace["claims"]):
        if not isinstance(claim, dict):
            raise ValueError(f"visible_reasoning_trace.claims[{idx}] must be an object")
        for field in (
            "claim_id",
            "statement",
            "evidence_refs",
            "alternatives_considered",
            "falsifiability_test",
            "decision_impact",
        ):
            if field not in claim:
                raise ValueError(f"visible_reasoning_trace.claims[{idx}] missing '{field}'")

    try:
        from jsonschema import validate as _jsonschema_validate  # type: ignore
    except Exception:
        return
    _jsonschema_validate(instance=trace, schema=_load_trace_schema())


def build_visible_reasoning_trace_advisory(
    *,
    enabled: bool,
    trace_builder: Callable[[], dict[str, Any]],
    trace_prefix: str,
    caps: VisibleReasoningTraceCaps = DEFAULT_TRACE_CAPS,
    redact_text: Callable[[str], str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    meta = {
        "enabled": bool(enabled),
        "mode": "advisory",
        "status": "disabled",
        "fallback": False,
        "caps": {
            "max_claims": int(caps.max_claims),
            "max_gates": int(caps.max_gates),
            "max_unknowns": int(caps.max_unknowns),
            "max_claim_id_len": int(caps.max_claim_id_len),
            "max_statement_len": int(caps.max_statement_len),
            "max_ref_len": int(caps.max_ref_len),
            "max_alternative_len": int(caps.max_alternative_len),
            "max_falsifiability_len": int(caps.max_falsifiability_len),
            "max_decision_impact_len": int(caps.max_decision_impact_len),
            "max_gate_len": int(caps.max_gate_len),
            "max_unknown_len": int(caps.max_unknown_len),
        },
    }
    if not enabled:
        return empty_visible_reasoning_trace(), meta

    try:
        raw_trace = trace_builder()
        normalized_trace = cap_visible_reasoning_trace(
            raw_trace,
            trace_prefix=trace_prefix,
            caps=caps,
            redact_text=redact_text,
        )
        validate_visible_reasoning_trace(normalized_trace)
        meta["status"] = "ok"
        return normalized_trace, meta
    except Exception as exc:
        meta["status"] = "fallback_empty"
        meta["fallback"] = True
        meta["error"] = _cap_text(str(exc), 240, redact_text=redact_text)
        return empty_visible_reasoning_trace(), meta
