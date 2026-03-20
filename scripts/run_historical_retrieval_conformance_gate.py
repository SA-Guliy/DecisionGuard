#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.architecture_v3 import (
    historical_conformance_path,
    historical_context_pack_path,
    load_json_with_integrity,
    reasoning_memory_ledger_path,
    save_json_with_sidecar,
    write_gate_result,
)
from src.security_utils import sha256_sidecar_path


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _normalize_artifact_ref(raw: Any) -> str:
    text = str(raw or "").strip()
    if text.startswith("artifact:"):
        text = text[len("artifact:") :]
    if "#" in text:
        text = text.split("#", 1)[0]
    return text.strip()


def _usage_from_agent_payload(payload: dict[str, Any], expected_ref: str, expected_sha256: str) -> tuple[bool, bool, list[str]]:
    reasons: list[str] = []
    integrity_failed = False
    hist = payload.get("historical_context", {}) if isinstance(payload.get("historical_context"), dict) else {}
    used_flag = _bool(hist.get("used"))
    ref = _normalize_artifact_ref(hist.get("pack_ref", ""))

    prov = payload.get("llm_provenance", {}) if isinstance(payload.get("llm_provenance"), dict) else {}
    prov_hist = prov.get("historical_context", {}) if isinstance(prov.get("historical_context"), dict) else {}
    if not used_flag:
        used_flag = _bool(prov_hist.get("used"))
    if not ref:
        ref = _normalize_artifact_ref(prov_hist.get("pack_ref", ""))

    ev = payload.get("evidence", {}) if isinstance(payload.get("evidence"), dict) else {}
    ev_hist = _normalize_artifact_ref(ev.get("historical_context_pack", ""))
    trace_refs = payload.get("trace_refs", [])
    trace_refs = trace_refs if isinstance(trace_refs, list) else []
    normalized_trace_refs = [_normalize_artifact_ref(x) for x in trace_refs]
    artifact_hash_refs = payload.get("artifact_hash_refs", [])
    artifact_hash_refs = artifact_hash_refs if isinstance(artifact_hash_refs, list) else []
    hash_match = False
    hash_ref_present = False
    for row in artifact_hash_refs:
        if not isinstance(row, dict):
            continue
        art_ref = _normalize_artifact_ref(row.get("artifact_ref", ""))
        sha = str(row.get("sha256", "")).strip().lower()
        if art_ref != expected_ref:
            continue
        hash_ref_present = True
        if sha and sha == expected_sha256:
            hash_match = True

    reasoning_refs: list[str] = []
    vrt = payload.get("visible_reasoning_trace", {})
    claims = vrt.get("claims", []) if isinstance(vrt, dict) and isinstance(vrt.get("claims"), list) else []
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        refs = claim.get("evidence_refs", [])
        if isinstance(refs, list):
            reasoning_refs.extend([_normalize_artifact_ref(x) for x in refs])
    reasons_blob = payload.get("reasons", [])
    if isinstance(reasons_blob, list):
        for row in reasons_blob:
            if not isinstance(row, dict):
                continue
            refs = row.get("evidence_refs", [])
            if isinstance(refs, list):
                reasoning_refs.extend([_normalize_artifact_ref(x) for x in refs])
    reasoning_used = expected_ref in reasoning_refs or ev_hist == expected_ref

    if not used_flag:
        reasons.append("used_flag_false")
    if ref and ref != expected_ref:
        reasons.append("pack_ref_mismatch")
        integrity_failed = True
    if expected_ref not in normalized_trace_refs:
        reasons.append("trace_ref_missing")
        integrity_failed = True
    if not hash_ref_present:
        reasons.append("artifact_hash_ref_missing")
        integrity_failed = True
    elif not hash_match:
        reasons.append("artifact_hash_mismatch")
        integrity_failed = True
    if ev_hist and ev_hist != expected_ref:
        reasons.append("evidence_ref_mismatch")
        integrity_failed = True
    if not ref and not ev_hist:
        reasons.append("missing_pack_reference")
        integrity_failed = True
    if not reasoning_used:
        reasons.append("reasoning_ref_absent")
    if not reasons:
        return True, False, []
    return False, integrity_failed, reasons


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Doctor/Commander conformance to historical context usage")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    pack_path = historical_context_pack_path(run_id)
    doctor_path = Path(f"data/agent_reports/{run_id}_doctor_variance.json")
    commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")

    status = "PASS"
    error_code = "NONE"
    severity_rank = {
        "NONE": 0,
        "HISTORICAL_CONTEXT_UNUSED": 1,
        "HISTORICAL_CONTEXT_MISSING": 2,
        "HISTORICAL_CONTEXT_INTEGRITY_FAIL": 3,
    }
    blocked_by: list[str] = []
    required_actions: list[str] = []
    details: dict[str, Any] = {}

    def _set_error(code: str) -> None:
        nonlocal error_code
        cur = severity_rank.get(error_code, 0)
        nxt = severity_rank.get(code, 0)
        if nxt >= cur:
            error_code = code

    try:
        pack = load_json_with_integrity(pack_path)
    except Exception as exc:
        status = "FAIL"
        _set_error("HISTORICAL_CONTEXT_INTEGRITY_FAIL")
        blocked_by.append("historical_context_pack_missing_or_invalid")
        required_actions.append("run_historical_retrieval_gate")
        details["pack_error"] = str(exc)
        pack = {}

    if isinstance(pack, dict):
        if str(pack.get("status", "")).upper() != "PASS":
            status = "FAIL"
            _set_error("HISTORICAL_CONTEXT_MISSING")
            blocked_by.append("historical_context_pack_status_fail")
            required_actions.append("fix_historical_context_pack_before_doctor")
        if not isinstance(pack.get("rows"), list) or len(pack.get("rows", [])) == 0:
            status = "FAIL"
            _set_error("HISTORICAL_CONTEXT_MISSING")
            blocked_by.append("historical_context_pack_empty")
            required_actions.append("ensure_non_empty_historical_context_pack")

    doctor = {}
    commander = {}
    try:
        doctor = load_json_with_integrity(doctor_path)
    except Exception as exc:
        status = "FAIL"
        _set_error("HISTORICAL_CONTEXT_UNUSED")
        blocked_by.append("doctor_artifact_missing_or_invalid")
        required_actions.append("run_doctor_after_historical_context_input_gate")
        details["doctor_error"] = str(exc)

    try:
        commander = load_json_with_integrity(commander_path)
    except Exception as exc:
        status = "FAIL"
        _set_error("HISTORICAL_CONTEXT_UNUSED")
        blocked_by.append("commander_artifact_missing_or_invalid")
        required_actions.append("run_commander_after_doctor")
        details["commander_error"] = str(exc)

    expected_ref = str(pack_path)
    sidecar_path = sha256_sidecar_path(pack_path)
    expected_sha256 = sidecar_path.read_text(encoding="utf-8").strip().lower() if sidecar_path.exists() else ""
    if not expected_sha256:
        status = "FAIL"
        _set_error("HISTORICAL_CONTEXT_INTEGRITY_FAIL")
        blocked_by.append("historical_context_pack_missing_sha256_sidecar")
        required_actions.append("regenerate_historical_context_pack_with_integrity")
    if isinstance(doctor, dict):
        doctor_used, doctor_integrity_failed, doctor_reasons = _usage_from_agent_payload(doctor, expected_ref, expected_sha256)
        details["doctor_usage_reasons"] = doctor_reasons
        details["doctor_used"] = doctor_used
        if not doctor_used:
            status = "FAIL"
            _set_error("HISTORICAL_CONTEXT_INTEGRITY_FAIL" if doctor_integrity_failed else "HISTORICAL_CONTEXT_UNUSED")
            blocked_by.append("doctor_historical_context_not_used")
            required_actions.append("doctor_must_consume_historical_context_pack")

    if isinstance(commander, dict):
        commander_used, commander_integrity_failed, commander_reasons = _usage_from_agent_payload(
            commander, expected_ref, expected_sha256
        )
        details["commander_usage_reasons"] = commander_reasons
        details["commander_used"] = commander_used
        if not commander_used:
            status = "FAIL"
            _set_error("HISTORICAL_CONTEXT_INTEGRITY_FAIL" if commander_integrity_failed else "HISTORICAL_CONTEXT_UNUSED")
            blocked_by.append("commander_historical_context_not_used")
            required_actions.append("commander_must_consume_historical_context_pack")

    payload = {
        "version": "historical_retrieval_conformance_gate_v1",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "error_code": error_code,
        "blocked_by": sorted({x for x in blocked_by if x})[:20],
        "required_actions": sorted({x for x in required_actions if x})[:20],
        "historical_context_pack_ref": expected_ref,
        "doctor_ref": str(doctor_path),
        "commander_ref": str(commander_path),
        "details": details,
    }
    save_json_with_sidecar(historical_conformance_path(run_id), payload)

    # append an immutable usage marker into memory ledger
    try:
        ledger_path = reasoning_memory_ledger_path(run_id)
        ledger = load_json_with_integrity(ledger_path)
        entries = ledger.get("entries", []) if isinstance(ledger.get("entries"), list) else []
        entries.append(
            {
                "stage": "historical_retrieval_conformance_gate",
                "artifact_ref": f"artifact:{historical_conformance_path(run_id)}",
                "used": status == "PASS",
                "usage_note": "doctor+commander historical-context usage validated",
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        ledger["entries"] = entries[:50]
        save_json_with_sidecar(ledger_path, ledger)
    except Exception:
        # Non-fatal here: conformance gate result stays primary signal.
        pass

    write_gate_result(
        run_id,
        gate_name="historical_retrieval_conformance_gate",
        status=status,
        error_code=error_code,
        blocked_by=payload["blocked_by"],
        required_actions=payload["required_actions"],
        details=details,
    )

    if status != "PASS":
        raise SystemExit(1)
    print(f"ok: historical retrieval conformance gate PASS for run_id={run_id}")


if __name__ == "__main__":
    main()
