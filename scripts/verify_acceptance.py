#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_profile import load_security_profile
from src.architecture_v3 import (
    REQUIRED_GATE_ORDER,
    PAIRED_CTRL_FOUNDATION_ALLOWED_STEPS,
    PAIRED_STATUS_LIFECYCLE_ALLOWED,
    PAIRED_STATUS_ENUM,
    SANITIZATION_POLICY_PATH,
    SANITIZATION_TRANSFORM_PATH,
    RECONCILIATION_POLICY_PATH,
    anti_goodhart_verdict_path,
    ctrl_foundation_audit_path,
    context_frame_path,
    decision_outcomes_ledger_path,
    governance_ceiling_path,
    handoff_guard_path,
    historical_conformance_path,
    historical_context_pack_path,
    list_gate_results,
    load_gate_result,
    load_json_with_integrity,
    offline_kpi_backtest_path,
    paired_experiment_context_path,
    quality_invariants_path,
    reasoning_memory_ledger_path,
    reasoning_policy_path,
    stat_evidence_bundle_path,
    validate_v3_contract_set,
)
from src.runtime_controls import load_feature_state_contract, load_runtime_limits_contract
from src.security_utils import verify_json_manifest, verify_manifest_scope, verify_sha256_sidecar
from src.sanitization_transform import verify_encrypted_map_document
from src.paired_registry import is_partial_like, load_registry_for_run

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]


def _redact(text: str) -> str:
    out = text
    for pat, repl in REDACTION_PATTERNS:
        out = pat.sub(repl, out)
    return out


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _safe_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(json.dumps(payload, ensure_ascii=False, indent=2)), encoding="utf-8")


def _safe_write_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(text), encoding="utf-8")


def _snippet(value: Any, max_len: int = 140) -> str:
    try:
        txt = json.dumps(value, ensure_ascii=False)
    except Exception:
        txt = str(value)
    txt = txt.replace("\n", " ")
    return txt[:max_len] + ("..." if len(txt) > max_len else "")


def _check(
    status: str,
    reason_code: str,
    evidence_path: str,
    evidence_snippet: Any,
    severity: str = "ADVISORY",
) -> dict[str, Any]:
    return {
        "status": status,
        "severity": severity,
        "reason_code": reason_code,
        "evidence_path": evidence_path,
        "evidence_snippet": _snippet(evidence_snippet),
    }


def _schema_ok(doc: dict[str, Any], required: dict[str, type]) -> tuple[bool, list[str]]:
    missing: list[str] = []
    for key, typ in required.items():
        if key not in doc:
            missing.append(f"missing:{key}")
            continue
        if not isinstance(doc.get(key), typ):
            missing.append(f"type:{key}")
    return (len(missing) == 0, missing)


def _validate_doctor_hypothesis_review_structure(commander_doc: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    issues: list[str] = []
    rows = commander_doc.get("doctor_hypothesis_review")
    summary = commander_doc.get("hypothesis_review_summary")
    if not isinstance(rows, list):
        return False, {"issues": ["missing_or_invalid:doctor_hypothesis_review"], "missing": True}
    if not isinstance(summary, dict):
        return False, {"issues": ["missing_or_invalid:hypothesis_review_summary"], "missing": True}

    allowed = {"SUPPORTED", "WEAK", "REFUTED", "UNTESTABLE"}
    refuted_high = 0
    misaligned = 0
    counts = {"SUPPORTED": 0, "WEAK": 0, "REFUTED": 0, "UNTESTABLE": 0}
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            issues.append(f"row_not_object:{idx}")
            continue
        if not str(row.get("hypothesis_id", "")).strip():
            issues.append(f"missing_hypothesis_id:{idx}")
        det = str(row.get("deterministic_verdict", "")).strip().upper()
        final = str(row.get("final_verdict", "")).strip().upper()
        if det not in allowed:
            issues.append(f"invalid_deterministic_verdict:{idx}")
        if final not in allowed:
            issues.append(f"invalid_final_verdict:{idx}")
        if det == "REFUTED" and final == "SUPPORTED":
            issues.append(f"forbidden_upgrade_refuted_to_supported:{idx}")
        goal_alignment = str(row.get("goal_alignment", "")).strip().lower()
        if goal_alignment not in {"aligned", "misaligned", "unknown"}:
            issues.append(f"invalid_goal_alignment:{idx}")
        else:
            if goal_alignment == "misaligned":
                misaligned += 1
        cross_goal_reference = row.get("cross_goal_reference")
        if cross_goal_reference is not None and not isinstance(cross_goal_reference, str):
            issues.append(f"invalid_cross_goal_reference:{idx}")
        refs = row.get("evidence_refs")
        if not isinstance(refs, list):
            issues.append(f"invalid_evidence_refs:{idx}")
        if final in counts:
            counts[final] += 1
        if final == "REFUTED" and str(row.get("impact_class", "")).strip().lower() == "high":
            refuted_high += 1

    total_raw = summary.get("total_count", -1)
    total_count = int(total_raw) if total_raw is not None else -1
    if total_count != len(rows):
        issues.append("summary_total_mismatch")
    supported_raw = summary.get("supported_count", -1)
    supported_count = int(supported_raw) if supported_raw is not None else -1
    if supported_count != counts["SUPPORTED"]:
        issues.append("summary_supported_mismatch")
    weak_raw = summary.get("weak_count", -1)
    weak_count = int(weak_raw) if weak_raw is not None else -1
    if weak_count != counts["WEAK"]:
        issues.append("summary_weak_mismatch")
    refuted_raw = summary.get("refuted_count", -1)
    refuted_count = int(refuted_raw) if refuted_raw is not None else -1
    if refuted_count != counts["REFUTED"]:
        issues.append("summary_refuted_mismatch")
    untestable_raw = summary.get("untestable_count", -1)
    untestable_count = int(untestable_raw) if untestable_raw is not None else -1
    if untestable_count != counts["UNTESTABLE"]:
        issues.append("summary_untestable_mismatch")
    misaligned_raw = summary.get("misaligned_hypothesis_count", -1)
    misaligned_count = int(misaligned_raw) if misaligned_raw is not None else -1
    if misaligned_count != misaligned:
        issues.append("summary_misaligned_count_mismatch")
    alignment_status = str(summary.get("goal_alignment_status", "")).strip().upper()
    if alignment_status not in {"PASS", "WARN", "UNKNOWN"}:
        issues.append("goal_alignment_status_invalid")
    else:
        expected_alignment = "UNKNOWN" if alignment_status == "UNKNOWN" else ("PASS" if misaligned == 0 else "WARN")
        if alignment_status != expected_alignment:
            issues.append("goal_alignment_status_mismatch")
    score = summary.get("verification_quality_score")
    try:
        score_f = float(score)
        if score_f < 0.0 or score_f > 1.0:
            issues.append("verification_quality_score_out_of_range")
    except Exception:
        issues.append("verification_quality_score_invalid")

    reviewed_ids = {
        str(r.get("hypothesis_id", "")).strip()
        for r in rows
        if isinstance(r, dict) and str(r.get("hypothesis_id", "")).strip()
    }

    return len(issues) == 0, {
        "issues": issues,
        "missing": False,
        "refuted_high_count": refuted_high,
        "misaligned_hypothesis_count": misaligned,
        "row_count": len(rows),
        "reviewed_ids": sorted(reviewed_ids),
    }


def _validate_paired_status_lifecycle(
    *,
    paired_status: str,
    status_history: Any,
) -> tuple[bool, list[str]]:
    issues: list[str] = []
    allowed_lifecycle = set(PAIRED_STATUS_LIFECYCLE_ALLOWED)
    status_norm = str(paired_status or "").strip().upper()
    history = status_history if isinstance(status_history, list) else []
    if not isinstance(status_history, list):
        issues.append("status_history_not_array")
    prev_to: str | None = None
    for idx, row in enumerate(history):
        if not isinstance(row, dict):
            issues.append(f"status_history_row_not_object:{idx}")
            continue
        from_s = str(row.get("from", "")).strip().upper()
        to_s = str(row.get("to", "")).strip().upper()
        if (from_s, to_s) not in allowed_lifecycle:
            issues.append(f"invalid_transition:{from_s}->{to_s}")
        if idx > 0 and prev_to is not None and from_s != prev_to:
            issues.append(f"transition_chain_break:{idx}:{from_s}!={prev_to}")
        prev_to = to_s
    if status_norm in {"PARTIAL", "TREATMENT_FAILED", "CTRL_FAILED"} and len(history) == 0:
        issues.append("non_complete_status_requires_history")
    if len(history) > 0:
        tail_to = str((history[-1] or {}).get("to", "")).strip().upper() if isinstance(history[-1], dict) else ""
        if tail_to != status_norm:
            issues.append("history_tail_mismatch_current_status")
    return (len(issues) == 0, issues)


def _f(v: Any) -> float | None:
    try:
        return float(v)
    except Exception:
        return None


def _parse_iso_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _find_ab_report(run_id: str, experiment_id: str = "") -> Path | None:
    if experiment_id.strip():
        p = Path(f"data/ab_reports/{run_id}_{experiment_id.strip()}_ab.json")
        return p if p.exists() else None
    matches = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab.json"))
    return matches[0] if matches else None


_RUNTIME_SCRIPT_RE = re.compile(r"scripts/[A-Za-z0-9_./-]+\.py")
_FORBIDDEN_RUNTIME_CLOUD_PATTERNS = (
    re.compile(r"^\s*from\s+src\.llm_client\s+import\s+get_llm_backend", re.MULTILINE),
    re.compile(r"(^|[^\"'])_client\.chat\.completions\.create\(", re.MULTILINE),
    re.compile(r"(^|[^\"'])api\.openai\.com", re.MULTILINE),
)

ARTIFACT_SPAM_POLICY_PATH = Path("configs/contracts/artifact_spam_prevention_v2.json")
GOLDEN_PAIR_POLICY_PATH = Path("configs/contracts/golden_pair_policy_v2.json")
CLEANUP_INTEGRITY_POLICY_PATH = Path("configs/contracts/cleanup_integrity_policy_v2.json")
BATCH_TRANSPORT_POLICY_PATH = Path("configs/contracts/batch_record_transport_policy_v2.json")
BATCH_RECORD_CONTRACT_PATH = Path("configs/contracts/batch_record_v2.json")
CLEANUP_MANIFEST_CONTRACT_PATH = Path("configs/contracts/cleanup_manifest_v1.json")
CONSOLIDATED_REPORT_CONTRACT_PATH = Path("configs/contracts/consolidated_report_v1.json")
EXPERIMENT_DURATION_POLICY_PATH = Path("configs/contracts/experiment_duration_policy_v1.json")


def _runtime_ddl_scan_targets() -> list[Path]:
    run_all_path = Path("scripts/run_all.py")
    targets: list[Path] = [run_all_path]
    if not run_all_path.exists():
        return targets
    try:
        text = run_all_path.read_text(encoding="utf-8")
    except Exception:
        return targets
    seen: set[str] = {"scripts/run_all.py"}
    for rel in sorted(set(_RUNTIME_SCRIPT_RE.findall(text))):
        if rel.startswith("scripts/admin_"):
            continue
        if rel in seen:
            continue
        p = Path(rel)
        if p.exists() and p.is_file():
            targets.append(p)
            seen.add(rel)
    return targets


def _load_contract_with_integrity(path: Path) -> tuple[dict[str, Any] | None, str]:
    if not path.exists():
        return None, f"missing_contract:{path}"
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        return None, reason
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"invalid_contract_json:{path}:{exc}"
    if not isinstance(payload, dict):
        return None, f"invalid_contract_payload:{path}"
    return payload, ""


def _match_any(path: Path, globs: list[str]) -> bool:
    norm = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(norm, g.replace("\\", "/")) for g in globs if str(g).strip())


def _runtime_ddl_findings(paths: list[Path]) -> list[dict[str, Any]]:
    tokens = ("create table", "alter table", "drop table", "grant ")
    findings: list[dict[str, Any]] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8").lower()
        except Exception:
            continue
        for token in tokens:
            if token in text:
                findings.append({"path": str(path), "token": token})
    return findings


def _scan_direct_cloud_usage_policy() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    targets = _runtime_ddl_scan_targets()
    poc_path = Path("scripts/run_poc_e2e.py")
    if poc_path.exists() and poc_path not in targets:
        targets.append(poc_path)
    for path in targets:
        if not path.exists():
            findings.append({"path": str(path), "token": "missing_script"})
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            findings.append({"path": str(path), "token": "unreadable_script"})
            continue
        for pat in _FORBIDDEN_RUNTIME_CLOUD_PATTERNS:
            if pat.search(text):
                findings.append({"path": str(path), "token": pat.pattern})
    return findings


def _acceptance_mode() -> str:
    if _to_bool(os.getenv("DS_RELEASE_ACCEPTANCE", "0")):
        return "release"
    if _to_bool(os.getenv("DS_NIGHTLY_ACCEPTANCE", "0")):
        return "nightly"
    return "run"


def _payload_has_cloud_backend(payload: Any) -> bool:
    cloud_values = {"groq", "openai", "anthropic"}
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_l = str(key).strip().lower()
            if key_l in {"backend", "backend_requested", "provider"}:
                if str(value or "").strip().lower() in cloud_values:
                    return True
            if _payload_has_cloud_backend(value):
                return True
        return False
    if isinstance(payload, list):
        for item in payload:
            if _payload_has_cloud_backend(item):
                return True
    return False


def _validate_mitigation_policy(payload: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    decision = str(payload.get("normalized_decision", payload.get("decision", ""))).upper().strip()
    if decision not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"}:
        return True, {"decision": decision, "required": False}

    proposals = payload.get("mitigation_proposals", [])
    valid_count = 0
    if isinstance(proposals, list):
        for row in proposals:
            if not isinstance(row, dict):
                continue
            app = str(row.get("applicability", "")).strip()
            tradeoff = str(row.get("risk_tradeoff", "")).strip()
            refs = row.get("evidence_refs", [])
            req = row.get("required_data", [])
            try:
                conf = float(row.get("confidence"))
            except Exception:
                conf = -1.0
            if app and tradeoff and isinstance(refs, list) and refs and isinstance(req, list) and req and (0.0 < conf <= 1.0):
                valid_count += 1

    insufficient = payload.get("insufficient_evidence", {})
    has_fallback = (
        isinstance(insufficient, dict)
        and isinstance(insufficient.get("required_data"), list)
        and len(insufficient.get("required_data", [])) > 0
        and isinstance(insufficient.get("next_validation_plan"), list)
        and len(insufficient.get("next_validation_plan", [])) > 0
    )
    ok = valid_count >= 2 or has_fallback
    return ok, {
        "decision": decision,
        "valid_mitigation_count": valid_count,
        "has_insufficient_evidence_fallback": has_fallback,
    }


def _validate_online_kpi(payload: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    system = payload.get("system", {}) if isinstance(payload.get("system"), dict) else {}
    required = ("prevented_loss_proxy_rate", "unsafe_rollout_block_rate", "evidence_coverage_rate")
    missing = [k for k in required if k not in system]
    return len(missing) == 0, {"missing": missing, "present": [k for k in required if k in system]}


def _icon(status: str) -> str:
    return {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "NA": "⚪ NA"}.get(status, status)


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _to_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def _classify_weak_reconciliation_event(row: dict[str, Any], topic: str) -> str | None:
    topic_norm = str(topic or "").strip().lower()
    if topic_norm == "ai.reasoning.weak_path_detected.v1":
        return "weak_reasoning_result"
    if topic_norm == "ai.reconciliation.requested.v1":
        return "reconciliation_request"
    if topic_norm == "ai.reconciliation.completed.v1":
        return "reconciliation_result"
    if topic_norm == "ai.reconciliation.recommended_override.v1":
        return "recommended_override"

    if (
        "audited_by_weak_model" in row
        and "decision_ceiling_applied" in row
        and "source_event_id" in row
    ):
        return "weak_reasoning_result"
    if (
        "reconciliation_id" in row
        and "requested_at" in row
        and "payload_ref" in row
    ):
        return "reconciliation_request"
    if (
        "reconciliation_id" in row
        and "completed_at" in row
        and "reconciliation_status" in row
    ):
        return "reconciliation_result"
    if (
        "reconciliation_id" in row
        and "recommended_decision" in row
        and "human_approval_required" in row
    ):
        return "recommended_override"
    return None


def _extract_run_events_from_payload(raw: Any, *, run_id: str, source_path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def _push(candidate: Any, *, topic_hint: str = "") -> None:
        if not isinstance(candidate, dict):
            return
        topic_local = str(candidate.get("topic", "") or topic_hint).strip()
        row = candidate
        if isinstance(candidate.get("payload"), dict):
            row = dict(candidate.get("payload") or {})
            if topic_local and "topic" not in row:
                row["topic"] = topic_local
        run_value = str(row.get("run_id", "")).strip()
        if run_value != run_id:
            return
        kind = _classify_weak_reconciliation_event(row, str(row.get("topic", "") or topic_local))
        if not kind:
            return
        normalized = dict(row)
        normalized["__kind"] = kind
        normalized["__topic"] = str(row.get("topic", "") or topic_local)
        normalized["__source_path"] = source_path
        out.append(normalized)

    if isinstance(raw, dict):
        _push(raw)
        topic = str(raw.get("topic", "")).strip()
        for key in ("events", "items", "records"):
            rows = raw.get(key)
            if isinstance(rows, list):
                for item in rows:
                    _push(item, topic_hint=topic)
    elif isinstance(raw, list):
        for item in raw:
            _push(item)
    return out


def _collect_weak_reconciliation_events(run_id: str) -> list[dict[str, Any]]:
    candidates: set[Path] = set()
    event_bus_dir = Path("data/event_bus")
    if event_bus_dir.exists():
        for path in event_bus_dir.rglob("*.json"):
            candidates.add(path)
    globs = [
        f"data/agent_reports/{run_id}_*weak*.json",
        f"data/agent_reports/{run_id}_*reconciliation*.json",
        f"data/decision_traces/*{run_id}*weak*.json",
        f"data/decision_traces/*{run_id}*reconciliation*.json",
    ]
    for pattern in globs:
        for path in Path().glob(pattern):
            if path.is_file():
                candidates.add(path)

    out: list[dict[str, Any]] = []
    for path in sorted(candidates):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.extend(_extract_run_events_from_payload(raw, run_id=run_id, source_path=str(path)))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic acceptance verification for P0 Agent Value")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--require-pre-publish", type=int, default=1)
    args = parser.parse_args()

    run_id = args.run_id
    require_pre_publish = bool(args.require_pre_publish)
    security_profile = load_security_profile()
    strict_manifest_scope = bool(security_profile.get("strict_manifest_scope", True))
    manifest_scope_ignore_globs = [str(x) for x in security_profile.get("manifest_scope_ignore_globs", []) if str(x).strip()]
    log_path = Path(f"data/logs/verify_acceptance_{run_id}.log")

    agent_eval_path = Path(f"data/agent_eval/{run_id}_agent_value_eval.json")
    governance_path = Path(f"data/agent_governance/{run_id}_agent_approvals.json")
    adversarial_path = Path(f"data/eval/adversarial_suite_{run_id}.json")
    vector_quality_path = Path(f"data/agent_reports/{run_id}_vector_quality.json")
    scorecard_path = Path(f"reports/L1_ops/{run_id}/AGENT_VALUE_SCORECARD.md")
    demo_index_path = Path(f"reports/L1_ops/{run_id}/DEMO_INDEX.md")
    causal_md_path = Path(f"reports/L1_ops/{run_id}/CAUSAL_EXPLANATION.md")
    narrative_path = Path(f"data/agent_reports/{run_id}_narrative_claims.json")
    validation_path = Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json")
    synthetic_bias_path = Path(f"data/realism_reports/{run_id}_synthetic_bias.json")
    captain_path = Path(f"data/llm_reports/{run_id}_captain.json")
    doctor_path = Path(f"data/agent_reports/{run_id}_doctor_variance.json")
    evaluator_path = Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")
    commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
    poc_path = Path(f"data/agent_reports/{run_id}_poc_sprint2.json")
    pre_publish_path = Path(f"data/agent_quality/{run_id}_pre_publish_audit.json")
    decision_card_path = Path(f"reports/L1_ops/{run_id}/decision_card.md")
    decision_contract_path = Path("configs/contracts/decision_contract_v2.json")
    runtime_guard_path = Path(f"data/runtime_guard/{run_id}_runtime_guard.json")
    ab_path = _find_ab_report(run_id, args.experiment_id)

    agent_eval = _read_json(agent_eval_path) or {}
    governance = _read_json(governance_path) or {}
    adversarial = _read_json(adversarial_path) or {}
    vector_quality = _read_json(vector_quality_path) or {}
    narrative = _read_json(narrative_path) or {}
    validation = _read_json(validation_path) or {}
    synthetic_bias = _read_json(synthetic_bias_path) or {}
    captain = _read_json(captain_path) or {}
    doctor = _read_json(doctor_path) or {}
    evaluator = _read_json(evaluator_path) or {}
    commander = _read_json(commander_path) or {}
    poc_payload = _read_json(poc_path) if poc_path.exists() else {}
    pre_publish = _read_json(pre_publish_path) if pre_publish_path.exists() else None
    ab = _read_json(ab_path) if ab_path else None
    decision_contract = _read_json(decision_contract_path) or {}
    reasoning_check_names = (
        decision_contract.get("reasoning_checks", {}).get("advisory_defaults", [])
        if isinstance(decision_contract.get("reasoning_checks"), dict)
        else []
    )
    if not isinstance(reasoning_check_names, list) or not reasoning_check_names:
        reasoning_check_names = [
            "trace_completeness_rate",
            "alternative_hypothesis_quality",
            "falsifiability_specificity",
            "decision_change_sensitivity",
        ]

    checks: dict[str, dict[str, Any]] = {}
    runtime_limits: dict[str, Any] = {}
    feature_state: dict[str, Any] = {}
    runtime_limits_error = ""
    feature_state_error = ""
    try:
        runtime_limits = load_runtime_limits_contract()
    except Exception as exc:
        runtime_limits_error = str(exc)
    try:
        feature_state = load_feature_state_contract()
    except Exception as exc:
        feature_state_error = str(exc)

    checks["runtime_limits_contract_loaded"] = _check(
        "PASS" if not runtime_limits_error else "FAIL",
        "runtime_limits_contract_invalid" if runtime_limits_error else "runtime_limits_contract_loaded",
        "configs/contracts/runtime_limits_v1.json",
        runtime_limits_error or runtime_limits,
        "CRITICAL",
    )
    checks["feature_state_contract_loaded"] = _check(
        "PASS" if not feature_state_error else "FAIL",
        "feature_state_contract_invalid" if feature_state_error else "feature_state_contract_loaded",
        "configs/contracts/feature_state_v1.json",
        feature_state_error or feature_state,
        "CRITICAL",
    )
    artifact_spam_contract, artifact_spam_contract_err = _load_contract_with_integrity(ARTIFACT_SPAM_POLICY_PATH)
    golden_pair_contract, golden_pair_contract_err = _load_contract_with_integrity(GOLDEN_PAIR_POLICY_PATH)
    cleanup_integrity_contract, cleanup_integrity_contract_err = _load_contract_with_integrity(CLEANUP_INTEGRITY_POLICY_PATH)
    batch_transport_contract, batch_transport_contract_err = _load_contract_with_integrity(BATCH_TRANSPORT_POLICY_PATH)
    batch_record_contract, batch_record_contract_err = _load_contract_with_integrity(BATCH_RECORD_CONTRACT_PATH)
    cleanup_manifest_contract, cleanup_manifest_contract_err = _load_contract_with_integrity(CLEANUP_MANIFEST_CONTRACT_PATH)
    consolidated_report_contract, consolidated_report_contract_err = _load_contract_with_integrity(CONSOLIDATED_REPORT_CONTRACT_PATH)
    experiment_duration_contract, experiment_duration_contract_err = _load_contract_with_integrity(
        EXPERIMENT_DURATION_POLICY_PATH
    )
    checks["artifact_spam_prevention_contract_loaded"] = _check(
        "PASS" if not artifact_spam_contract_err else "FAIL",
        "artifact_spam_prevention_contract_invalid" if artifact_spam_contract_err else "artifact_spam_prevention_contract_loaded",
        str(ARTIFACT_SPAM_POLICY_PATH),
        artifact_spam_contract if isinstance(artifact_spam_contract, dict) else {"error": artifact_spam_contract_err},
        "CRITICAL",
    )
    checks["golden_pair_policy_contract_loaded"] = _check(
        "PASS" if not golden_pair_contract_err else "FAIL",
        "golden_pair_policy_contract_invalid" if golden_pair_contract_err else "golden_pair_policy_contract_loaded",
        str(GOLDEN_PAIR_POLICY_PATH),
        golden_pair_contract if isinstance(golden_pair_contract, dict) else {"error": golden_pair_contract_err},
        "CRITICAL",
    )
    checks["cleanup_integrity_policy_contract_loaded"] = _check(
        "PASS" if not cleanup_integrity_contract_err else "FAIL",
        "cleanup_integrity_policy_contract_invalid" if cleanup_integrity_contract_err else "cleanup_integrity_policy_contract_loaded",
        str(CLEANUP_INTEGRITY_POLICY_PATH),
        cleanup_integrity_contract
        if isinstance(cleanup_integrity_contract, dict)
        else {"error": cleanup_integrity_contract_err},
        "CRITICAL",
    )
    checks["batch_record_transport_policy_contract_loaded"] = _check(
        "PASS" if not batch_transport_contract_err else "FAIL",
        "batch_record_transport_policy_contract_invalid" if batch_transport_contract_err else "batch_record_transport_policy_contract_loaded",
        str(BATCH_TRANSPORT_POLICY_PATH),
        batch_transport_contract if isinstance(batch_transport_contract, dict) else {"error": batch_transport_contract_err},
        "CRITICAL",
    )
    checks["batch_record_contract_loaded"] = _check(
        "PASS" if not batch_record_contract_err else "FAIL",
        "batch_record_contract_invalid" if batch_record_contract_err else "batch_record_contract_loaded",
        str(BATCH_RECORD_CONTRACT_PATH),
        batch_record_contract if isinstance(batch_record_contract, dict) else {"error": batch_record_contract_err},
        "CRITICAL",
    )
    checks["cleanup_manifest_contract_loaded"] = _check(
        "PASS" if not cleanup_manifest_contract_err else "FAIL",
        "cleanup_manifest_contract_invalid" if cleanup_manifest_contract_err else "cleanup_manifest_contract_loaded",
        str(CLEANUP_MANIFEST_CONTRACT_PATH),
        cleanup_manifest_contract if isinstance(cleanup_manifest_contract, dict) else {"error": cleanup_manifest_contract_err},
        "CRITICAL",
    )
    checks["consolidated_report_contract_loaded"] = _check(
        "PASS" if not consolidated_report_contract_err else "FAIL",
        "consolidated_report_contract_invalid" if consolidated_report_contract_err else "consolidated_report_contract_loaded",
        str(CONSOLIDATED_REPORT_CONTRACT_PATH),
        consolidated_report_contract if isinstance(consolidated_report_contract, dict) else {"error": consolidated_report_contract_err},
        "CRITICAL",
    )
    checks["experiment_duration_policy_contract_loaded"] = _check(
        "PASS" if not experiment_duration_contract_err else "FAIL",
        "experiment_duration_policy_contract_invalid"
        if experiment_duration_contract_err
        else "experiment_duration_policy_contract_loaded",
        str(EXPERIMENT_DURATION_POLICY_PATH),
        experiment_duration_contract
        if isinstance(experiment_duration_contract, dict)
        else {"error": experiment_duration_contract_err},
        "CRITICAL",
    )

    artifact_spam_policy = (
        artifact_spam_contract.get("policy")
        if isinstance(artifact_spam_contract, dict) and isinstance(artifact_spam_contract.get("policy"), dict)
        else {}
    )
    golden_pair_policy = (
        golden_pair_contract.get("policy")
        if isinstance(golden_pair_contract, dict) and isinstance(golden_pair_contract.get("policy"), dict)
        else {}
    )
    cleanup_integrity_policy = (
        cleanup_integrity_contract.get("policy")
        if isinstance(cleanup_integrity_contract, dict) and isinstance(cleanup_integrity_contract.get("policy"), dict)
        else {}
    )
    batch_transport_policy = (
        batch_transport_contract.get("policy")
        if isinstance(batch_transport_contract, dict) and isinstance(batch_transport_contract.get("policy"), dict)
        else {}
    )
    forbidden_globs = [str(x) for x in artifact_spam_policy.get("forbidden_globs", []) if str(x).strip()]
    excluded_globs = [str(x) for x in artifact_spam_policy.get("excluded_globs", []) if str(x).strip()]
    golden_card_glob = str(golden_pair_policy.get("allowed_card_glob", "")).strip()
    golden_json_glob = str(golden_pair_policy.get("allowed_json_glob", "")).strip()
    if golden_card_glob:
        excluded_globs.append(golden_card_glob)
    if golden_json_glob:
        excluded_globs.append(golden_json_glob)
        excluded_globs.append(f"{golden_json_glob}.sha256")

    data_json_hits: list[str] = []
    for p in Path("data").rglob("*_poc_sprint2.json"):
        rel = Path(str(p).replace("\\", "/"))
        if str(rel).startswith("_PROJECT_TRASH/"):
            continue
        if _match_any(rel, excluded_globs):
            continue
        data_json_hits.append(str(rel))
    reports_json_hits: list[str] = []
    for p in Path("reports").rglob("*_poc_sprint2.json"):
        rel = Path(str(p).replace("\\", "/"))
        if _match_any(rel, excluded_globs):
            continue
        reports_json_hits.append(str(rel))
    reports_card_hits: list[str] = []
    for p in Path("reports").rglob("POC_DECISION_CARD_SPRINT2.md"):
        rel = Path(str(p).replace("\\", "/"))
        if _match_any(rel, excluded_globs):
            continue
        reports_card_hits.append(str(rel))

    checks["poc_cleanup_data_json_scope"] = _check(
        "PASS" if not data_json_hits else "FAIL",
        "poc_data_json_clean" if not data_json_hits else "poc_data_json_cleanup_required",
        "data/**/*_poc_sprint2.json",
        {"hits": data_json_hits[:20], "count": len(data_json_hits)},
        "CRITICAL",
    )
    checks["poc_cleanup_reports_json_scope"] = _check(
        "PASS" if not reports_json_hits else "FAIL",
        "poc_reports_json_clean" if not reports_json_hits else "poc_reports_json_cleanup_required",
        "reports/**/*_poc_sprint2.json",
        {"hits": reports_json_hits[:20], "count": len(reports_json_hits)},
        "CRITICAL",
    )
    checks["poc_cleanup_reports_card_scope"] = _check(
        "PASS" if not reports_card_hits else "FAIL",
        "poc_reports_card_clean" if not reports_card_hits else "poc_reports_card_cleanup_required",
        "reports/**/POC_DECISION_CARD_SPRINT2.md",
        {"hits": reports_card_hits[:20], "count": len(reports_card_hits)},
        "CRITICAL",
    )

    strict_cleanup_integrity = bool(cleanup_integrity_policy.get("strict_integrity_default", True))
    checks["cleanup_strict_integrity_default"] = _check(
        "PASS" if strict_cleanup_integrity else "FAIL",
        "cleanup_strict_integrity_enabled" if strict_cleanup_integrity else "cleanup_strict_integrity_disabled",
        str(CLEANUP_INTEGRITY_POLICY_PATH),
        {"strict_integrity_default": strict_cleanup_integrity},
        "CRITICAL",
    )

    golden_sidecar_errors: list[dict[str, Any]] = []
    golden_json_files = [p for p in Path().glob(golden_json_glob) if p.is_file()] if golden_json_glob else []
    golden_max_json = _to_int(golden_pair_policy.get("max_allowed_json_files"))
    if golden_max_json is not None and len(golden_json_files) > int(golden_max_json):
        golden_sidecar_errors.append(
            {
                "path": golden_json_glob,
                "reason": f"golden_pair_count_exceeded:{len(golden_json_files)}>{int(golden_max_json)}",
            }
        )
    golden_targets: list[Path] = []
    if golden_card_glob:
        golden_targets.extend([p for p in Path().glob(golden_card_glob) if p.is_file()])
    golden_targets.extend(golden_json_files)
    if strict_cleanup_integrity:
        for gp in golden_targets:
            ok_gp, reason_gp = verify_sha256_sidecar(gp, required=True)
            if not ok_gp:
                golden_sidecar_errors.append({"path": str(gp), "reason": reason_gp})
    checks["poc_golden_pair_integrity"] = _check(
        "PASS" if not golden_sidecar_errors else "FAIL",
        "poc_golden_pair_integrity_ok" if not golden_sidecar_errors else "poc_golden_pair_integrity_invalid",
        "reports/L1_ops/demo_golden_example",
        {"errors": golden_sidecar_errors[:20], "golden_targets": [str(p) for p in golden_targets]},
        "CRITICAL",
    )

    summary_only_policy_ok = (
        str(batch_transport_policy.get("summary_source_only", "")).strip() == "data/batch_eval/<batch_id>_summary.json"
    )
    consolidated_script = Path("scripts/build_batch_consolidated_report.py")
    consolidated_script_violations: list[str] = []
    if not consolidated_script.exists():
        consolidated_script_violations.append("missing_build_batch_consolidated_report_script")
    else:
        try:
            consolidated_text = consolidated_script.read_text(encoding="utf-8")
        except Exception:
            consolidated_text = ""
            consolidated_script_violations.append("unreadable_build_batch_consolidated_report_script")
        forbidden_markers = [
            "_PROJECT_TRASH/data/agent_reports",
            "data/agent_reports/{run_id}_poc_sprint2.json",
            "_load_agent_report_fallback(",
            "data/batch_eval/staging",
        ]
        for marker in forbidden_markers:
            if marker in consolidated_text:
                consolidated_script_violations.append(f"forbidden_dependency:{marker}")
    checks["consolidated_report_summary_only_policy"] = _check(
        "PASS" if (summary_only_policy_ok and not consolidated_script_violations) else "FAIL",
        "consolidated_summary_only_enforced"
        if (summary_only_policy_ok and not consolidated_script_violations)
        else "consolidated_summary_only_violation",
        str(consolidated_script),
        {
            "summary_only_policy_ok": summary_only_policy_ok,
            "violations": consolidated_script_violations[:20],
            "forbidden_globs_configured": forbidden_globs,
        },
        "CRITICAL",
    )
    runtime_guard_integrity_ok, runtime_guard_integrity_reason = verify_sha256_sidecar(runtime_guard_path, required=True)
    runtime_guard_payload = _read_json(runtime_guard_path) if runtime_guard_path.exists() and runtime_guard_integrity_ok else None
    runtime_guard_pass = (
        runtime_guard_integrity_ok
        and isinstance(runtime_guard_payload, dict)
        and str(runtime_guard_payload.get("status", "")).upper() == "PASS"
        and isinstance(runtime_guard_payload.get("stages"), list)
        and any(
            isinstance(s, dict)
            and str(s.get("stage", "")).strip().lower() == "execution"
            and str(s.get("status", "")).upper() == "PASS"
            for s in runtime_guard_payload.get("stages", [])
        )
    )
    checks["runtime_guard_report_passed"] = _check(
        "PASS" if runtime_guard_pass else "FAIL",
        (
            "runtime_guard_report_passed"
            if runtime_guard_pass
            else ("runtime_guard_report_integrity_invalid" if not runtime_guard_integrity_ok else "runtime_guard_report_missing_or_failed")
        ),
        str(runtime_guard_path),
        (
            runtime_guard_payload
            if isinstance(runtime_guard_payload, dict)
            else {
                "exists": runtime_guard_path.exists(),
                "integrity_ok": runtime_guard_integrity_ok,
                "integrity_reason": runtime_guard_integrity_reason,
            }
        ),
        "CRITICAL",
    )
    v3_contract_error = ""
    try:
        v3_contract_map = validate_v3_contract_set()
    except Exception as exc:
        v3_contract_map = {}
        v3_contract_error = str(exc)
    checks["v3_contract_set_integrity"] = _check(
        "PASS" if not v3_contract_error else "FAIL",
        "v3_contract_set_invalid" if v3_contract_error else "v3_contract_set_valid",
        "configs/contracts",
        v3_contract_error or v3_contract_map,
        "CRITICAL",
    )

    gate_payloads: dict[str, dict[str, Any]] = {}
    gate_load_errors: list[str] = []
    for gate_path in list_gate_results(run_id):
        try:
            gate_payload = load_gate_result(gate_path)
        except Exception as exc:
            gate_load_errors.append(f"{gate_path}:{exc}")
            continue
        gate_name = str(gate_payload.get("gate_name", "")).strip()
        if gate_name:
            gate_payloads[gate_name] = gate_payload

    required_primary_gate_order = [g for g in REQUIRED_GATE_ORDER if g not in {"acceptance", "pre_publish"}]
    required_gate_names = [*required_primary_gate_order]
    missing_gate_results = [name for name in required_gate_names if name not in gate_payloads]
    failed_gate_results = [
        name
        for name, payload in gate_payloads.items()
        if name in required_gate_names and str(payload.get("status", "")).upper() != "PASS"
    ]
    checks["v3_gate_results_present"] = _check(
        "PASS" if (not gate_load_errors and not missing_gate_results) else "FAIL",
        "gate_result_missing_or_invalid",
        "data/gates",
        {
            "load_errors": gate_load_errors[:5],
            "missing": missing_gate_results,
            "found": sorted(gate_payloads.keys()),
        },
        "CRITICAL",
    )
    checks["v3_gate_results_passed"] = _check(
        "PASS" if not failed_gate_results else "FAIL",
        "gate_result_failed_status",
        "data/gates",
        {"failed_gates": failed_gate_results},
        "CRITICAL",
    )
    captain_gate = gate_payloads.get("captain", {})
    checks["captain_gate_result"] = _check(
        "PASS" if isinstance(captain_gate, dict) and str(captain_gate.get("status", "")).upper() == "PASS" else "FAIL",
        "CONTEXT_CONFLICT",
        f"data/gates/{run_id}_captain_gate_result.json",
        captain_gate if isinstance(captain_gate, dict) else {"error": "missing_captain_gate_result"},
        "CRITICAL",
    )
    duration_gate_payload = gate_payloads.get("experiment_duration_gate", {})
    duration_gate_details = duration_gate_payload.get("details", {}) if isinstance(duration_gate_payload, dict) else {}
    duration_days_covered = _to_int(duration_gate_details.get("days_covered"))
    duration_min_days = (
        _to_int(duration_gate_details.get("min_experiment_days"))
        or _to_int((experiment_duration_contract or {}).get("min_experiment_days"))
        or 14
    )
    duration_gate_status = (
        str(duration_gate_payload.get("status", "")).upper()
        if isinstance(duration_gate_payload, dict)
        else ""
    )
    gate_order_violations: list[str] = []
    gate_ts_order: list[tuple[str, datetime]] = []
    for gate_name in required_primary_gate_order:
        row = gate_payloads.get(gate_name, {})
        ts = _parse_iso_ts(row.get("generated_at")) if isinstance(row, dict) else None
        if ts is None:
            gate_order_violations.append(f"missing_generated_at:{gate_name}")
            continue
        gate_ts_order.append((gate_name, ts))
    if len(gate_ts_order) == len(required_primary_gate_order):
        for i in range(1, len(gate_ts_order)):
            if gate_ts_order[i][1] < gate_ts_order[i - 1][1]:
                gate_order_violations.append(
                    f"gate_order_violation:{gate_ts_order[i - 1][0]}>{gate_ts_order[i][0]}"
                )
    checks["v3_gate_order"] = _check(
        "PASS" if not gate_order_violations else "FAIL",
        "gate_order_invalid",
        "data/gates",
        {"violations": gate_order_violations, "order": [x[0] for x in gate_ts_order]},
        "CRITICAL",
    )

    context_frame = None
    context_frame_err = ""
    try:
        context_frame = load_json_with_integrity(context_frame_path(run_id))
    except Exception as exc:
        context_frame_err = str(exc)
    current_id = str((((context_frame or {}).get("current_ab") or {}) if isinstance((context_frame or {}).get("current_ab"), dict) else {}).get("experiment_id", "")).strip()
    next_id = str((((context_frame or {}).get("next_experiment") or {}) if isinstance((context_frame or {}).get("next_experiment"), dict) else {}).get("experiment_id", "")).strip()
    contours_distinct = bool(current_id and next_id and current_id != next_id)
    checks["context_frame_contract"] = _check(
        "PASS"
        if isinstance(context_frame, dict) and str(context_frame.get("status", "")).upper() == "PASS" and contours_distinct
        else "FAIL",
        "CONTEXT_CONFLICT",
        str(context_frame_path(run_id)),
        {
            "error": context_frame_err,
            "current_experiment_id": current_id,
            "next_experiment_id": next_id,
            "context_status": (context_frame or {}).get("status") if isinstance(context_frame, dict) else None,
        },
        "CRITICAL",
    )
    handoff_guard = None
    handoff_guard_err = ""
    try:
        handoff_guard = load_json_with_integrity(handoff_guard_path(run_id))
    except Exception as exc:
        handoff_guard_err = str(exc)
    checks["handoff_contract_guard"] = _check(
        "PASS" if isinstance(handoff_guard, dict) and str(handoff_guard.get("status", "")).upper() == "PASS" else "FAIL",
        "CONTEXT_CONFLICT",
        str(handoff_guard_path(run_id)),
        handoff_guard if isinstance(handoff_guard, dict) else {"error": handoff_guard_err},
        "CRITICAL",
    )
    historical_pack = None
    historical_pack_err = ""
    try:
        historical_pack = load_json_with_integrity(historical_context_pack_path(run_id))
    except Exception as exc:
        historical_pack_err = str(exc)
    historical_pack_ok = (
        isinstance(historical_pack, dict)
        and str(historical_pack.get("status", "")).upper() == "PASS"
        and str(historical_pack.get("retrieval_mode", "")).strip().lower() == "semantic_hybrid_mvp"
        and str(historical_pack.get("query_ref", "")).strip().startswith("artifact:")
        and str(historical_pack.get("embedding_model", "")).strip() != ""
        and int(historical_pack.get("top_k", 0) or 0) > 0
        and isinstance(historical_pack.get("rows"), list)
        and len(historical_pack.get("rows", [])) > 0
        and isinstance(historical_pack.get("fact_refs"), list)
        and len(historical_pack.get("fact_refs", [])) > 0
        and isinstance(historical_pack.get("evidence_hashes"), list)
        and len(historical_pack.get("evidence_hashes", [])) > 0
    )
    checks["historical_retrieval_gate"] = _check(
        "PASS" if historical_pack_ok else "FAIL",
        "HISTORICAL_CONTEXT_MISSING" if not historical_pack_err else "HISTORICAL_CONTEXT_INTEGRITY_FAIL",
        str(historical_context_pack_path(run_id)),
        historical_pack if isinstance(historical_pack, dict) else {"error": historical_pack_err},
        "CRITICAL",
    )
    memory_ledger = None
    memory_ledger_err = ""
    try:
        memory_ledger = load_json_with_integrity(reasoning_memory_ledger_path(run_id))
    except Exception as exc:
        memory_ledger_err = str(exc)
    ledger_ok = (
        isinstance(memory_ledger, dict)
        and isinstance(memory_ledger.get("entries"), list)
        and len(memory_ledger.get("entries", [])) > 0
    )
    checks["reasoning_memory_ledger_present"] = _check(
        "PASS" if ledger_ok else "FAIL",
        "HISTORICAL_CONTEXT_INTEGRITY_FAIL",
        str(reasoning_memory_ledger_path(run_id)),
        memory_ledger if isinstance(memory_ledger, dict) else {"error": memory_ledger_err},
        "CRITICAL",
    )
    hist_conf = None
    hist_conf_err = ""
    try:
        hist_conf = load_json_with_integrity(historical_conformance_path(run_id))
    except Exception as exc:
        hist_conf_err = str(exc)
    checks["historical_retrieval_conformance_gate"] = _check(
        "PASS" if isinstance(hist_conf, dict) and str(hist_conf.get("status", "")).upper() == "PASS" else "FAIL",
        "HISTORICAL_CONTEXT_UNUSED",
        str(historical_conformance_path(run_id)),
        hist_conf if isinstance(hist_conf, dict) else {"error": hist_conf_err},
        "CRITICAL",
    )

    paired_registry = None
    paired_registry_err = ""
    try:
        paired_registry = load_registry_for_run(run_id, required=False)
    except Exception as exc:
        paired_registry_err = str(exc)
    paired_mode = isinstance(paired_registry, dict) and str(paired_registry.get("mode", "")).strip().lower() == "paired"
    paired_status_raw = (
        str((paired_registry or {}).get("paired_status", "")).strip().upper()
        if isinstance(paired_registry, dict)
        else ""
    )
    paired_status_enum_ok = (not paired_mode) or paired_status_raw in set(PAIRED_STATUS_ENUM)
    checks["paired_status_enum_canonical"] = _check(
        "PASS" if paired_status_enum_ok else "FAIL",
        "PAIRED_REGISTRY_KEY_INVALID",
        "data/paired_registry/*__<run_id>.json",
        {
            "paired_mode": paired_mode,
            "paired_status": paired_status_raw,
            "allowed": list(PAIRED_STATUS_ENUM),
            "error": paired_registry_err,
        },
        "CRITICAL",
    )

    registry_required = {
        "experiment_id",
        "parent_run_id",
        "ctrl_run_id",
        "treatment_run_id",
        "paired_status",
        "created_at",
        "updated_at",
        "error_code",
        "reason",
        "audit_ref",
    }
    registry_missing = [
        key for key in sorted(registry_required) if not isinstance(paired_registry, dict) or key not in paired_registry
    ]
    paired_registry_ok = (not paired_mode and not paired_registry_err) or (
        paired_mode
        and not registry_missing
        and str((paired_registry or {}).get("parent_run_id", "")).strip() == run_id
        and str((paired_registry or {}).get("experiment_id", "")).strip() != ""
    )
    checks["paired_registry_contract_valid"] = _check(
        "PASS" if paired_registry_ok else "FAIL",
        "PAIRED_REGISTRY_KEY_INVALID",
        "data/paired_registry/*__<run_id>.json",
        {
            "paired_mode": paired_mode,
            "registry_missing": registry_missing,
            "error": paired_registry_err,
            "registry": paired_registry if isinstance(paired_registry, dict) else None,
        },
        "CRITICAL",
    )

    paired_context_payload = None
    paired_context_err = ""
    paired_context_path = paired_experiment_context_path(run_id)
    if paired_mode and isinstance(paired_registry, dict):
        paired_context_ref = str(paired_registry.get("paired_context_ref", "")).strip()
        if paired_context_ref.startswith("artifact:"):
            ref_path = paired_context_ref[len("artifact:") :].strip()
            if ref_path:
                paired_context_path = Path(ref_path)
        try:
            paired_context_payload = load_json_with_integrity(paired_context_path)
        except Exception as exc:
            paired_context_err = str(exc)
    status_issues: list[str] = []
    if paired_mode:
        ctx_status = str((paired_context_payload or {}).get("paired_status", "")).strip().upper()
        if ctx_status != paired_status_raw:
            status_issues.append("paired_status_mismatch_between_registry_and_context")
        if ctx_status == "COMPLETE":
            if not isinstance((paired_context_payload or {}).get("layer1"), dict):
                status_issues.append("complete_missing_layer1")
            if not isinstance((paired_context_payload or {}).get("layer2"), dict):
                status_issues.append("complete_missing_layer2")
            if not str((paired_context_payload or {}).get("merger_artifact_ref", "")).strip():
                status_issues.append("complete_missing_merger_artifact_ref")
        elif ctx_status == "PARTIAL":
            if not str((paired_context_payload or {}).get("partial_reason", "")).strip():
                status_issues.append("partial_missing_reason")
            if str((paired_context_payload or {}).get("decision_ceiling", "")).strip().upper() != "HOLD_NEED_DATA":
                status_issues.append("partial_ceiling_not_hold_need_data")
        elif ctx_status == "TREATMENT_FAILED":
            if not str((paired_context_payload or {}).get("partial_reason", "")).strip():
                status_issues.append("treatment_failed_missing_reason")
            if not str((paired_context_payload or {}).get("failed_step", "")).strip():
                status_issues.append("treatment_failed_missing_failed_step")
            if str((paired_context_payload or {}).get("decision_ceiling", "")).strip().upper() != "HOLD_NEED_DATA":
                status_issues.append("treatment_failed_ceiling_not_hold_need_data")
        elif ctx_status == "CTRL_FAILED":
            if not str((paired_context_payload or {}).get("failure_reason", "")).strip():
                status_issues.append("ctrl_failed_missing_failure_reason")
            if not str((paired_context_payload or {}).get("failed_step", "")).strip():
                status_issues.append("ctrl_failed_missing_failed_step")
            if "layer1" in (paired_context_payload or {}) or "layer2" in (paired_context_payload or {}):
                status_issues.append("ctrl_failed_layer_fields_must_be_absent")
        else:
            status_issues.append("context_paired_status_invalid")
    checks["paired_context_contract_valid"] = _check(
        "PASS" if ((not paired_mode) or (isinstance(paired_context_payload, dict) and not status_issues)) else "FAIL",
        "PAIRED_REGISTRY_KEY_INVALID",
        str(paired_context_path),
        {
            "paired_mode": paired_mode,
            "context_error": paired_context_err,
            "status_issues": status_issues[:10],
        },
        "CRITICAL",
    )
    lifecycle_ok = True
    lifecycle_issues: list[str] = []
    if paired_mode and isinstance(paired_registry, dict):
        lifecycle_ok, lifecycle_issues = _validate_paired_status_lifecycle(
            paired_status=paired_status_raw,
            status_history=paired_registry.get("status_history", []),
        )
    checks["paired_status_lifecycle_valid"] = _check(
        "PASS" if ((not paired_mode) or lifecycle_ok) else "FAIL",
        "PAIRED_REGISTRY_KEY_INVALID",
        "data/paired_registry/*__<run_id>.json",
        {
            "paired_mode": paired_mode,
            "paired_status": paired_status_raw,
            "lifecycle_issues": lifecycle_issues[:10],
            "allowed_transitions": list(PAIRED_STATUS_LIFECYCLE_ALLOWED),
        },
        "CRITICAL",
    )

    ctrl_scope_ok = True
    ctrl_scope_error = ""
    ctrl_scope_path = ctrl_foundation_audit_path(str((paired_registry or {}).get("ctrl_run_id", run_id)))
    if paired_mode and isinstance(paired_registry, dict):
        audit_ref = str(paired_registry.get("audit_ref", "")).strip()
        if audit_ref.startswith("artifact:"):
            audit_ref_path = audit_ref[len("artifact:") :].strip()
            if audit_ref_path:
                ctrl_scope_path = Path(audit_ref_path)
        try:
            ctrl_scope_payload = load_json_with_integrity(ctrl_scope_path)
            executed_steps = (
                ctrl_scope_payload.get("executed_steps", [])
                if isinstance(ctrl_scope_payload, dict) and isinstance(ctrl_scope_payload.get("executed_steps"), list)
                else []
            )
            allowed_set = set(PAIRED_CTRL_FOUNDATION_ALLOWED_STEPS)
            if any(str(step) not in allowed_set for step in executed_steps):
                ctrl_scope_ok = False
                ctrl_scope_error = "executed_step_outside_allowlist"
            if str((ctrl_scope_payload or {}).get("status", "")).upper() != "PASS":
                ctrl_scope_ok = False
                ctrl_scope_error = "ctrl_foundation_audit_not_pass"
        except Exception as exc:
            ctrl_scope_ok = False
            ctrl_scope_error = str(exc)
    checks["ctrl_foundation_scope_guard"] = _check(
        "PASS" if ((not paired_mode) or ctrl_scope_ok) else "FAIL",
        "CTRL_FOUNDATION_SCOPE_VIOLATION",
        str(ctrl_scope_path),
        {
            "paired_mode": paired_mode,
            "error": ctrl_scope_error,
            "allowed_steps": list(PAIRED_CTRL_FOUNDATION_ALLOWED_STEPS),
        },
        "CRITICAL",
    )
    checks["single_mode_no_paired_artifact_dependency"] = _check(
        "PASS" if (not paired_mode) else "NA",
        "single_mode_independent",
        "data/paired_registry/*",
        {"paired_mode": paired_mode},
        "CRITICAL",
    )
    stat_bundle_required = paired_mode and paired_status_raw == "COMPLETE"
    stat_bundle_payload: dict[str, Any] | None = None
    stat_bundle_err = ""
    stat_bundle_layers: dict[str, Any] = {}
    if stat_bundle_required:
        try:
            stat_bundle_payload = load_json_with_integrity(stat_evidence_bundle_path(run_id))
            stat_bundle_layers = (
                stat_bundle_payload.get("layers_present", {})
                if isinstance(stat_bundle_payload.get("layers_present"), dict)
                else {}
            )
        except Exception as exc:
            stat_bundle_err = str(exc)
    stat_bundle_present_ok = (
        not stat_bundle_required
        or (
            isinstance(stat_bundle_payload, dict)
            and isinstance(stat_bundle_payload.get("guardrail_status_check"), list)
            and isinstance(stat_bundle_layers, dict)
            and bool(stat_bundle_layers)
        )
    )
    checks["stat_evidence_present_when_paired_complete"] = _check(
        "PASS" if stat_bundle_present_ok else "FAIL",
        "METHODOLOGY_INVARIANT_BROKEN",
        str(stat_evidence_bundle_path(run_id)),
        {
            "paired_mode": paired_mode,
            "paired_status": paired_status_raw,
            "required": stat_bundle_required,
            "bundle_status": (stat_bundle_payload or {}).get("status") if isinstance(stat_bundle_payload, dict) else None,
            "layers_present": stat_bundle_layers,
            "error": stat_bundle_err,
        },
        "CRITICAL",
    )

    anti_goodhart_verdict = None
    anti_goodhart_err = ""
    try:
        anti_goodhart_verdict = load_json_with_integrity(anti_goodhart_verdict_path(run_id))
    except Exception as exc:
        anti_goodhart_err = str(exc)
    anti_goodhart_status_ok = (
        isinstance(anti_goodhart_verdict, dict)
        and str(anti_goodhart_verdict.get("status", "")).upper() == "PASS"
        and str(anti_goodhart_verdict.get("source_of_truth", "")) == "anti_goodhart_verdict_v1"
        and isinstance(anti_goodhart_verdict.get("anti_goodhart_triggered"), bool)
    )
    anti_goodhart_partial_expected = (
        paired_mode
        and is_partial_like(paired_status_raw)
        and isinstance(anti_goodhart_verdict, dict)
        and str(anti_goodhart_verdict.get("status", "")).upper() == "FAIL"
        and str(anti_goodhart_verdict.get("error_code", "")).upper() == "AB_ARTIFACT_REQUIRED"
    )
    anti_goodhart_status_ok = anti_goodhart_status_ok or anti_goodhart_partial_expected
    checks["anti_goodhart_sot_integrity"] = _check(
        "PASS" if anti_goodhart_status_ok else "FAIL",
        "AB_ARTIFACT_REQUIRED" if anti_goodhart_partial_expected else "ANTI_GOODHART_MISMATCH",
        str(anti_goodhart_verdict_path(run_id)),
        anti_goodhart_verdict if isinstance(anti_goodhart_verdict, dict) else {"error": anti_goodhart_err},
        "CRITICAL",
    )
    anti_goodhart_ab_v2_mismatch = False
    anti_goodhart_ab_v2_path = None
    if isinstance(ab_path, Path):
        anti_goodhart_ab_v2_path = Path(str(ab_path).replace("_ab.json", "_ab_v2.json"))
    if anti_goodhart_ab_v2_path and anti_goodhart_ab_v2_path.exists():
        ab_v2_payload = _read_json(anti_goodhart_ab_v2_path) or {}
        if isinstance(anti_goodhart_verdict, dict) and isinstance(ab_v2_payload, dict) and "anti_goodhart_triggered" in ab_v2_payload:
            anti_goodhart_ab_v2_mismatch = bool(ab_v2_payload.get("anti_goodhart_triggered")) != bool(
                anti_goodhart_verdict.get("anti_goodhart_triggered", False)
            )
    checks["anti_goodhart_sot_consistency"] = _check(
        "PASS" if (anti_goodhart_partial_expected or not anti_goodhart_ab_v2_mismatch) else "FAIL",
        "AB_ARTIFACT_REQUIRED" if anti_goodhart_partial_expected else "ANTI_GOODHART_MISMATCH",
        str(anti_goodhart_ab_v2_path) if anti_goodhart_ab_v2_path else "data/ab_reports/*_ab_v2.json",
        {
            "has_ab_v2": bool(anti_goodhart_ab_v2_path and anti_goodhart_ab_v2_path.exists()),
            "mismatch": anti_goodhart_ab_v2_mismatch,
            "paired_mode": paired_mode,
            "paired_status": paired_status_raw,
            "partial_expected": anti_goodhart_partial_expected,
        },
        "CRITICAL",
    )

    quality_inv = None
    quality_inv_err = ""
    try:
        quality_inv = load_json_with_integrity(quality_invariants_path(run_id))
    except Exception as exc:
        quality_inv_err = str(exc)
    checks["quality_invariants_gate"] = _check(
        "PASS" if isinstance(quality_inv, dict) and str(quality_inv.get("status", "")).upper() == "PASS" else "FAIL",
        "METHODOLOGY_INVARIANT_BROKEN",
        str(quality_invariants_path(run_id)),
        quality_inv if isinstance(quality_inv, dict) else {"error": quality_inv_err},
        "CRITICAL",
    )

    reasoning_policy = None
    reasoning_policy_err = ""
    try:
        reasoning_policy = load_json_with_integrity(reasoning_policy_path(run_id))
    except Exception as exc:
        reasoning_policy_err = str(exc)
    reasoning_policy_ok = isinstance(reasoning_policy, dict) and str(reasoning_policy.get("status", "")).upper() == "PASS"
    ceiling_violation = False
    if isinstance(reasoning_policy, dict) and int(reasoning_policy.get("effective_real_llm_agents_count", 0) or 0) == 0:
        ceiling_violation = str(reasoning_policy.get("decision_ceiling", "")).upper() != "HOLD_NEED_DATA"
        if commander_decision not in {"STOP", "HOLD_NEED_DATA"}:
            ceiling_violation = True
    checks["reasoning_score_policy_gate"] = _check(
        "PASS" if (reasoning_policy_ok and not ceiling_violation) else "FAIL",
        "METHODOLOGY_INVARIANT_BROKEN",
        str(reasoning_policy_path(run_id)),
        reasoning_policy if isinstance(reasoning_policy, dict) else {"error": reasoning_policy_err},
        "CRITICAL",
    )

    governance_ceiling = None
    governance_ceiling_err = ""
    try:
        governance_ceiling = load_json_with_integrity(governance_ceiling_path(run_id))
    except Exception as exc:
        governance_ceiling_err = str(exc)
    governance_status = str((governance_ceiling or {}).get("governance_status", "")).strip().lower() if isinstance(governance_ceiling, dict) else ""
    governance_required_actions = (
        (governance_ceiling or {}).get("required_actions", [])
        if isinstance(governance_ceiling, dict) and isinstance((governance_ceiling or {}).get("required_actions"), list)
        else []
    )
    governance_ceiling_ok = isinstance(governance_ceiling, dict) and str(governance_ceiling.get("status", "")).upper() == "PASS"
    if governance_status == "missing_review":
        governance_ceiling_ok = (
            str(governance_ceiling.get("decision_ceiling", "")).upper() == "HOLD_NEED_DATA"
            and len(governance_required_actions) > 0
        )
    checks["governance_ceiling_gate"] = _check(
        "PASS" if governance_ceiling_ok else "FAIL",
        "GOVERNANCE_REVIEW_REQUIRED",
        str(governance_ceiling_path(run_id)),
        governance_ceiling if isinstance(governance_ceiling, dict) else {"error": governance_ceiling_err},
        "CRITICAL",
    )

    weak_reconciliation_events = _collect_weak_reconciliation_events(run_id)
    weak_events = [e for e in weak_reconciliation_events if e.get("__kind") == "weak_reasoning_result"]
    reconciliation_requests = [e for e in weak_reconciliation_events if e.get("__kind") == "reconciliation_request"]
    reconciliation_results = [e for e in weak_reconciliation_events if e.get("__kind") == "reconciliation_result"]
    recommended_overrides = [e for e in weak_reconciliation_events if e.get("__kind") == "recommended_override"]

    weak_runtime_disabled = str(feature_state.get("weak_path_runtime", "")).upper() == "DISABLED"
    reconciliation_not_implemented = str(feature_state.get("reconciliation_runtime", "")).upper() == "NOT_IMPLEMENTED"
    weak_runtime_events_present = len(weak_reconciliation_events) > 0
    checks["feature_state_runtime_disabled_enforced"] = _check(
        "PASS"
        if (not weak_runtime_disabled and not reconciliation_not_implemented) or (not weak_runtime_events_present)
        else "FAIL",
        "feature_state_disabled_runtime_event_detected",
        "data/event_bus/**/*.json",
        {
            "weak_path_runtime": feature_state.get("weak_path_runtime"),
            "reconciliation_runtime": feature_state.get("reconciliation_runtime"),
            "runtime_events_detected": weak_runtime_events_present,
            "event_count": len(weak_reconciliation_events),
        },
        "CRITICAL",
    )

    # Minimal schema sanity for critical decision artifacts.
    doctor_ok, doctor_issues = _schema_ok(
        doctor,
        {
            "run_id": str,
            "normalized_decision": str,
            "measurement_state": str,
            "hypothesis_portfolio": list,
        },
    )
    evaluator_ok, evaluator_issues = _schema_ok(
        evaluator,
        {
            "run_id": str,
            "decision": str,
            "ab_status": str,
            "assignment_status": str,
        },
    )
    commander_ok, commander_issues = _schema_ok(
        commander,
        {
            "run_id": str,
            "normalized_decision": str,
            "blocked_by": list,
        },
    )
    checks["schema_doctor_minimal"] = _check(
        "PASS" if doctor_ok else "FAIL",
        "doctor_schema_invalid",
        str(doctor_path),
        doctor_issues,
        "CRITICAL",
    )
    checks["schema_evaluator_minimal"] = _check(
        "PASS" if evaluator_ok else "FAIL",
        "evaluator_schema_invalid",
        str(evaluator_path),
        evaluator_issues,
        "CRITICAL",
    )
    checks["schema_commander_minimal"] = _check(
        "PASS" if commander_ok else "FAIL",
        "commander_schema_invalid",
        str(commander_path),
        commander_issues,
        "CRITICAL",
    )
    mitigation_ok, mitigation_meta = _validate_mitigation_policy(commander if isinstance(commander, dict) else {})
    checks["commander_mitigation_policy"] = _check(
        "PASS" if mitigation_ok else "FAIL",
        "MITIGATION_PROPOSALS_MISSING",
        str(commander_path),
        mitigation_meta,
        "CRITICAL",
    )
    online_kpi_ok, online_kpi_meta = _validate_online_kpi(agent_eval if isinstance(agent_eval, dict) else {})
    checks["online_kpi_present"] = _check(
        "PASS" if online_kpi_ok else "FAIL",
        "KPI_ONLINE_MISSING",
        str(agent_eval_path),
        online_kpi_meta,
        "CRITICAL",
    )
    mode = _acceptance_mode()
    nightly_mode = mode in {"nightly", "release"}
    decision_ledger_path = decision_outcomes_ledger_path(run_id)
    offline_kpi_path = offline_kpi_backtest_path(run_id)

    decision_ledger = None
    decision_ledger_err = ""
    try:
        decision_ledger = load_json_with_integrity(decision_ledger_path)
    except Exception as exc:
        decision_ledger_err = str(exc)

    offline_payload = None
    offline_kpi_err = ""
    try:
        offline_payload = load_json_with_integrity(offline_kpi_path)
    except Exception as exc:
        offline_kpi_err = str(exc)

    required_real_kpi_fields = (
        "would_have_prevented_loss_rate",
        "decision_regret_rate",
        "sample_size",
        "label_window_days",
        "ground_truth_source",
        "ground_truth_refs",
    )
    ledger_missing_fields: list[str] = []
    for key in required_real_kpi_fields:
        if not isinstance(decision_ledger, dict) or key not in decision_ledger:
            ledger_missing_fields.append(key)
    ledger_sample_size = int((decision_ledger or {}).get("sample_size", 0) or 0) if isinstance(decision_ledger, dict) else 0
    ledger_label_window_days = int((decision_ledger or {}).get("label_window_days", 0) or 0) if isinstance(decision_ledger, dict) else 0
    min_sample_size_by_mode = {"run": 10, "nightly": 50, "release": 100}
    min_sample_size = int(min_sample_size_by_mode.get(mode, 10))
    ledger_outcomes = (
        decision_ledger.get("outcomes", [])
        if isinstance(decision_ledger, dict) and isinstance(decision_ledger.get("outcomes"), list)
        else []
    )
    outcomes_count = len([x for x in ledger_outcomes if isinstance(x, dict)])
    unique_outcome_ids = len(
        {
            str(x.get("decision_id", "")).strip()
            for x in ledger_outcomes
            if isinstance(x, dict) and str(x.get("decision_id", "")).strip()
        }
    )
    outcomes_scope_violations: list[str] = []
    allowed_decisions = {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}
    for row in ledger_outcomes:
        if not isinstance(row, dict):
            continue
        decision_id = str(row.get("decision_id", "")).strip()
        if not decision_id or "/" in decision_id or ".." in decision_id:
            outcomes_scope_violations.append(f"invalid_decision_id:{decision_id or 'empty'}")
        decision_name = str(row.get("decision", "")).strip().upper()
        if decision_name and decision_name not in allowed_decisions:
            outcomes_scope_violations.append(f"invalid_decision_value:{decision_name}")
    checks["kpi_outcomes_scope"] = _check(
        "PASS" if not outcomes_scope_violations else "FAIL",
        "KPI_OUTCOMES_SCOPE_VIOLATION",
        str(decision_ledger_path),
        {"violations": outcomes_scope_violations[:20], "outcomes_count": outcomes_count},
        "CRITICAL",
    )
    ground_truth_source = str((decision_ledger or {}).get("ground_truth_source", "")).strip() if isinstance(decision_ledger, dict) else ""
    source_disallowed = ground_truth_source.lower() in {
        "",
        "unknown",
        "synthetic",
        "mock",
        "ab_reports+adversarial_suite+governance",
    }
    ground_truth_refs = (
        decision_ledger.get("ground_truth_refs", [])
        if isinstance(decision_ledger, dict) and isinstance(decision_ledger.get("ground_truth_refs"), list)
        else []
    )
    if ledger_label_window_days <= 0:
        ledger_missing_fields.append("label_window_days<=0")
    if ledger_sample_size != outcomes_count:
        ledger_missing_fields.append("sample_size_mismatch_outcomes_count")
    ground_truth_ref_issues: list[str] = []
    for ref in ground_truth_refs:
        raw_ref = str(ref or "").strip()
        if not raw_ref:
            continue
        path_raw = raw_ref
        if path_raw.startswith("artifact:"):
            path_raw = path_raw[len("artifact:") :]
        if "#" in path_raw:
            path_raw = path_raw.split("#", 1)[0]
        p = Path(path_raw)
        if not p.exists():
            ground_truth_ref_issues.append(f"missing_ref:{raw_ref}")
            continue
        ok_ref, reason_ref = verify_sha256_sidecar(p, required=True)
        if not ok_ref:
            ground_truth_ref_issues.append(f"ref_integrity_fail:{reason_ref}")
    ledger_ok = (
        isinstance(decision_ledger, dict)
        and not ledger_missing_fields
        and not source_disallowed
        and outcomes_count >= min_sample_size
        and unique_outcome_ids >= min_sample_size
        and ledger_sample_size >= min_sample_size
        and len(ground_truth_refs) > 0
        and not ground_truth_ref_issues
    )
    checks["real_kpi_ledger_present"] = _check(
        "PASS" if ledger_ok else "FAIL",
        "KPI_LEDGER_MISSING",
        str(decision_ledger_path),
        (
            {
                "missing_fields": ledger_missing_fields,
                "sample_size": ledger_sample_size,
                "required_sample_size": min_sample_size,
                "outcomes_count": outcomes_count,
                "unique_outcome_ids": unique_outcome_ids,
                "ground_truth_source": ground_truth_source,
                "ground_truth_ref_count": len(ground_truth_refs),
                "ground_truth_ref_issues": ground_truth_ref_issues[:5],
                "mode": mode,
                "error": decision_ledger_err,
            }
            if not ledger_ok
            else {
                "sample_size": ledger_sample_size,
                "outcomes_count": outcomes_count,
                "unique_outcome_ids": unique_outcome_ids,
                "ground_truth_source": ground_truth_source,
                "ground_truth_ref_count": len(ground_truth_refs),
                "mode": mode,
            }
        ),
        "CRITICAL",
    )

    # Proxy KPI cannot pass if real KPI ledger is missing/incomplete.
    if checks["online_kpi_present"]["status"] == "PASS" and not ledger_ok:
        checks["online_kpi_present"] = _check(
            "FAIL",
            "KPI_LEDGER_MISSING",
            str(decision_ledger_path),
            {"reason": "proxy_kpi_without_real_ledger", "mode": mode},
            "CRITICAL",
        )

    offline_missing_fields: list[str] = []
    for key in required_real_kpi_fields:
        if not isinstance(offline_payload, dict) or key not in offline_payload:
            offline_missing_fields.append(key)
    offline_sample_size = int((offline_payload or {}).get("sample_size", 0) or 0) if isinstance(offline_payload, dict) else 0
    offline_label_window_days = int((offline_payload or {}).get("label_window_days", 0) or 0) if isinstance(offline_payload, dict) else 0
    if offline_sample_size < min_sample_size:
        offline_missing_fields.append(f"sample_size<{min_sample_size}")
    if offline_label_window_days <= 0:
        offline_missing_fields.append("label_window_days<=0")
    offline_ground_truth_source = (
        str((offline_payload or {}).get("ground_truth_source", "")).strip()
        if isinstance(offline_payload, dict)
        else ""
    )
    if offline_ground_truth_source.lower() in {"", "unknown", "synthetic", "mock", "ab_reports+adversarial_suite+governance"}:
        offline_missing_fields.append("ground_truth_source_unverified")
    offline_ground_truth_refs = (
        offline_payload.get("ground_truth_refs", [])
        if isinstance(offline_payload, dict) and isinstance(offline_payload.get("ground_truth_refs"), list)
        else []
    )
    offline_ref_issues: list[str] = []
    for ref in offline_ground_truth_refs:
        raw_ref = str(ref or "").strip()
        if not raw_ref:
            continue
        path_raw = raw_ref
        if path_raw.startswith("artifact:"):
            path_raw = path_raw[len("artifact:") :]
        if "#" in path_raw:
            path_raw = path_raw.split("#", 1)[0]
        p = Path(path_raw)
        if not p.exists():
            offline_ref_issues.append(f"missing_ref:{raw_ref}")
            continue
        ok_ref, reason_ref = verify_sha256_sidecar(p, required=True)
        if not ok_ref:
            offline_ref_issues.append(f"ref_integrity_fail:{reason_ref}")
    if not offline_ground_truth_refs:
        offline_missing_fields.append("ground_truth_refs_empty")
    if offline_ref_issues:
        offline_missing_fields.append("ground_truth_refs_integrity_failed")
    offline_ts = _parse_iso_ts((offline_payload or {}).get("generated_at") if isinstance(offline_payload, dict) else None)
    now_utc = datetime.now(timezone.utc)
    age_hours: float | None = None
    if offline_ts is not None:
        age_hours = max(0.0, (now_utc - offline_ts).total_seconds() / 3600.0)
    if offline_payload is None or age_hours is None or offline_missing_fields:
        offline_kpi_status = "FAIL" if nightly_mode else "WARN"
    elif age_hours <= 24.0:
        offline_kpi_status = "PASS"
    elif age_hours <= 48.0:
        offline_kpi_status = "WARN"
    else:
        offline_kpi_status = "FAIL" if nightly_mode else "WARN"
    checks["offline_kpi_freshness"] = _check(
        offline_kpi_status,
        "KPI_OFFLINE_STALE",
        str(offline_kpi_path),
        {
            "exists": offline_payload is not None,
            "missing_fields": offline_missing_fields,
            "offline_error": offline_kpi_err,
            "nightly_mode": nightly_mode,
            "mode": mode,
            "sample_size": offline_sample_size,
            "required_sample_size": min_sample_size,
            "label_window_days": offline_label_window_days,
            "ground_truth_source": offline_ground_truth_source,
            "ground_truth_ref_count": len(offline_ground_truth_refs),
            "ground_truth_ref_issues": offline_ref_issues[:5],
            "age_hours": (None if age_hours is None else round(age_hours, 3)),
            "generated_at": (offline_payload or {}).get("generated_at") if isinstance(offline_payload, dict) else None,
        },
        "CRITICAL" if (nightly_mode and offline_kpi_status == "FAIL") else "ADVISORY",
    )

    # Non-critical schema checks for analytics artifacts.
    agent_eval_ok, agent_eval_issues = _schema_ok(
        agent_eval,
        {"system": dict, "doctor": dict, "narrative": dict},
    )
    adversarial_ok, adversarial_issues = _schema_ok(adversarial, {"scenarios": list})
    governance_ok, governance_issues = _schema_ok(governance, {"governance_status": str, "proposal_rows": list})
    checks["schema_agent_eval_minimal"] = _check(
        "PASS" if agent_eval_ok else "FAIL",
        "agent_eval_schema_invalid",
        str(agent_eval_path),
        agent_eval_issues,
        "ADVISORY",
    )
    checks["schema_adversarial_minimal"] = _check(
        "PASS" if adversarial_ok else "FAIL",
        "adversarial_schema_invalid",
        str(adversarial_path),
        adversarial_issues,
        "ADVISORY",
    )
    checks["schema_governance_minimal"] = _check(
        "PASS" if governance_ok else "FAIL",
        "governance_schema_invalid",
        str(governance_path),
        governance_issues,
        "ADVISORY",
    )

    doctor_metrics = agent_eval.get("doctor", {}) if isinstance(agent_eval.get("doctor"), dict) else {}
    narrative_metrics = agent_eval.get("narrative", {}) if isinstance(agent_eval.get("narrative"), dict) else {}
    system_metrics = agent_eval.get("system", {}) if isinstance(agent_eval.get("system"), dict) else {}

    portfolio = doctor.get("hypothesis_portfolio", []) if isinstance(doctor.get("hypothesis_portfolio"), list) else []
    unique_hyp = len({str(h.get("hypothesis_id", "")).strip() for h in portfolio if isinstance(h, dict) and str(h.get("hypothesis_id", "")).strip()})
    portfolio_rows = [h for h in portfolio if isinstance(h, dict)]
    commander_decision = str(commander.get("normalized_decision", commander.get("decision", ""))).upper()
    review_ok, review_meta = _validate_doctor_hypothesis_review_structure(commander if isinstance(commander, dict) else {})
    review_missing = bool(review_meta.get("missing", False))
    review_required = len(portfolio_rows) > 0
    checks["commander_hypothesis_review_present"] = _check(
        "PASS" if (not review_required or review_ok) else "FAIL",
        "HYPOTHESIS_REVIEW_MISSING" if review_missing else "HYPOTHESIS_REVIEW_INVALID_SCHEMA",
        str(commander_path),
        {
            "review_required": review_required,
            "portfolio_count": len(portfolio_rows),
            "review_row_count": review_meta.get("row_count"),
            "issues": review_meta.get("issues", [])[:8],
        },
        "CRITICAL",
    )
    portfolio_ids = {
        str(h.get("hypothesis_id", "")).strip()
        for h in portfolio_rows
        if str(h.get("hypothesis_id", "")).strip()
    }
    reviewed_ids = {
        str(x).strip()
        for x in (review_meta.get("reviewed_ids", []) if isinstance(review_meta.get("reviewed_ids"), list) else [])
        if str(x).strip()
    }
    missing_review_ids = sorted(portfolio_ids - reviewed_ids)
    extra_review_ids = sorted(reviewed_ids - portfolio_ids)
    checks["commander_hypothesis_review_coverage"] = _check(
        "PASS"
        if (not review_required or (review_ok and not missing_review_ids and not extra_review_ids))
        else "FAIL",
        "HYPOTHESIS_REVIEW_MISSING" if missing_review_ids else "HYPOTHESIS_REVIEW_INVALID_SCHEMA",
        str(commander_path),
        {
            "review_required": review_required,
            "portfolio_count": len(portfolio_rows),
            "review_row_count": review_meta.get("row_count"),
            "portfolio_ids_count": len(portfolio_ids),
            "reviewed_ids_count": len(reviewed_ids),
            "missing_review_ids": missing_review_ids[:10],
            "extra_review_ids": extra_review_ids[:10],
        },
        "CRITICAL",
    )
    refuted_high_count = int(review_meta.get("refuted_high_count", 0) or 0) if review_ok else 0
    checks["commander_hypothesis_review_policy"] = _check(
        "PASS" if (not review_required or refuted_high_count <= 0 or commander_decision not in {"GO", "RUN_AB", "ROLLOUT_CANDIDATE"}) else "FAIL",
        "HYPOTHESIS_REVIEW_POLICY_VIOLATION",
        str(commander_path),
        {
            "review_required": review_required,
            "commander_decision": commander_decision,
            "refuted_high_count": refuted_high_count,
        },
        "CRITICAL",
    )
    doctor_structured_required = paired_mode and paired_status_raw == "COMPLETE"
    doctor_structured_issues: list[str] = []
    required_doctor_slots = {
        "layer1_verdict": str,
        "layer2_guardrail_verdicts": list,
        "alternative_hypotheses": list,
        "temporal_risk": str,
        "sensitivity_note": str,
        "reasoning_confidence_inputs": dict,
        "layers_present": dict,
    }
    if doctor_structured_required:
        for slot_name, slot_type in required_doctor_slots.items():
            slot_value = doctor.get(slot_name)
            if not isinstance(slot_value, slot_type):
                doctor_structured_issues.append(f"missing_or_invalid:{slot_name}")
        if isinstance(doctor.get("layer1_verdict"), str) and not str(doctor.get("layer1_verdict", "")).strip():
            doctor_structured_issues.append("empty:layer1_verdict")
    checks["doctor_structured_reasoning_slots_present"] = _check(
        "PASS" if (not doctor_structured_required or not doctor_structured_issues) else "FAIL",
        "METHODOLOGY_INVARIANT_BROKEN",
        str(doctor_path),
        {
            "required": doctor_structured_required,
            "paired_mode": paired_mode,
            "paired_status": paired_status_raw,
            "issues": doctor_structured_issues[:10],
        },
        "CRITICAL",
    )
    captain_issues = captain.get("issues", []) if isinstance(captain.get("issues"), list) else []
    captain_issue_density_issues: list[str] = []
    for idx, row in enumerate(captain_issues):
        if not isinstance(row, dict):
            captain_issue_density_issues.append(f"row_not_object:{idx}")
            continue
        for field_name in ("observed_value", "threshold", "delta"):
            if field_name not in row:
                captain_issue_density_issues.append(f"missing_field:{idx}:{field_name}")
                continue
            value = row.get(field_name)
            if value is not None and not isinstance(value, (int, float, str)):
                captain_issue_density_issues.append(f"invalid_scalar:{idx}:{field_name}")
    checks["captain_issue_evidence_density_present"] = _check(
        "PASS" if not captain_issue_density_issues else "FAIL",
        "METHODOLOGY_INVARIANT_BROKEN",
        str(captain_path),
        {
            "issue_count": len(captain_issues),
            "issues": captain_issue_density_issues[:12],
        },
        "CRITICAL",
    )
    commander_guardrail_required = paired_mode and paired_status_raw == "COMPLETE"
    commander_guardrail_rows = (
        commander.get("guardrail_status_check", [])
        if isinstance(commander.get("guardrail_status_check"), list)
        else []
    )
    commander_guardrail_issues: list[str] = []
    if commander_guardrail_required:
        if not commander_guardrail_rows:
            commander_guardrail_issues.append("missing_guardrail_status_check")
        for idx, row in enumerate(commander_guardrail_rows):
            if not isinstance(row, dict):
                commander_guardrail_issues.append(f"row_not_object:{idx}")
                continue
            if not str(row.get("metric_id", "")).strip():
                commander_guardrail_issues.append(f"missing_metric_id:{idx}")
            status = str(row.get("status", "")).strip().upper()
            if status not in {"PASS", "BREACH", "NO_DATA"}:
                commander_guardrail_issues.append(f"invalid_status:{idx}")
            if not isinstance(row.get("blocks_rollout"), bool):
                commander_guardrail_issues.append(f"missing_blocks_rollout_bool:{idx}")
    checks["commander_guardrail_status_check_present"] = _check(
        "PASS" if (not commander_guardrail_required or not commander_guardrail_issues) else "FAIL",
        "METHODOLOGY_INVARIANT_BROKEN",
        str(commander_path),
        {
            "required": commander_guardrail_required,
            "row_count": len(commander_guardrail_rows),
            "issues": commander_guardrail_issues[:12],
        },
        "CRITICAL",
    )
    breach_blocks = any(
        isinstance(row, dict)
        and str(row.get("status", "")).strip().upper() == "BREACH"
        and bool(row.get("blocks_rollout", False))
        for row in commander_guardrail_rows
    )
    aggressive_decision = commander_decision in {"GO", "RUN_AB", "ROLLOUT_CANDIDATE"}
    checks["commander_guardrail_breach_blocks_aggressive_decision"] = _check(
        "PASS" if (not commander_guardrail_required or not breach_blocks or not aggressive_decision) else "FAIL",
        "METHODOLOGY_INVARIANT_BROKEN",
        str(commander_path),
        {
            "required": commander_guardrail_required,
            "breach_blocks_rollout": breach_blocks,
            "commander_decision": commander_decision,
        },
        "CRITICAL",
    )
    confidence_required = paired_mode and paired_status_raw == "COMPLETE"
    confidence_score = commander.get("reasoning_confidence")
    confidence_basis = commander.get("reasoning_confidence_basis")
    confidence_inputs = commander.get("reasoning_confidence_inputs")
    confidence_dynamic_ok = False
    confidence_error = ""
    if not confidence_required:
        confidence_dynamic_ok = True
    else:
        try:
            score_f = float(confidence_score)
            if not (0.0 <= score_f <= 1.0):
                raise ValueError("score_out_of_range")
            if not isinstance(confidence_basis, list) or not confidence_basis:
                raise ValueError("missing_basis")
            if not isinstance(confidence_inputs, dict):
                raise ValueError("missing_inputs")
            has_dynamic_token = any(
                isinstance(x, str)
                and (
                    x.startswith("penalty:")
                    or x.startswith("bonus:")
                    or x.startswith("cap:")
                    or x.startswith("analog_similarity:")
                    or x.startswith("no_bonus:")
                )
                for x in confidence_basis
            )
            if not has_dynamic_token:
                raise ValueError("basis_not_dynamic")
            for key in ("p_value", "best_analog_similarity", "guardrail_data_complete", "n_min", "srm_pass", "paired_status"):
                if key not in confidence_inputs:
                    raise ValueError(f"inputs_missing:{key}")
            confidence_dynamic_ok = True
        except Exception as exc:
            confidence_error = str(exc)
            confidence_dynamic_ok = False
    checks["reasoning_confidence_dynamic_not_hardcoded"] = _check(
        "PASS" if confidence_dynamic_ok else "FAIL",
        "METHODOLOGY_INVARIANT_BROKEN",
        str(commander_path),
        {
            "required": confidence_required,
            "reasoning_confidence": confidence_score,
            "reasoning_confidence_basis": confidence_basis if isinstance(confidence_basis, list) else [],
            "confidence_inputs_keys": sorted(confidence_inputs.keys()) if isinstance(confidence_inputs, dict) else [],
            "error": confidence_error,
        },
        "CRITICAL",
    )
    duration_aggressive_block = (
        duration_days_covered is not None
        and int(duration_days_covered) < int(duration_min_days)
        and commander_decision in {"GO", "RUN_AB", "ROLLOUT_CANDIDATE"}
    )
    checks["experiment_duration_decision_ceiling"] = _check(
        "PASS" if not duration_aggressive_block else "FAIL",
        "EXPERIMENT_DURATION_INSUFFICIENT",
        "data/gates",
        {
            "commander_decision": commander_decision,
            "duration_gate_status": duration_gate_status,
            "days_covered": duration_days_covered,
            "min_experiment_days": duration_min_days,
        },
        "CRITICAL",
    )
    partial_decision_violation = (
        paired_mode
        and is_partial_like(paired_status_raw)
        and commander_decision in {"GO", "RUN_AB", "ROLLOUT_CANDIDATE"}
    )
    checks["paired_partial_ceiling_enforced"] = _check(
        "PASS" if not partial_decision_violation else "FAIL",
        "PAIRED_PARTIAL_CEILING_VIOLATION",
        str(commander_path),
        {
            "paired_mode": paired_mode,
            "paired_status": paired_status_raw,
            "commander_decision": commander_decision,
            "paired_context_path": str(paired_context_path),
        },
        "CRITICAL",
    )
    partial_mode_active = paired_mode and is_partial_like(paired_status_raw)
    anti_goodhart_fail_expected = (
        isinstance(anti_goodhart_verdict, dict)
        and str(anti_goodhart_verdict.get("status", "")).upper() == "FAIL"
        and str(anti_goodhart_verdict.get("error_code", "")).upper() == "AB_ARTIFACT_REQUIRED"
    )
    anti_goodhart_pass_forced_ceiling = (
        isinstance(anti_goodhart_verdict, dict)
        and str(anti_goodhart_verdict.get("status", "")).upper() == "PASS"
        and (
            str((paired_context_payload or {}).get("decision_ceiling", "")).upper() == "HOLD_NEED_DATA"
            or str((commander or {}).get("forced_decision_ceiling", "")).upper() == "HOLD_NEED_DATA"
        )
    )
    checks["paired_partial_anti_goodhart_expected_outcome"] = _check(
        "PASS"
        if (not partial_mode_active or anti_goodhart_fail_expected or anti_goodhart_pass_forced_ceiling)
        else "FAIL",
        "PAIRED_PARTIAL_CEILING_VIOLATION",
        str(anti_goodhart_verdict_path(run_id)),
        {
            "paired_mode": paired_mode,
            "paired_status": paired_status_raw,
            "anti_goodhart_status": (anti_goodhart_verdict or {}).get("status") if isinstance(anti_goodhart_verdict, dict) else None,
            "anti_goodhart_error_code": (anti_goodhart_verdict or {}).get("error_code") if isinstance(anti_goodhart_verdict, dict) else None,
            "forced_ceiling_context": (paired_context_payload or {}).get("decision_ceiling") if isinstance(paired_context_payload, dict) else None,
            "forced_ceiling_commander": (commander or {}).get("forced_decision_ceiling") if isinstance(commander, dict) else None,
        },
        "CRITICAL",
    )
    diversity = _f(doctor_metrics.get("portfolio_diversity_score"))
    measurement_state = str(doctor.get("measurement_state", "")).upper()
    doctor_decision = str(doctor.get("normalized_decision", doctor.get("decision", ""))).upper()
    reasoning_mode = str(doctor.get("reasoning_mode", "standard")).strip().lower()
    protocol_checks_passed = doctor.get("protocol_checks_passed")
    has_fix_plan = isinstance(doctor.get("measurement_fix_plan"), dict)
    flagged_status = str(doctor_metrics.get("flagged_metric_alignment_status", "N/A"))
    flagged_rate = doctor_metrics.get("flagged_metric_alignment_rate")

    checks["doctor_portfolio_ge3"] = _check(
        "PASS" if len(portfolio) >= 3 else "FAIL",
        "doctor_portfolio_size",
        str(doctor_path),
        {"count": len(portfolio)},
    )
    checks["doctor_unique_hyp_ge2"] = _check(
        "PASS" if unique_hyp >= 2 else "FAIL",
        "doctor_unique_hypotheses",
        str(doctor_path),
        {"unique_hypotheses": unique_hyp},
    )
    checks["doctor_diversity_ge05"] = _check(
        "PASS" if (diversity is not None and diversity >= 0.5) else "FAIL",
        "doctor_portfolio_diversity",
        str(agent_eval_path),
        {"portfolio_diversity_score": diversity},
    )
    if measurement_state in {"UNOBSERVABLE", "BLOCKED_BY_DATA"}:
        checks["doctor_fix_plan_when_unobservable"] = _check(
            "PASS" if has_fix_plan else "FAIL",
            "doctor_measurement_fix_plan",
            str(doctor_path),
            {"measurement_state": measurement_state, "has_fix_plan": has_fix_plan},
        )
    else:
        checks["doctor_fix_plan_when_unobservable"] = _check(
            "NA",
            "doctor_measurement_observable",
            str(doctor_path),
            {"measurement_state": measurement_state},
        )
    if flagged_status.upper() == "N/A":
        checks["doctor_tied_to_flagged_metric"] = _check(
            "NA",
            "doctor_flagged_metric_absent",
            str(agent_eval_path),
            {"flagged_metric_alignment_status": flagged_status},
        )
    else:
        checks["doctor_tied_to_flagged_metric"] = _check(
            "PASS" if flagged_status.upper() == "PASS" else "FAIL",
            "doctor_flagged_metric_alignment",
            str(agent_eval_path),
            {
                "flagged_metric_alignment_status": flagged_status,
                "flagged_metric_alignment_rate": flagged_rate,
            },
        )
    if reasoning_mode == "react":
        checks["react_protocol_checks_passed"] = _check(
            "PASS" if protocol_checks_passed is True else "FAIL",
            "react_protocol_checks_failed",
            str(doctor_path),
            {"reasoning_mode": reasoning_mode, "protocol_checks_passed": protocol_checks_passed},
            "CRITICAL",
        )
    else:
        checks["react_protocol_checks_passed"] = _check(
            "NA",
            "react_not_enabled",
            str(doctor_path),
            {"reasoning_mode": reasoning_mode},
        )
    if reasoning_mode == "react" and measurement_state in {"UNOBSERVABLE", "BLOCKED_BY_DATA"}:
        checks["react_unobservable_doctor_ceiling"] = _check(
            "PASS" if doctor_decision in {"STOP", "HOLD_RISK", "HOLD_NEED_DATA"} else "FAIL",
            "react_doctor_decision_too_aggressive",
            str(doctor_path),
            {"doctor_decision": doctor_decision, "measurement_state": measurement_state},
            "CRITICAL",
        )
    else:
        checks["react_unobservable_doctor_ceiling"] = _check(
            "NA",
            "react_unobservable_not_applicable",
            str(doctor_path),
            {"reasoning_mode": reasoning_mode, "measurement_state": measurement_state},
        )

    claims = narrative.get("causal_chains", []) if isinstance(narrative.get("causal_chains"), list) else []
    if not claims and isinstance(narrative.get("claims"), list):
        claims = narrative.get("claims", [])
    claim_count = len(claims)
    has_cause_type = all(isinstance(c, dict) and str(c.get("cause_type", "")).strip() for c in claims)
    has_refs = all(isinstance(c, dict) and isinstance(c.get("evidence_refs"), list) and len(c.get("evidence_refs")) >= 2 for c in claims)
    action_rate = _f(narrative_metrics.get("evidence_refs_to_actions_rate"))
    uniq_pattern = _f(narrative_metrics.get("evidence_pattern_uniqueness_rate"))
    grounded = bool(validation.get("grounded", False)) or str(validation.get("narrative_status", "")).upper() == "GROUNDED"

    checks["narrative_claims_ge3"] = _check(
        "PASS" if claim_count >= 3 else "FAIL",
        "narrative_claim_count",
        str(narrative_path),
        {"claims": claim_count},
    )
    checks["narrative_claims_have_cause_type"] = _check(
        "PASS" if has_cause_type else "FAIL",
        "narrative_cause_type_required",
        str(narrative_path),
        {"claims_with_cause_type": has_cause_type},
    )
    checks["narrative_claims_have_refs_ge2"] = _check(
        "PASS" if has_refs else "FAIL",
        "narrative_evidence_refs_required",
        str(narrative_path),
        {"claims_refs_ge2": has_refs},
    )
    checks["narrative_refs_to_actions_ge05"] = _check(
        "PASS" if (action_rate is not None and action_rate >= 0.5) else "FAIL",
        "narrative_action_linkage",
        str(agent_eval_path),
        {"evidence_refs_to_actions_rate": action_rate},
    )
    checks["narrative_uniqueness"] = _check(
        "PASS" if (uniq_pattern is not None and uniq_pattern >= 0.5) else "FAIL",
        "narrative_uniqueness",
        str(agent_eval_path),
        {"evidence_pattern_uniqueness_rate": uniq_pattern},
    )
    checks["narrative_grounded"] = _check(
        "PASS" if grounded else "FAIL",
        "narrative_grounding",
        str(validation_path),
        {"grounded": grounded, "issues": len(validation.get("issues", [])) if isinstance(validation.get("issues"), list) else None},
        "CRITICAL",
    )
    commander_decision = str(commander.get("normalized_decision", commander.get("decision", ""))).upper()
    if not grounded:
        checks["ungrounded_requires_commander_hold_risk"] = _check(
            "PASS" if commander_decision in {"STOP", "HOLD_RISK", "HOLD_NEED_DATA"} else "FAIL",
            "narrative_ungrounded_commander_too_aggressive",
            str(commander_path),
            {"commander_decision": commander_decision},
            "CRITICAL",
        )
    else:
        checks["ungrounded_requires_commander_hold_risk"] = _check(
            "NA",
            "narrative_grounded",
            str(commander_path),
            {"commander_decision": commander_decision},
        )

    proposal_rows = governance.get("proposal_rows", [])
    if not isinstance(proposal_rows, list):
        proposal_rows = []
    proposals_exist = len(portfolio) > 0 or claim_count > 0
    approvals_exist = len(proposal_rows) > 0
    ids_ok = all(isinstance(r, dict) and re.fullmatch(r"[0-9a-f]{40}", str(r.get("proposal_id", ""))) for r in proposal_rows)
    decisions_ok = all(
        isinstance(r, dict)
        and str(r.get("decision", "")).upper() in {"APPROVE", "REJECT"}
        and str(r.get("reason_code", "")).strip()
        for r in proposal_rows
    )
    gov_status = str(governance.get("governance_status", "")).strip().lower()

    checks["governance_approvals_exist"] = _check(
        "PASS" if (not proposals_exist or approvals_exist) else "FAIL",
        "governance_missing_review_rows",
        str(governance_path),
        {"proposals_exist": proposals_exist, "approvals_rows": len(proposal_rows)},
    )
    checks["governance_proposal_id_deterministic"] = _check(
        "PASS" if ids_ok else "FAIL",
        "governance_proposal_id_invalid",
        str(governance_path),
        {"all_sha1_ids": ids_ok},
    )
    checks["governance_no_auto_approve"] = _check(
        "PASS" if decisions_ok else "FAIL",
        "governance_decision_reason_invalid",
        str(governance_path),
        {"all_rows_have_decision_and_reason": decisions_ok},
    )
    checks["governance_status_not_missing_review"] = _check(
        "PASS" if gov_status != "missing_review" else "FAIL",
        "governance_missing_review",
        str(governance_path),
        {"governance_status": gov_status},
    )

    ab_status = str((ab or {}).get("status", "")).upper()
    evaluator_decision = str(evaluator.get("decision", "")).upper()
    checks["ab_status_valid"] = _check(
        "PASS" if (ab is not None and ab_status not in {"", "INVALID"}) else "FAIL",
        "ab_status_missing_or_invalid",
        str(ab_path) if ab_path else "data/ab_reports/<run>_*_ab.json",
        {"ab_status": ab_status},
        "CRITICAL",
    )
    experiment_expected = bool(args.experiment_id.strip()) or (ab is not None)
    assignment_signal_present = bool(str(evaluator.get("assignment_status", "")).strip()) or ab_status in {
        "OK",
        "UNDERPOWERED",
        "INCONCLUSIVE",
        "MISSING_ASSIGNMENT",
        "METHODOLOGY_MISMATCH",
        "ASSIGNMENT_RECOVERED",
    }
    checks["assignment_signal_present"] = _check(
        "PASS" if (not experiment_expected or assignment_signal_present) else "FAIL",
        "missing_assignment_signal",
        str(evaluator_path),
        {"experiment_expected": experiment_expected, "assignment_status": evaluator.get("assignment_status"), "ab_status": ab_status},
        "CRITICAL",
    )
    if ab_status in {"METHODOLOGY_MISMATCH", "MISSING_ASSIGNMENT"}:
        summary = ab.get("summary", {}) if isinstance(ab, dict) and isinstance(ab.get("summary"), dict) else {}
        uplift_null = summary.get("primary_metric_uplift") is None and summary.get("primary_metric_uplift_ci95") is None
        checks["blind_spot_uplift_must_be_null"] = _check(
            "PASS" if uplift_null else "FAIL",
            "blind_spot_has_uplift_values",
            str(ab_path) if ab_path else "data/ab_reports",
            summary,
            "CRITICAL",
        )
        checks["blind_spot_evaluator_guard"] = _check(
            "PASS" if evaluator_decision in {"STOP", "HOLD_RISK"} else "FAIL",
            "blind_spot_evaluator_not_blocking",
            str(evaluator_path),
            {"evaluator_decision": evaluator_decision, "ab_status": ab_status},
            "CRITICAL",
        )
        mbr_path = Path(f"reports/L1_ops/{run_id}/RETAIL_MBR.md")
        if mbr_path.exists():
            mbr_txt = mbr_path.read_text(encoding="utf-8")
            has_fatal = "## ❌ FATAL" in mbr_txt or "Experiment unobservable" in mbr_txt
            checks["blind_spot_mbr_fatal_banner"] = _check(
                "PASS" if has_fatal else "FAIL",
                "blind_spot_mbr_missing_fatal",
                str(mbr_path),
                {"has_fatal_banner": has_fatal},
                "CRITICAL",
            )
        else:
            checks["blind_spot_mbr_fatal_banner"] = _check(
                "NA",
                "mbr_missing",
                str(mbr_path),
                {"exists": False},
            )
    else:
        checks["blind_spot_uplift_must_be_null"] = _check(
            "NA",
            "blind_spot_not_present",
            str(ab_path) if ab_path else "data/ab_reports",
            {"ab_status": ab_status},
        )
        checks["blind_spot_evaluator_guard"] = _check(
            "NA",
            "blind_spot_not_present",
            str(evaluator_path),
            {"ab_status": ab_status},
        )
        checks["blind_spot_mbr_fatal_banner"] = _check(
            "NA",
            "blind_spot_not_present",
            f"reports/L1_ops/{run_id}/RETAIL_MBR.md",
            {"ab_status": ab_status},
        )
    # Cross-artifact consistency + unsafe commander decision guard.
    evaluator_run = str(evaluator.get("run_id", "")).strip()
    commander_run = str(commander.get("run_id", "")).strip()
    ab_run = str((ab or {}).get("run_id", "")).strip() if isinstance(ab, dict) else ""
    run_consistent = (not evaluator_run or evaluator_run == run_id) and (not commander_run or commander_run == run_id) and (not ab_run or ab_run == run_id)
    checks["artifact_run_id_consistency"] = _check(
        "PASS" if run_consistent else "FAIL",
        "cross_artifact_run_id_mismatch",
        str(evaluator_path),
        {"expected_run_id": run_id, "evaluator_run_id": evaluator_run, "commander_run_id": commander_run, "ab_run_id": ab_run},
        "CRITICAL",
    )
    evaluator_exp = str(evaluator.get("experiment_id", "")).strip()
    ab_exp = str((ab or {}).get("experiment_id", "")).strip() if isinstance(ab, dict) else ""
    exp_consistent = (not evaluator_exp or not ab_exp or evaluator_exp == ab_exp)
    checks["artifact_experiment_id_consistency"] = _check(
        "PASS" if exp_consistent else "FAIL",
        "cross_artifact_experiment_id_mismatch",
        str(evaluator_path),
        {"evaluator_experiment_id": evaluator_exp, "ab_experiment_id": ab_exp},
        "CRITICAL",
    )
    if ab_path and ab_path.exists():
        ab_ts = _parse_iso_ts((ab or {}).get("generated_at")) if isinstance(ab, dict) else None
        ab_epoch = ab_ts.timestamp() if ab_ts else ab_path.stat().st_mtime
        if decision_card_path.exists():
            card_epoch = decision_card_path.stat().st_mtime
            # 1s tolerance for filesystem timestamp resolution.
            is_fresh = card_epoch + 1.0 >= ab_epoch
            checks["artifact_freshness_decision_card_vs_ab"] = _check(
                "PASS" if is_fresh else "FAIL",
                "stale_decision_card_after_ab",
                str(decision_card_path),
                {
                    "ab_generated_at": (ab or {}).get("generated_at") if isinstance(ab, dict) else None,
                    "ab_epoch": ab_epoch,
                    "decision_card_mtime_epoch": card_epoch,
                },
                "CRITICAL",
            )
        else:
            checks["artifact_freshness_decision_card_vs_ab"] = _check(
                "FAIL",
                "decision_card_missing",
                str(decision_card_path),
                {"exists": False},
                "CRITICAL",
            )
    else:
        checks["artifact_freshness_decision_card_vs_ab"] = _check(
            "NA",
            "ab_artifact_missing",
            str(decision_card_path),
            {"ab_exists": False},
        )
    commander_unsafe = False
    unsafe_reasons: list[str] = []
    if commander_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and evaluator_decision in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"}:
        commander_unsafe = True
        unsafe_reasons.append("commander_more_aggressive_than_evaluator")
    if commander_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and measurement_state in {"UNOBSERVABLE", "BLOCKED_BY_DATA"}:
        commander_unsafe = True
        unsafe_reasons.append("commander_ignores_measurement_state")
    if commander_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and ab_status in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH"}:
        commander_unsafe = True
        unsafe_reasons.append("commander_ignores_blind_spot")
    checks["commander_unsafe_decision"] = _check(
        "FAIL" if commander_unsafe else "PASS",
        "commander_unsafe_decision",
        str(commander_path),
        {"commander_decision": commander_decision, "evaluator_decision": evaluator_decision, "measurement_state": measurement_state, "ab_status": ab_status, "unsafe_reasons": unsafe_reasons},
        "CRITICAL",
    )
    if ab_status == "METHODOLOGY_MISMATCH":
        checks["methodology_mismatch_blocked"] = _check(
            "PASS" if evaluator_decision in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"} else "FAIL",
            "methodology_mismatch_not_blocked",
            str(evaluator_path),
            {"evaluator_decision": evaluator_decision},
        )
    else:
        checks["methodology_mismatch_blocked"] = _check(
            "NA",
            "methodology_mismatch_not_present",
            str(ab_path) if ab_path else "data/ab_reports",
            {"ab_status": ab_status},
        )
    if ab_status == "UNDERPOWERED":
        checks["underpowered_handled"] = _check(
            "PASS" if evaluator_decision not in {"RUN_AB", "ROLLOUT_CANDIDATE"} else "FAIL",
            "underpowered_false_win",
            str(evaluator_path),
            {"evaluator_decision": evaluator_decision},
        )
    else:
        checks["underpowered_handled"] = _check(
            "NA",
            "underpowered_not_present",
            str(ab_path) if ab_path else "data/ab_reports",
            {"ab_status": ab_status},
        )
    doctor_reasons = doctor.get("reasons", []) if isinstance(doctor.get("reasons"), list) else []
    evaluator_reasons = evaluator.get("reasons", []) if isinstance(evaluator.get("reasons"), list) else []
    evaluator_blocked = evaluator.get("blocked_by", []) if isinstance(evaluator.get("blocked_by"), list) else []
    sb_findings = synthetic_bias.get("findings", []) if isinstance(synthetic_bias.get("findings"), list) else []
    risk_blob = " ".join([str(x) for x in (doctor_reasons + evaluator_reasons + evaluator_blocked + sb_findings)]).lower()
    goodhart_signal_present = any(
        k in risk_blob
        for k in ("goodhart", "starvation", "guardrail", "margin burn", "margin_burn", "availability starvation")
    )
    if goodhart_signal_present:
        blocked_safely = evaluator_decision in {"STOP", "HOLD_RISK", "HOLD_NEED_DATA"} or commander_decision in {"STOP", "HOLD_RISK", "HOLD_NEED_DATA"}
        checks["goodhart_detection_active"] = _check(
            "PASS" if blocked_safely else "FAIL",
            "goodhart_signal_detected_but_not_blocked",
            str(evaluator_path),
            {
                "evaluator_decision": evaluator_decision,
                "commander_decision": commander_decision,
                "signal_present": True,
            },
        )
    else:
        checks["goodhart_detection_active"] = _check(
            "NA",
            "goodhart_not_triggered",
            str(synthetic_bias_path),
            {"signal_present": False},
        )

    score_values = [
        _f((agent_eval.get("captain", {}) if isinstance(agent_eval.get("captain"), dict) else {}).get("score")),
        _f((agent_eval.get("doctor", {}) if isinstance(agent_eval.get("doctor"), dict) else {}).get("score")),
        _f((agent_eval.get("commander", {}) if isinstance(agent_eval.get("commander"), dict) else {}).get("score")),
        _f((agent_eval.get("narrative", {}) if isinstance(agent_eval.get("narrative"), dict) else {}).get("score")),
    ]
    score_values = [x for x in score_values if x is not None]
    non_trivial_scores = not (score_values and all(abs(x - 1.0) < 1e-9 for x in score_values))
    penalty_exists = False
    if measurement_state in {"UNOBSERVABLE", "BLOCKED_BY_DATA"}:
        penalty_exists = True
    if evaluator_decision in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"}:
        penalty_exists = True
    if isinstance(validation.get("issues"), list) and len(validation.get("issues")) > 0:
        penalty_exists = True
    scenarios = adversarial.get("scenarios", []) if isinstance(adversarial.get("scenarios"), list) else []
    if any(str(s.get("status", "")).upper() in {"WARN", "FAIL"} for s in scenarios if isinstance(s, dict)):
        penalty_exists = True
    if ab_status in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "UNDERPOWERED", "ASSIGNMENT_RECOVERED", "INCONCLUSIVE"}:
        penalty_exists = True
    checks["scores_not_all_ones"] = _check(
        "PASS" if non_trivial_scores else "FAIL",
        "scores_trivial",
        str(agent_eval_path),
        {"scores": score_values},
    )
    checks["at_least_one_penalty_or_hold"] = _check(
        "PASS" if penalty_exists else "FAIL",
        "no_penalty_detected",
        str(agent_eval_path),
        {
            "measurement_state": measurement_state,
            "evaluator_decision": evaluator_decision,
            "ab_status": ab_status,
        },
    )
    reasoning_layer_status = str((system_metrics.get("reasoning_layer_status", "") or "")).upper()
    reasoning_layer_score = _f(system_metrics.get("reasoning_layer_score"))
    checks["reasoning_layer_status"] = _check(
        "PASS" if reasoning_layer_status in {"PASS", "WARN"} else "FAIL",
        "reasoning_layer_status_missing",
        str(agent_eval_path),
        {"reasoning_layer_status": reasoning_layer_status, "reasoning_layer_score": reasoning_layer_score},
        "ADVISORY",
    )
    reasoning_checks = agent_eval.get("reasoning_checks", {}) if isinstance(agent_eval.get("reasoning_checks"), dict) else {}
    for metric_name in reasoning_check_names:
        raw_val = reasoning_checks.get(metric_name)
        val = _f(raw_val)
        ok = val is not None and 0.0 <= val <= 1.0
        checks[f"reasoning_check_{metric_name}"] = _check(
            "PASS" if ok else "FAIL",
            "reasoning_check_missing_or_invalid",
            str(agent_eval_path),
            {"metric": metric_name, "value": raw_val},
            "ADVISORY",
        )
    checks["reasoning_checks_status"] = _check(
        "PASS" if str(reasoning_checks.get("status", "")).upper() in {"PASS", "WARN"} else "FAIL",
        "reasoning_checks_status_missing",
        str(agent_eval_path),
        {"status": reasoning_checks.get("status"), "mode": reasoning_checks.get("mode")},
        "ADVISORY",
    )
    vector_status = str(vector_quality.get("status", "")).upper()
    vector_score = _f(vector_quality.get("vector_quality_score"))
    if vector_quality_path.exists():
        checks["vector_quality_signal"] = _check(
            "PASS" if vector_status in {"PASS", "WARN"} else "FAIL",
            "vector_quality_status_missing",
            str(vector_quality_path),
            {"status": vector_status, "score": vector_score},
            "ADVISORY",
        )
    else:
        checks["vector_quality_signal"] = _check(
            "NA",
            "vector_quality_not_present",
            str(vector_quality_path),
            {"exists": False},
        )

    if pre_publish is None:
        checks["pre_publish_audit"] = _check(
            "FAIL" if require_pre_publish else "NA",
            "pre_publish_missing",
            str(pre_publish_path),
            {"required": require_pre_publish},
            "CRITICAL" if require_pre_publish else "ADVISORY",
        )
    else:
        passed = bool(pre_publish.get("passed"))
        checks["pre_publish_audit"] = _check(
            "PASS" if passed else "FAIL",
            "pre_publish_not_passed",
            str(pre_publish_path),
            pre_publish.get("counts", {}),
            "CRITICAL",
        )
    findings = pre_publish.get("findings", []) if isinstance(pre_publish, dict) and isinstance(pre_publish.get("findings"), list) else []
    secret_types = {"dsn", "api_key", "password", "token", "groq_key", "json_secret_kv", "yaml_secret_kv", "bearer_token"}
    has_secret_findings = any(str(f.get("type", "")).lower() in secret_types for f in findings if isinstance(f, dict))
    checks["no_secret_leakage_detected"] = _check(
        "PASS" if not has_secret_findings else "FAIL",
        "secret_pattern_detected",
        str(pre_publish_path) if pre_publish_path.exists() else "data/agent_quality/<run>_pre_publish_audit.json",
        {"secret_findings": has_secret_findings},
        "CRITICAL",
    )
    json_manifest_path = Path(f"reports/L1_ops/{run_id}/artifact_manifest.json")
    manifest_ok, manifest_issues = verify_json_manifest(
        json_manifest_path,
        require_manifest=True,
        verify_manifest_sidecar=True,
    )
    checks["artifact_manifest_integrity"] = _check(
        "PASS" if manifest_ok else "FAIL",
        "artifact_manifest_invalid",
        str(json_manifest_path),
        {"issues": manifest_issues[:5]},
        "CRITICAL",
    )
    manifest_scope_ok, manifest_scope_issues = verify_manifest_scope(
        json_manifest_path,
        run_id=run_id,
        ignore_globs=manifest_scope_ignore_globs,
        require_manifest=True,
    )
    checks["artifact_manifest_scope"] = _check(
        "PASS" if manifest_scope_ok else "FAIL",
        "artifact_manifest_scope_invalid",
        str(json_manifest_path),
        {
            "issues": manifest_scope_issues[:5],
            "security_profile": security_profile.get("name"),
            "strict_manifest_scope": strict_manifest_scope,
        },
        "CRITICAL" if strict_manifest_scope else "ADVISORY",
    )
    ddl_targets = _runtime_ddl_scan_targets()
    ddl_findings = _runtime_ddl_findings(ddl_targets)
    runtime_ddl_detected = len(ddl_findings) > 0
    checks["no_runtime_ddl_detected"] = _check(
        "PASS" if not runtime_ddl_detected else "FAIL",
        "runtime_ddl_detected",
        "scripts/run_all.py",
        {"runtime_ddl_detected": runtime_ddl_detected, "findings": ddl_findings[:5], "targets": [str(p) for p in ddl_targets[:20]]},
        "CRITICAL",
    )
    direct_cloud_findings = _scan_direct_cloud_usage_policy()
    checks["llm_secure_gateway_enforced"] = _check(
        "PASS" if not direct_cloud_findings else "FAIL",
        "SANITIZATION_REQUIRED_FOR_CLOUD",
        "scripts/run_*",
        {"violations": direct_cloud_findings[:10]},
        "CRITICAL",
    )
    sanitization_policy = None
    sanitization_policy_err = ""
    try:
        sanitization_policy = load_json_with_integrity(SANITIZATION_POLICY_PATH)
    except Exception as exc:
        sanitization_policy_err = str(exc)
    sanitization_transform = None
    sanitization_transform_err = ""
    try:
        sanitization_transform = load_json_with_integrity(SANITIZATION_TRANSFORM_PATH)
    except Exception as exc:
        sanitization_transform_err = str(exc)
    sanitization_policy_ok = (
        isinstance(sanitization_policy, dict)
        and str(sanitization_policy.get("storage_policy", "")).strip() == "security_obfuscation_map_only"
        and bool(sanitization_policy.get("encrypted_at_rest", False)) is True
        and str(sanitization_policy.get("encryption_algorithm", "")).strip() == "openssl_aes_256_cbc_pbkdf2"
        and bool(sanitization_policy.get("kms_envelope_required", False)) is True
        and bool(sanitization_policy.get("acl_enforced", False)) is True
        and bool(sanitization_policy.get("decrypt_roundtrip_required", False)) is True
        and bool(sanitization_policy.get("audit_log_required", False)) is True
    )
    checks["sanitization_policy_contract"] = _check(
        "PASS" if sanitization_policy_ok else "FAIL",
        "SANITIZATION_MAP_POLICY_VIOLATION",
        str(SANITIZATION_POLICY_PATH),
        sanitization_policy if isinstance(sanitization_policy, dict) else {"error": sanitization_policy_err},
        "CRITICAL",
    )
    sanitization_transform_ok = (
        isinstance(sanitization_transform, dict)
        and str(sanitization_transform.get("version", "")).strip() == "sanitization_transform_v1"
        and str(sanitization_transform.get("transform_mode", "")).strip() == "vectorized_placeholder_map"
        and bool(sanitization_transform.get("require_vectorization_for_cloud", False)) is True
        and bool(sanitization_transform.get("response_deobfuscation_required", False)) is True
    )
    checks["sanitization_transform_contract"] = _check(
        "PASS" if sanitization_transform_ok else "FAIL",
        "SANITIZATION_REQUIRED_FOR_CLOUD",
        str(SANITIZATION_TRANSFORM_PATH),
        sanitization_transform if isinstance(sanitization_transform, dict) else {"error": sanitization_transform_err},
        "CRITICAL",
    )
    forbidden_map_hits: list[str] = []
    for root in (Path("reports"), Path("human_reports"), Path("data/agent_reports")):
        if not root.exists():
            continue
        for p in root.rglob("*obfusc*map*.json"):
            if p.is_file():
                forbidden_map_hits.append(str(p))
    checks["sanitization_map_not_published"] = _check(
        "PASS" if not forbidden_map_hits else "FAIL",
        "SANITIZATION_MAP_POLICY_VIOLATION",
        "reports|human_reports|data/agent_reports",
        {"forbidden_paths": forbidden_map_hits[:20]},
        "CRITICAL",
    )
    captain_prov = captain.get("llm_provenance", {}) if isinstance(captain, dict) and isinstance(captain.get("llm_provenance"), dict) else {}
    commander_prov = commander.get("llm_provenance", {}) if isinstance(commander, dict) and isinstance(commander.get("llm_provenance"), dict) else {}
    poc_usage_rows = []
    if isinstance(poc_payload, dict):
        for key in ("captain_usage", "doctor_usage", "commander_usage"):
            row = poc_payload.get(key)
            if isinstance(row, dict):
                poc_usage_rows.append(row)
    captain_map_refs = captain_prov.get("obfuscation_map_refs", []) if isinstance(captain_prov.get("obfuscation_map_refs"), list) else []
    has_explicit_map_refs = bool(captain_map_refs) or ("obfuscation_map_ref" in json.dumps(doctor, ensure_ascii=False)) or (
        "obfuscation_map_ref" in json.dumps(commander, ensure_ascii=False)
    ) or (
        "obfuscation_map_ref" in json.dumps(poc_payload, ensure_ascii=False)
    )
    captain_cloud_actual = (
        bool(captain_prov.get("remote_allowed", False))
        and bool(captain_prov.get("attempted_llm_path", False))
        and not bool(captain_prov.get("used_fallback", False))
        and str(captain.get("model", "")).strip().lower() != "local_mock"
    )
    commander_cloud_actual = (
        bool(commander_prov.get("remote_allowed", False))
        and not bool(commander_prov.get("used_fallback", False))
        and str(commander_prov.get("backend_requested", "")).strip().lower() in {"groq", "openai", "anthropic"}
    )
    poc_cloud_actual = any(
        bool(row.get("cloud_path", False))
        and str(row.get("backend", "")).strip().lower() in {"groq", "openai", "anthropic"}
        for row in poc_usage_rows
    )
    doctor_cloud_intent = _payload_has_cloud_backend(doctor) and ("obfuscation_map_ref" in json.dumps(doctor, ensure_ascii=False))
    cloud_path_used = bool(
        has_explicit_map_refs or captain_cloud_actual or commander_cloud_actual or doctor_cloud_intent or poc_cloud_actual
    )
    map_root = Path("data/security/obfuscation_maps")
    map_files = sorted(
        [
            p
            for p in map_root.glob("*.json")
            if p.is_file()
            and p.name.startswith(f"{run_id}_")
            and p.name != "audit_log.jsonl"
            and not p.name.endswith("_manifest.json")
        ]
    )
    audit_log_path = map_root / "audit_log.jsonl"
    audit_entries_for_run = 0
    if audit_log_path.exists():
        try:
            for raw_line in audit_log_path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if str(row.get("run_id", "")).strip() == run_id:
                    audit_entries_for_run += 1
        except Exception:
            audit_entries_for_run = 0
    manifest_path = map_root / f"{run_id}_obfuscation_manifest.json"
    manifest_ok, manifest_issues = verify_json_manifest(
        manifest_path,
        require_manifest=cloud_path_used,
        verify_manifest_sidecar=True,
    )
    map_encryption_ok = True
    map_encryption_reason = "present_or_not_required"
    map_docs: list[dict[str, Any]] = []
    if cloud_path_used:
        if not map_files:
            map_encryption_ok = False
            map_encryption_reason = "cloud_path_used_but_obfuscation_map_missing"
        else:
            for p in map_files:
                try:
                    doc = load_json_with_integrity(p)
                except Exception as exc:
                    map_encryption_ok = False
                    map_encryption_reason = f"map_integrity_or_json_invalid:{p}:{exc}"
                    break
                map_docs.append(doc)
                enc_ok, enc_reason = verify_encrypted_map_document(
                    doc,
                    kms_key_ref=str((sanitization_policy or {}).get("kms_key_ref", "")),
                    require_roundtrip=bool((sanitization_policy or {}).get("decrypt_roundtrip_required", True)),
                )
                if not enc_ok:
                    map_encryption_ok = False
                    map_encryption_reason = f"{p}:{enc_reason}"
                    break
    checks["map_encryption_verified"] = _check(
        "PASS" if map_encryption_ok else "FAIL",
        "MAP_ENCRYPTION_VERIFIED",
        str(map_root),
        {
            "cloud_path_used": cloud_path_used,
            "map_count": len(map_files),
            "reason": map_encryption_reason,
        },
        "CRITICAL",
    )
    vectorization_ok = True
    deobfuscation_required_ok = True
    deobfuscation_actual_ok = True
    if cloud_path_used:
        if not map_docs:
            vectorization_ok = False
            deobfuscation_required_ok = False
            deobfuscation_actual_ok = False
        else:
            vectorization_ok = all(bool(doc.get("sanitization_vectorization_applied", False)) for doc in map_docs)
            deobfuscation_required_ok = all(bool(doc.get("response_deobfuscation_required", False)) for doc in map_docs)
            deobfuscation_actual_ok = all(
                (
                    isinstance(doc.get("response_deobfuscation_applied_actual"), bool)
                    and int(doc.get("response_deobfuscation_hit_count", 0) or 0) >= 0
                    and (
                        bool(doc.get("response_deobfuscation_applied_actual", False))
                        == (int(doc.get("response_deobfuscation_hit_count", 0) or 0) > 0)
                    )
                )
                for doc in map_docs
            )
    checks["sanitization_vectorization_applied"] = _check(
        "PASS" if vectorization_ok else "FAIL",
        "SANITIZATION_REQUIRED_FOR_CLOUD",
        str(map_root),
        {"cloud_path_used": cloud_path_used, "map_count": len(map_files)},
        "CRITICAL",
    )
    checks["response_deobfuscation_required"] = _check(
        "PASS" if deobfuscation_required_ok else "FAIL",
        "SANITIZATION_REQUIRED_FOR_CLOUD",
        str(map_root),
        {"cloud_path_used": cloud_path_used, "map_count": len(map_files)},
        "CRITICAL",
    )
    checks["response_deobfuscation_applied"] = _check(
        "PASS" if deobfuscation_actual_ok else "FAIL",
        "SANITIZATION_REQUIRED_FOR_CLOUD",
        str(map_root),
        {"cloud_path_used": cloud_path_used, "map_count": len(map_files)},
        "CRITICAL",
    )
    audit_log_ok = True
    audit_reason = "present_or_not_required"
    if isinstance(sanitization_policy, dict) and bool(sanitization_policy.get("audit_log_required", False)) is True:
        if cloud_path_used and len(map_files) == 0:
            audit_log_ok = False
            audit_reason = "cloud_path_used_but_obfuscation_map_missing"
        elif cloud_path_used and audit_entries_for_run <= 0:
            audit_log_ok = False
            audit_reason = "cloud_path_used_but_audit_trail_missing"
        elif cloud_path_used and not manifest_ok:
            audit_log_ok = False
            audit_reason = f"cloud_path_manifest_invalid:{','.join(manifest_issues[:3])}"
    checks["sanitization_audit_trail"] = _check(
        "PASS" if audit_log_ok else "FAIL",
        "SANITIZATION_AUDIT_TRAIL_MISSING",
        str(audit_log_path),
        {
            "cloud_path_used": cloud_path_used,
            "poc_cloud_path_used": poc_cloud_actual,
            "map_count": len(map_files),
            "audit_entries_for_run": audit_entries_for_run,
            "manifest_path": str(manifest_path),
            "manifest_ok": manifest_ok,
            "manifest_issues": manifest_issues[:5],
            "audit_reason": audit_reason,
        },
        "CRITICAL",
    )
    reconciliation_policy = None
    reconciliation_policy_err = ""
    try:
        reconciliation_policy = load_json_with_integrity(RECONCILIATION_POLICY_PATH)
    except Exception as exc:
        reconciliation_policy_err = str(exc)
    reconciliation_policy_ok = (
        isinstance(reconciliation_policy, dict)
        and str(reconciliation_policy.get("version", "")).strip() == "reconciliation_policy_v1"
        and bool(reconciliation_policy.get("provisional_requires_reconciliation", False)) is True
        and bool(reconciliation_policy.get("reconciliation_job_required", False)) is True
    )
    checks["reconciliation_policy_contract"] = _check(
        "PASS" if reconciliation_policy_ok else "FAIL",
        "PROVISIONAL_REQUIRES_RECONCILIATION",
        str(RECONCILIATION_POLICY_PATH),
        reconciliation_policy if isinstance(reconciliation_policy, dict) else {"error": reconciliation_policy_err},
        "CRITICAL",
    )
    doctor_prov = doctor.get("llm_provenance", {}) if isinstance(doctor, dict) and isinstance(doctor.get("llm_provenance"), dict) else {}
    commander_decision_prov = (
        commander.get("llm_decision_provenance", {})
        if isinstance(commander, dict) and isinstance(commander.get("llm_decision_provenance"), dict)
        else {}
    )
    provisional_agents: list[str] = []
    if (
        bool(captain.get("provisional_local_fallback", False))
        or bool(captain.get("needs_cloud_reconciliation", False))
        or bool(captain_prov.get("needs_cloud_reconciliation", False))
    ):
        provisional_agents.append("captain")
    doctor_hyp_gen = doctor_prov.get("hypothesis_generation", {}) if isinstance(doctor_prov.get("hypothesis_generation"), dict) else {}
    doctor_hsum = doctor_prov.get("human_summary", {}) if isinstance(doctor_prov.get("human_summary"), dict) else {}
    if (
        bool(doctor.get("provisional_local_fallback", False))
        or bool(doctor.get("needs_cloud_reconciliation", False))
        or bool(doctor_hyp_gen.get("needs_cloud_reconciliation", False))
        or bool(doctor_hsum.get("needs_cloud_reconciliation", False))
        or str(doctor.get("model_used", "")).strip().lower() == "local_mock"
    ):
        provisional_agents.append("doctor")
    if (
        bool(commander.get("provisional_local_fallback", False))
        or bool(commander.get("needs_cloud_reconciliation", False))
        or bool(commander_decision_prov.get("needs_cloud_reconciliation", False))
        or str(commander.get("commander_model", "")).strip().lower() == "local_mock"
    ):
        provisional_agents.append("commander")
    provisional_required = len(provisional_agents) > 0
    recon_job_path = Path(f"data/reconciliation/{run_id}_reconciliation_job.json")
    recon_result_path = Path(f"data/reconciliation/{run_id}_reconciliation_result.json")
    recon_job_ok = False
    recon_result_ok = False
    recon_issue = "not_required"
    recon_job_payload: dict[str, Any] | None = None
    if provisional_required:
        try:
            recon_job_payload = load_json_with_integrity(recon_job_path)
            recon_job_ok = True
        except Exception as exc:
            recon_issue = f"reconciliation_job_missing_or_invalid:{exc}"
        if recon_job_ok:
            if bool(recon_job_payload.get("needs_cloud_reconciliation", False)) is not True:
                recon_job_ok = False
                recon_issue = "reconciliation_job_needs_cloud_reconciliation_false"
            elif not isinstance(recon_job_payload.get("fallback_agents"), list) or not recon_job_payload.get("fallback_agents"):
                recon_job_ok = False
                recon_issue = "reconciliation_job_fallback_agents_missing"
            else:
                try:
                    _ = load_json_with_integrity(recon_result_path)
                    recon_result_ok = True
                except Exception:
                    recon_result_ok = False
                if not recon_result_ok:
                    recon_issue = "reconciliation_result_missing_or_invalid"
        if recon_job_ok and recon_result_ok:
            recon_issue = "ok"
    checks["provisional_requires_reconciliation"] = _check(
        "PASS" if (not provisional_required or (recon_job_ok and recon_result_ok)) else "FAIL",
        "PROVISIONAL_REQUIRES_RECONCILIATION",
        str(recon_job_path),
        {
            "provisional_required": provisional_required,
            "provisional_agents": provisional_agents,
            "reconciliation_job_ok": recon_job_ok,
            "reconciliation_result_ok": recon_result_ok,
            "issue": recon_issue,
        },
        "CRITICAL",
    )
    provisional_final_block = (
        provisional_required
        and commander_decision in {"GO", "RUN_AB", "ROLLOUT_CANDIDATE"}
        and not (recon_job_ok and recon_result_ok)
    )
    checks["provisional_final_decision_blocked"] = _check(
        "PASS" if not provisional_final_block else "FAIL",
        "PROVISIONAL_REQUIRES_RECONCILIATION",
        str(recon_result_path),
        {
            "provisional_required": provisional_required,
            "commander_decision": commander_decision,
            "reconciliation_job_ok": recon_job_ok,
            "reconciliation_result_ok": recon_result_ok,
            "issue": recon_issue,
        },
        "CRITICAL",
    )
    weak_ceiling_expected = str(feature_state.get("default_weak_path_ceiling", "HOLD_NEED_DATA")).upper() or "HOLD_NEED_DATA"
    if weak_events:
        weak_ceiling_violations = [
            {
                "source_event_id": str(e.get("source_event_id", "")),
                "decision_ceiling_applied": str(e.get("decision_ceiling_applied", "")),
                "source": e.get("__source_path"),
            }
            for e in weak_events
            if str(e.get("decision_ceiling_applied", "")).upper() != weak_ceiling_expected
        ]
        checks["weak_path_without_ceiling"] = _check(
            "PASS" if not weak_ceiling_violations else "FAIL",
            "weak_path_without_ceiling",
            "data/event_bus/**/*.json",
            {"violations": weak_ceiling_violations[:5], "expected_ceiling": weak_ceiling_expected},
            "CRITICAL",
        )
    else:
        checks["weak_path_without_ceiling"] = _check(
            "NA",
            "weak_path_not_present",
            "data/event_bus/**/*.json",
            {"weak_event_count": 0},
            "CRITICAL",
        )

    auto_change_rows = [
        {
            "kind": str(e.get("__kind")),
            "source_event_id": str(e.get("source_event_id", "")),
            "reconciliation_id": str(e.get("reconciliation_id", "")),
            "source": e.get("__source_path"),
        }
        for e in weak_reconciliation_events
        if _to_bool(e.get("auto_decision_change_applied"))
    ]
    checks["auto_decision_change_detected"] = _check(
        "FAIL" if auto_change_rows else "PASS",
        "auto_decision_change_detected" if auto_change_rows else "auto_decision_change_not_detected",
        "data/event_bus/**/*.json",
        {"violations": auto_change_rows[:5], "event_count": len(weak_reconciliation_events)},
        "CRITICAL",
    )
    if recommended_overrides:
        override_policy_violations = [
            {
                "reconciliation_id": str(e.get("reconciliation_id", "")),
                "human_approval_required": e.get("human_approval_required"),
                "source": e.get("__source_path"),
            }
            for e in recommended_overrides
            if not _to_bool(e.get("human_approval_required"))
        ]
        checks["recommended_override_requires_human_approval"] = _check(
            "PASS" if not override_policy_violations else "FAIL",
            "recommended_override_requires_human_approval",
            "data/event_bus/**/*.json",
            {"violations": override_policy_violations[:5], "event_count": len(recommended_overrides)},
            "CRITICAL",
        )
    else:
        checks["recommended_override_requires_human_approval"] = _check(
            "NA",
            "recommended_override_not_present",
            "data/event_bus/**/*.json",
            {"event_count": 0},
            "CRITICAL",
        )

    # Reconciliation stale check (weak-path must end in COMPLETED|EXPIRED|FAILED within SLA TTL).
    terminal_statuses = {"COMPLETED", "EXPIRED", "FAILED"}
    ttl_hours = int(runtime_limits.get("reconciliation_ttl_hours", 24) or 24)
    now_utc = datetime.now(timezone.utc)
    result_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in reconciliation_results:
        source_id = str(event.get("source_event_id", "")).strip()
        if source_id:
            result_by_source[source_id].append(event)
    stale_rows: list[dict[str, Any]] = []
    if weak_events:
        for weak in weak_events:
            source_event_id = str(weak.get("source_event_id", "")).strip()
            weak_status = str(weak.get("reconciliation_status", "")).upper()
            if weak_status in terminal_statuses:
                continue
            matched_results = result_by_source.get(source_event_id, [])
            latest_status = ""
            latest_ts: datetime | None = None
            for row in matched_results:
                ts = _parse_iso_ts(row.get("completed_at"))
                if ts and (latest_ts is None or ts > latest_ts):
                    latest_ts = ts
                    latest_status = str(row.get("reconciliation_status", "")).upper()
            if latest_status in terminal_statuses:
                continue
            occurred_at = _parse_iso_ts(weak.get("occurred_at"))
            if occurred_at is None:
                stale_rows.append(
                    {
                        "source_event_id": source_event_id,
                        "reason": "weak_occurred_at_missing_or_invalid",
                        "weak_status": weak_status,
                    }
                )
                continue
            age_hours = (now_utc - occurred_at).total_seconds() / 3600.0
            if age_hours > float(ttl_hours):
                stale_rows.append(
                    {
                        "source_event_id": source_event_id,
                        "reason": "reconciliation_stale",
                        "age_hours": round(age_hours, 2),
                        "ttl_hours": ttl_hours,
                        "weak_status": weak_status,
                        "latest_result_status": latest_status or "MISSING",
                    }
                )
        checks["reconciliation_stale"] = _check(
            "FAIL" if stale_rows else "PASS",
            "reconciliation_stale" if stale_rows else "reconciliation_within_sla",
            "data/event_bus/**/*.json",
            {"violations": stale_rows[:5], "ttl_hours": ttl_hours, "weak_event_count": len(weak_events)},
            "CRITICAL",
        )
    else:
        checks["reconciliation_stale"] = _check(
            "NA",
            "weak_path_not_present",
            "data/event_bus/**/*.json",
            {"weak_event_count": 0, "ttl_hours": ttl_hours},
            "CRITICAL",
        )

    # Payload guard: chunk_ref_required must be true when payload size exceeds contract limit.
    max_payload_bytes_contract = int(runtime_limits.get("max_payload_bytes", 0) or 0)
    payload_guard_violations: list[dict[str, Any]] = []
    if reconciliation_requests and max_payload_bytes_contract > 0:
        for event in reconciliation_requests:
            event_max_payload = _to_int(event.get("max_payload_bytes"))
            if event_max_payload is None:
                continue
            if event_max_payload > max_payload_bytes_contract and not _to_bool(event.get("chunk_ref_required")):
                payload_guard_violations.append(
                    {
                        "reason": "chunk_ref_required_missing_for_oversize_payload",
                        "max_payload_bytes": event_max_payload,
                        "contract_max_payload_bytes": max_payload_bytes_contract,
                        "source_event_id": str(event.get("source_event_id", "")),
                        "source": event.get("__source_path"),
                    }
                )
        checks["reconciliation_chunk_ref_guard"] = _check(
            "FAIL" if payload_guard_violations else "PASS",
            "reconciliation_chunk_ref_guard_failed" if payload_guard_violations else "reconciliation_chunk_ref_guard_ok",
            "data/event_bus/**/*.json",
            {
                "violations": payload_guard_violations[:5],
                "request_event_count": len(reconciliation_requests),
                "contract_max_payload_bytes": max_payload_bytes_contract,
            },
            "CRITICAL",
        )
    elif reconciliation_requests:
        checks["reconciliation_chunk_ref_guard"] = _check(
            "FAIL",
            "runtime_contract_payload_limit_missing",
            "configs/contracts/runtime_limits_v1.json",
            {"request_event_count": len(reconciliation_requests)},
            "CRITICAL",
        )
    else:
        checks["reconciliation_chunk_ref_guard"] = _check(
            "NA",
            "reconciliation_not_present",
            "data/event_bus/**/*.json",
            {"request_event_count": 0, "contract_max_payload_bytes": max_payload_bytes_contract},
            "CRITICAL",
        )

    # Loop guard check: attempt_no <= max_attempts, no duplicate loop_guard_key, no cyclic source_event_id.
    loop_violations: list[dict[str, Any]] = []
    max_attempts_contract = int(runtime_limits.get("max_reconcile_attempts", 1) or 1)
    loop_guard_counts: dict[str, int] = defaultdict(int)
    recon_events = [*reconciliation_requests, *reconciliation_results]
    reconciliation_ids = {
        str(e.get("reconciliation_id", "")).strip()
        for e in [*reconciliation_requests, *reconciliation_results, *recommended_overrides]
        if str(e.get("reconciliation_id", "")).strip()
    }
    for event in recon_events:
        attempt_no = _to_int(event.get("attempt_no"))
        max_attempts = _to_int(event.get("max_attempts"))
        if attempt_no is not None and max_attempts is not None and attempt_no > max_attempts:
            loop_violations.append(
                {
                    "reason": "attempt_exceeds_event_max_attempts",
                    "attempt_no": attempt_no,
                    "max_attempts": max_attempts,
                    "source": event.get("__source_path"),
                }
            )
        if attempt_no is not None and attempt_no > max_attempts_contract:
            loop_violations.append(
                {
                    "reason": "attempt_exceeds_contract_max_attempts",
                    "attempt_no": attempt_no,
                    "contract_max_attempts": max_attempts_contract,
                    "source": event.get("__source_path"),
                }
            )
        loop_guard_key = str(event.get("loop_guard_key", "")).strip()
        if loop_guard_key:
            loop_guard_counts[loop_guard_key] += 1
        source_event_id = str(event.get("source_event_id", "")).strip()
        event_id = str(event.get("event_id", "")).strip()
        reconciliation_id = str(event.get("reconciliation_id", "")).strip()
        if source_event_id and source_event_id in reconciliation_ids:
            loop_violations.append(
                {
                    "reason": "cyclic_source_event_id",
                    "source_event_id": source_event_id,
                    "reconciliation_id": reconciliation_id,
                    "source": event.get("__source_path"),
                }
            )
        if source_event_id and event_id and source_event_id == event_id:
            loop_violations.append(
                {
                    "reason": "self_referential_source_event_id",
                    "event_id": event_id,
                    "source": event.get("__source_path"),
                }
            )
        if source_event_id and reconciliation_id and source_event_id == reconciliation_id:
            loop_violations.append(
                {
                    "reason": "source_event_equals_reconciliation_id",
                    "source_event_id": source_event_id,
                    "reconciliation_id": reconciliation_id,
                    "source": event.get("__source_path"),
                }
            )
    for key, cnt in loop_guard_counts.items():
        if cnt > 1:
            loop_violations.append({"reason": "duplicate_loop_guard_key", "loop_guard_key": key, "count": cnt})
    if recon_events:
        checks["reconciliation_loop_detected"] = _check(
            "FAIL" if loop_violations else "PASS",
            "reconciliation_loop_detected" if loop_violations else "reconciliation_loop_guard_ok",
            "data/event_bus/**/*.json",
            {"violations": loop_violations[:5], "event_count": len(recon_events), "contract_max_attempts": max_attempts_contract},
            "CRITICAL",
        )
    else:
        checks["reconciliation_loop_detected"] = _check(
            "NA",
            "reconciliation_not_present",
            "data/event_bus/**/*.json",
            {"event_count": 0, "contract_max_attempts": max_attempts_contract},
            "CRITICAL",
        )

    required_files = {
        "agent_value_eval_json": agent_eval_path,
        "decision_outcomes_ledger_json": decision_outcomes_ledger_path(run_id),
        "offline_kpi_backtest_json": offline_kpi_backtest_path(run_id),
        "agent_approvals_json": governance_path,
        "adversarial_suite_json": adversarial_path,
        "agent_value_scorecard_md": scorecard_path,
        "demo_index_md": demo_index_path,
        "causal_explanation_md": causal_md_path,
    }
    for label, path in required_files.items():
        checks[f"artifact_exists_{label}"] = _check(
            "PASS" if path.exists() else "FAIL",
            "missing_artifact",
            str(path),
            {"exists": path.exists()},
        )

    statuses = [c["status"] for c in checks.values()]
    fail_count = sum(1 for s in statuses if s == "FAIL")
    pass_count = sum(1 for s in statuses if s == "PASS")
    na_count = sum(1 for s in statuses if s == "NA")
    critical_fail_count = sum(
        1 for c in checks.values() if c.get("status") == "FAIL" and str(c.get("severity", "ADVISORY")).upper() == "CRITICAL"
    )
    overall = "PASS" if critical_fail_count == 0 else "FAIL"

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall,
        "counts": {"pass": pass_count, "fail": fail_count, "na": na_count, "critical_fail": critical_fail_count},
        "checks": checks,
        "version": "acceptance_verify.v1",
        "security_profile": security_profile.get("name"),
        "strict_manifest_scope": strict_manifest_scope,
    }

    out_json = Path(f"data/acceptance/{run_id}_acceptance.json")
    _safe_write_json(out_json, payload)

    def row(label: str, key: str) -> str:
        c = checks[key]
        return f"| {label} | {_icon(c['status'])} | `{c.get('severity','ADVISORY')}` | `{c['evidence_path']}` | {c['reason_code']} |"

    md_lines = [
        f"# ACCEPTANCE REPORT — {run_id}",
        "",
        f"**Run ID:** `{run_id}`",
        f"**Generated at:** `{payload['generated_at']}`",
        f"**Overall Status:** {_icon(overall)}",
        "",
        "## One-minute summary",
        f"- Decision safety: `{overall}` (critical_fail={critical_fail_count})",
        f"- Why: assignment/measurement/narrative/governance guards were {'satisfied' if critical_fail_count == 0 else 'violated'}",
        f"- Reasoning layer: `{system_metrics.get('reasoning_layer_status', 'missing')}` (score={system_metrics.get('reasoning_layer_score', 'missing')})",
        f"- Action: {'Can proceed with current decision path.' if critical_fail_count == 0 else 'Fix CRITICAL checks before rollout.'}",
        "",
        "## 30-second summary (Exec)",
        f"- What happened: evaluator=`{evaluator_decision}`, commander=`{commander_decision}`, AB status=`{ab_status or 'missing'}`.",
        f"- Business risk now: `{'LOW' if critical_fail_count == 0 else 'HIGH'}` (critical_fail=`{critical_fail_count}`, measurement_state=`{measurement_state or 'missing'}`).",
        f"- Decision now: `{'Proceed with current decision path' if critical_fail_count == 0 else 'Stop/hold and fix measurement + governance gaps first'}`.",
        "",
        "## Explain like I'm 10",
        "- We run a fair game between two teams: `control` and `treatment`.",
        "- If teams were not formed correctly, we cannot say who played better.",
        f"- In this run, we mark the game as `{ab_status or 'missing'}` and only allow safe decisions.",
        f"- If explanation is not grounded in real numbers, we force safe mode (no risky rollout).",
        f"- Final safety light: `{'green' if critical_fail_count == 0 else 'red'}`.",
        "",
        "## 1) Agent Thinking — Doctor",
        "| Check | Status | Severity | Evidence | Notes |",
        "|---|---|---|---|---|",
        row("doctor minimal schema", "schema_doctor_minimal"),
        row("doctor structured reasoning slots", "doctor_structured_reasoning_slots_present"),
        row("hypothesis_portfolio >= 3", "doctor_portfolio_ge3"),
        row("unique_hypotheses >= 2", "doctor_unique_hyp_ge2"),
        row("portfolio_diversity >= 0.5", "doctor_diversity_ge05"),
        row("captain issue evidence density", "captain_issue_evidence_density_present"),
        row("measurement_fix_plan for unobservable", "doctor_fix_plan_when_unobservable"),
        row(">=1 hypothesis tied to flagged metric", "doctor_tied_to_flagged_metric"),
        row("ReAct protocol checks passed", "react_protocol_checks_passed"),
        row("ReAct unobservable decision ceiling", "react_unobservable_doctor_ceiling"),
        "",
        "## 2) Narrative Grounding",
        "| Check | Status | Severity | Evidence | Notes |",
        "|---|---|---|---|---|",
        row(">=3 claims", "narrative_claims_ge3"),
        row("each claim has cause_type", "narrative_claims_have_cause_type"),
        row("each claim has >=2 evidence refs", "narrative_claims_have_refs_ge2"),
        row(">=50% refs linked to actions", "narrative_refs_to_actions_ge05"),
        row("uniqueness (evidence pattern)", "narrative_uniqueness"),
        row("grounded validation", "narrative_grounded"),
        row("if ungrounded => commander <= HOLD_RISK", "ungrounded_requires_commander_hold_risk"),
        "",
        "## 3) Governance Integrity",
        "| Check | Status | Severity | Evidence | Notes |",
        "|---|---|---|---|---|",
        row("governance minimal schema", "schema_governance_minimal"),
        row("approvals exist if proposals exist", "governance_approvals_exist"),
        row("proposal_id deterministic", "governance_proposal_id_deterministic"),
        row("no auto-approve without reason", "governance_no_auto_approve"),
        row("governance_status != missing_review", "governance_status_not_missing_review"),
        "",
        "## 4) Experiment Integrity",
        "| Check | Status | Severity | Evidence | Notes |",
        "|---|---|---|---|---|",
        row("evaluator minimal schema", "schema_evaluator_minimal"),
        row("commander minimal schema", "schema_commander_minimal"),
        row("commander mitigation policy", "commander_mitigation_policy"),
        row("AB status valid", "ab_status_valid"),
        row("assignment signal present", "assignment_signal_present"),
        row("blind spot uplift must be null", "blind_spot_uplift_must_be_null"),
        row("blind spot evaluator guard", "blind_spot_evaluator_guard"),
        row("MBR fatal banner on blind spot", "blind_spot_mbr_fatal_banner"),
        row("run_id consistency across artifacts", "artifact_run_id_consistency"),
        row("experiment_id consistency across artifacts", "artifact_experiment_id_consistency"),
        row("decision_card freshness vs AB artifact", "artifact_freshness_decision_card_vs_ab"),
        row("commander unsafe decision guard", "commander_unsafe_decision"),
        row("methodology mismatch blocked", "methodology_mismatch_blocked"),
        row("UNDERPOWERED handled", "underpowered_handled"),
        row("Goodhart detection active", "goodhart_detection_active"),
        row("commander guardrail status check", "commander_guardrail_status_check_present"),
        row("guardrail breach blocks aggressive decision", "commander_guardrail_breach_blocks_aggressive_decision"),
        row("reasoning confidence dynamic", "reasoning_confidence_dynamic_not_hardcoded"),
        "",
        "## 5) Non-Triviality",
        "| Check | Status | Severity | Evidence | Notes |",
        "|---|---|---|---|---|",
        row("agent eval minimal schema", "schema_agent_eval_minimal"),
        row("adversarial minimal schema", "schema_adversarial_minimal"),
        row("online KPI present", "online_kpi_present"),
        row("real KPI ledger present", "real_kpi_ledger_present"),
        row("KPI outcomes scope", "kpi_outcomes_scope"),
        row("offline KPI freshness", "offline_kpi_freshness"),
        row("scores not all 1.0", "scores_not_all_ones"),
        row("at least one penalty/hold exists", "at_least_one_penalty_or_hold"),
        row("reasoning layer status present", "reasoning_layer_status"),
        row("reasoning checks status present", "reasoning_checks_status"),
        row("trace_completeness_rate", "reasoning_check_trace_completeness_rate"),
        row("alternative_hypothesis_quality", "reasoning_check_alternative_hypothesis_quality"),
        row("falsifiability_specificity", "reasoning_check_falsifiability_specificity"),
        row("decision_change_sensitivity", "reasoning_check_decision_change_sensitivity"),
        row("vector quality signal present", "vector_quality_signal"),
        "",
        "## 6) Safety & Audit",
        "| Check | Status | Severity | Evidence | Notes |",
        "|---|---|---|---|---|",
        row("pre_publish_audit", "pre_publish_audit"),
        row("no secret leakage detected", "no_secret_leakage_detected"),
        row("artifact manifest integrity", "artifact_manifest_integrity"),
        row("artifact manifest scope", "artifact_manifest_scope"),
        row("no runtime DDL detected", "no_runtime_ddl_detected"),
        row("v3 contract set integrity", "v3_contract_set_integrity"),
        row("runtime_limits contract loaded", "runtime_limits_contract_loaded"),
        row("feature_state contract loaded", "feature_state_contract_loaded"),
        row("runtime_guard report PASS", "runtime_guard_report_passed"),
        row("v3 gate results present", "v3_gate_results_present"),
        row("v3 gate results PASS", "v3_gate_results_passed"),
        row("captain gate result", "captain_gate_result"),
        row("v3 gate order", "v3_gate_order"),
        row("context frame contract", "context_frame_contract"),
        row("handoff contract guard", "handoff_contract_guard"),
        row("historical retrieval gate", "historical_retrieval_gate"),
        row("reasoning memory ledger present", "reasoning_memory_ledger_present"),
        row("historical retrieval conformance gate", "historical_retrieval_conformance_gate"),
        row("paired status enum canonical", "paired_status_enum_canonical"),
        row("paired registry contract valid", "paired_registry_contract_valid"),
        row("paired context contract valid", "paired_context_contract_valid"),
        row("stat evidence present when paired COMPLETE", "stat_evidence_present_when_paired_complete"),
        row("paired status lifecycle valid", "paired_status_lifecycle_valid"),
        row("ctrl foundation scope guard", "ctrl_foundation_scope_guard"),
        row("single mode independent from paired", "single_mode_no_paired_artifact_dependency"),
        row("paired partial anti-goodhart policy", "paired_partial_anti_goodhart_expected_outcome"),
        row("paired partial ceiling enforced", "paired_partial_ceiling_enforced"),
        row("anti-goodhart SoT integrity", "anti_goodhart_sot_integrity"),
        row("anti-goodhart SoT consistency", "anti_goodhart_sot_consistency"),
        row("quality invariants gate", "quality_invariants_gate"),
        row("reasoning score policy gate", "reasoning_score_policy_gate"),
        row("governance ceiling gate", "governance_ceiling_gate"),
        row("LLM secure gateway enforced", "llm_secure_gateway_enforced"),
        row("sanitization policy contract", "sanitization_policy_contract"),
        row("sanitization transform contract", "sanitization_transform_contract"),
        row("sanitization map not published", "sanitization_map_not_published"),
        row("sanitization vectorization applied", "sanitization_vectorization_applied"),
        row("response deobfuscation required", "response_deobfuscation_required"),
        row("response deobfuscation applied", "response_deobfuscation_applied"),
        row("map encryption verified", "map_encryption_verified"),
        row("sanitization audit trail", "sanitization_audit_trail"),
        row("reconciliation policy contract", "reconciliation_policy_contract"),
        row("provisional requires reconciliation", "provisional_requires_reconciliation"),
        row("feature_state DISABLED runtime enforcement", "feature_state_runtime_disabled_enforced"),
        row("weak_path requires HOLD_NEED_DATA ceiling", "weak_path_without_ceiling"),
        row("auto decision change forbidden", "auto_decision_change_detected"),
        row("recommended override requires human approval", "recommended_override_requires_human_approval"),
        row("reconciliation stale guard", "reconciliation_stale"),
        row("reconciliation chunk-ref guard", "reconciliation_chunk_ref_guard"),
        row("reconciliation loop guard", "reconciliation_loop_detected"),
        "",
        "## 7) Artifact Presence",
        "| Check | Status | Severity | Evidence | Notes |",
        "|---|---|---|---|---|",
        row("agent value eval JSON exists", "artifact_exists_agent_value_eval_json"),
        row("decision outcomes ledger JSON exists", "artifact_exists_decision_outcomes_ledger_json"),
        row("offline KPI backtest JSON exists", "artifact_exists_offline_kpi_backtest_json"),
        row("approvals JSON exists", "artifact_exists_agent_approvals_json"),
        row("adversarial suite JSON exists", "artifact_exists_adversarial_suite_json"),
        row("AGENT_VALUE_SCORECARD.md exists", "artifact_exists_agent_value_scorecard_md"),
        row("DEMO_INDEX.md exists", "artifact_exists_demo_index_md"),
        row("CAUSAL_EXPLANATION.md exists", "artifact_exists_causal_explanation_md"),
        "",
        "## Critical failures",
    ]
    critical_fails = [k for k, v in checks.items() if v.get("status") == "FAIL" and str(v.get("severity", "")).upper() == "CRITICAL"]
    if critical_fails:
        md_lines.extend([f"- `{k}`: `{checks[k]['reason_code']}` ({checks[k]['evidence_path']})" for k in critical_fails[:5]])
    else:
        md_lines.append("- none")
    md_lines.extend([
        "",
        "## Final Verdict",
        f"- PASS: `{pass_count}`",
        f"- FAIL: `{fail_count}`",
        f"- NA: `{na_count}`",
        f"- Critical FAIL: `{critical_fail_count}`",
        f"- Overall: `{overall}`",
    ])
    out_md = Path(f"reports/L1_ops/{run_id}/ACCEPTANCE_REPORT.md")
    _safe_write_md(out_md, "\n".join(md_lines))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        _redact(
            json.dumps(
                {
                    "run_id": run_id,
                    "overall_status": overall,
                    "counts": payload["counts"],
                    "generated_at": payload["generated_at"],
                },
                ensure_ascii=False,
                indent=2,
            )
        ),
        encoding="utf-8",
    )

    print(f"acceptance {overall}: pass={pass_count} fail={fail_count} na={na_count}")
    if fail_count:
        failed_keys = [k for k, v in checks.items() if v["status"] == "FAIL"]
        print("failed_checks:", ", ".join(failed_keys))
    print(f"json: {out_json}")
    print(f"md:   {out_md}")
    print(f"log:  {log_path}")
    if critical_fail_count > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import sys

        run_id = "unknown"
        if "--run-id" in sys.argv:
            idx = sys.argv.index("--run-id")
            if idx + 1 < len(sys.argv):
                run_id = sys.argv[idx + 1]
        log_path = Path(f"data/logs/verify_acceptance_{run_id}.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(_redact(traceback.format_exc()), encoding="utf-8")
        out_json = Path(f"data/acceptance/{run_id}_acceptance.json")
        out_md = Path(f"reports/L1_ops/{run_id}/ACCEPTANCE_REPORT.md")
        fail_payload = {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_status": "FAIL",
            "counts": {"pass": 0, "fail": 1, "na": 0},
            "checks": {
                "verify_runtime_error": _check(
                    "FAIL",
                    "verify_runtime_error",
                    str(log_path),
                    "see verify log",
                )
            },
            "version": "acceptance_verify.v1",
        }
        _safe_write_json(out_json, fail_payload)
        _safe_write_md(
            out_md,
            "\n".join(
                [
                    f"# ACCEPTANCE REPORT — {run_id}",
                    "",
                    "**Overall Status:** ❌ FAIL",
                    "",
                    "- reason: `verify_runtime_error`",
                    f"- log: `{log_path}`",
                ]
            ),
        )
        print(f"acceptance FAIL: runtime error (see {log_path})")
        raise SystemExit(1)
