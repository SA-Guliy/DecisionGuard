#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.architecture_v3 import load_json_with_integrity, paired_experiment_context_path, stat_evidence_bundle_path
from src.security_utils import write_sha256_sidecar

_TOKEN_RE = re.compile(r"[a-zA-Z0-9_]{2,}")
_SIGNIFICANT_VERDICTS = {"POSITIVE_SIGNIFICANT", "NEGATIVE_SIGNIFICANT"}


def _to_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _write_json_with_sidecar(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(path)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(str(text or ""))]


def _normalize(vec: list[float]) -> list[float]:
    norm = math.sqrt(sum(v * v for v in vec))
    if norm <= 0.0:
        return [0.0 for _ in vec]
    return [v / norm for v in vec]


def _vectorize(text: str, vocab: list[str]) -> list[float]:
    tf: dict[str, float] = {}
    for token in _tokenize(text):
        tf[token] = tf.get(token, 0.0) + 1.0
    return _normalize([tf.get(term, 0.0) for term in vocab])


def _history_doc_text(report: dict[str, Any]) -> str:
    primary = report.get("primary_metric_outcome", {}) if isinstance(report.get("primary_metric_outcome"), dict) else {}
    guardrail = report.get("guardrail_breach", {}) if isinstance(report.get("guardrail_breach"), dict) else {}
    reasoning = report.get("reasoning_decision", {}) if isinstance(report.get("reasoning_decision"), dict) else {}
    pieces = [
        str(report.get("hypothesis", "")).strip(),
        str(primary.get("metric_id", "")).strip(),
        str(primary.get("interpretation", "")).strip(),
        str(guardrail.get("metric_id", "")).strip(),
        str(guardrail.get("breach_reason", "")).strip(),
        str(reasoning.get("decision", "")).strip(),
        str(reasoning.get("analyst_summary", "")).strip(),
    ]
    return " ".join([p for p in pieces if p])


def _rebuild_vector_index(reports: list[dict[str, Any]]) -> dict[str, Any]:
    docs: list[tuple[str, str]] = []
    vocab_set: set[str] = set()
    for row in reports:
        if not isinstance(row, dict):
            continue
        experiment_id = str(row.get("experiment_id", "")).strip()
        if not experiment_id:
            continue
        doc_text = _history_doc_text(row)
        docs.append((experiment_id, doc_text))
        vocab_set.update(_tokenize(doc_text))
    vocab = sorted(vocab_set)
    vectors = [{"experiment_id": exp_id, "vector": _vectorize(text, vocab)} for exp_id, text in docs]
    return {
        "version": "history_vector_index_v1",
        "generated_at": _now_iso(),
        "vocab": vocab,
        "vectors": vectors,
    }


def _resolve_primary_metric_hint(doctor: dict[str, Any], commander: dict[str, Any]) -> str:
    experiment_header = doctor.get("experiment_header", {}) if isinstance(doctor.get("experiment_header"), dict) else {}
    hint = str(experiment_header.get("ab_primary_metric", "")).strip()
    if hint:
        return hint
    goals = commander.get("goals", [])
    if isinstance(goals, list) and goals:
        first_goal = goals[0]
        if isinstance(first_goal, dict):
            hint = str(first_goal.get("primary_metric", "")).strip()
            if hint:
                return hint
    return ""


def _pick_primary_metric_row(stat_bundle: dict[str, Any], metric_hint: str) -> dict[str, Any] | None:
    rows = stat_bundle.get("metrics", []) if isinstance(stat_bundle.get("metrics"), list) else []
    if not rows:
        return None
    hint = str(metric_hint or "").strip()
    if hint:
        for row in rows:
            if isinstance(row, dict) and str(row.get("metric_id", "")).strip() == hint:
                return row
    for row in rows:
        if isinstance(row, dict) and str(row.get("metric_type", "")).strip().lower() == "continuous":
            return row
    for row in rows:
        if isinstance(row, dict):
            return row
    return None


def _pick_guardrail_breach(stat_bundle: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    checks = stat_bundle.get("guardrail_status_check", []) if isinstance(stat_bundle.get("guardrail_status_check"), list) else []
    metrics = stat_bundle.get("metrics", []) if isinstance(stat_bundle.get("metrics"), list) else []
    metric_by_id: dict[str, dict[str, Any]] = {}
    for row in metrics:
        if isinstance(row, dict):
            metric_id = str(row.get("metric_id", "")).strip()
            if metric_id:
                metric_by_id[metric_id] = row
    for row in checks:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status", "")).strip().upper()
        if status == "BREACH":
            metric_id = str(row.get("metric_id", "")).strip()
            return metric_by_id.get(metric_id), "guardrail_threshold_breach"
    for row in checks:
        if not isinstance(row, dict):
            continue
        if str(row.get("status", "")).strip().upper() == "NO_DATA":
            metric_id = str(row.get("metric_id", "")).strip()
            return metric_by_id.get(metric_id), "guardrail_no_data"
    return None, "no_guardrail_breach_detected"


def _build_history_entry(
    *,
    run_id: str,
    paired_context: dict[str, Any],
    doctor: dict[str, Any],
    commander: dict[str, Any],
    stat_bundle: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    metric_hint = _resolve_primary_metric_hint(doctor, commander)
    primary_row = _pick_primary_metric_row(stat_bundle, metric_hint)
    if not isinstance(primary_row, dict):
        return None, "primary_metric_missing_in_stat_bundle"
    verdict = str(primary_row.get("verdict", "")).strip().upper()
    if verdict not in _SIGNIFICANT_VERDICTS:
        return None, "primary_metric_not_significant"

    metric_id = str(primary_row.get("metric_id", "")).strip() or (metric_hint or "unknown_metric")
    ctrl = _to_float(primary_row.get("ctrl_value"))
    trt = _to_float(primary_row.get("trt_value"))
    delta_pct = None
    if ctrl is not None and trt is not None and abs(ctrl) > 1e-9:
        delta_pct = (trt - ctrl) / abs(ctrl)
    p_value = _to_float(primary_row.get("p_value"))

    hypothesis = ""
    portfolio = doctor.get("hypothesis_portfolio", [])
    if isinstance(portfolio, list) and portfolio:
        first = portfolio[0]
        if isinstance(first, dict):
            hypothesis = (
                str(first.get("hypothesis", "")).strip()
                or str(first.get("title", "")).strip()
                or str(first.get("hypothesis_statement", "")).strip()
                or str(first.get("message", "")).strip()
            )
    if not hypothesis:
        hypothesis = str((doctor.get("executive_summary") or {}).get("headline", "")).strip()
    if not hypothesis:
        hypothesis = f"run {run_id} auto-captured hypothesis"

    guardrail_row, guardrail_reason = _pick_guardrail_breach(stat_bundle)
    guardrail_metric = str((guardrail_row or {}).get("metric_id", "")).strip() if isinstance(guardrail_row, dict) else "none"
    guardrail_ctrl = _to_float((guardrail_row or {}).get("ctrl_value")) if isinstance(guardrail_row, dict) else None
    guardrail_trt = _to_float((guardrail_row or {}).get("trt_value")) if isinstance(guardrail_row, dict) else None
    guardrail_delta_pct = None
    if guardrail_ctrl is not None and guardrail_trt is not None and abs(guardrail_ctrl) > 1e-9:
        guardrail_delta_pct = (guardrail_trt - guardrail_ctrl) / abs(guardrail_ctrl)

    decision = str(commander.get("normalized_decision", commander.get("decision", ""))).strip().upper() or "HOLD_NEED_DATA"
    analyst_summary = (
        str((commander.get("executive_summary") or {}).get("headline", "")).strip()
        or str((doctor.get("executive_summary") or {}).get("headline", "")).strip()
        or f"Primary verdict {verdict} on {metric_id}; decision {decision}."
    )

    entry = {
        "experiment_id": str(paired_context.get("experiment_id", "")).strip() or f"exp::{run_id}",
        "hypothesis": hypothesis,
        "primary_metric_outcome": {
            "metric_id": metric_id,
            "control": ctrl,
            "treatment": trt,
            "delta_pct": delta_pct,
            "interpretation": (
                "Primary metric improved with statistical significance"
                if verdict == "POSITIVE_SIGNIFICANT"
                else "Primary metric degraded with statistical significance"
            ),
            "p_value": p_value,
            "stat_verdict": verdict,
        },
        "guardrail_breach": {
            "metric_id": guardrail_metric,
            "control": guardrail_ctrl,
            "treatment": guardrail_trt,
            "delta_pct": guardrail_delta_pct,
            "breach_reason": guardrail_reason,
        },
        "reasoning_decision": {
            "decision": decision,
            "analyst_summary": analyst_summary,
        },
    }
    return entry, "updated"


def _upsert_report(reports: list[dict[str, Any]], new_entry: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    exp_id = str(new_entry.get("experiment_id", "")).strip()
    if not exp_id:
        return reports, "skip_invalid_experiment_id"
    out: list[dict[str, Any]] = []
    replaced = False
    for row in reports:
        if not isinstance(row, dict):
            continue
        if str(row.get("experiment_id", "")).strip() == exp_id:
            out.append(new_entry)
            replaced = True
        else:
            out.append(row)
    if not replaced:
        out.append(new_entry)
    return out, ("replaced" if replaced else "appended")


def _write_audit(path: Path, payload: dict[str, Any]) -> None:
    _write_json_with_sidecar(path, payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Update history corpus from paired COMPLETE statistical evidence")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--paired-context-path", default="")
    parser.add_argument("--stat-evidence-path", default="")
    parser.add_argument("--doctor-path", default="")
    parser.add_argument("--commander-path", default="")
    parser.add_argument("--sot-path", default="data/poc/history_sot_v1.json")
    parser.add_argument("--index-path", default="data/poc/history_vector_index_v1.json")
    parser.add_argument("--audit-path", default="")
    args = parser.parse_args()

    run_id = str(args.run_id).strip()
    if not run_id:
        raise SystemExit("run_id is required")

    paired_context_p = Path(args.paired_context_path) if str(args.paired_context_path).strip() else paired_experiment_context_path(run_id)
    stat_bundle_p = Path(args.stat_evidence_path) if str(args.stat_evidence_path).strip() else stat_evidence_bundle_path(run_id)
    doctor_p = Path(args.doctor_path) if str(args.doctor_path).strip() else Path(f"data/agent_reports/{run_id}_doctor_variance.json")
    commander_p = Path(args.commander_path) if str(args.commander_path).strip() else Path(f"data/agent_reports/{run_id}_commander_priority.json")
    sot_p = Path(args.sot_path)
    index_p = Path(args.index_path)
    audit_p = Path(args.audit_path) if str(args.audit_path).strip() else Path(f"data/agent_quality/{run_id}_history_corpus_update.json")

    audit_payload: dict[str, Any] = {
        "version": "history_corpus_update_v1",
        "run_id": run_id,
        "generated_at": _now_iso(),
        "status": "FAIL",
        "error_code": "METHODOLOGY_INVARIANT_BROKEN",
        "details": {},
    }

    try:
        paired_context = load_json_with_integrity(paired_context_p)
        paired_status = str(paired_context.get("paired_status", "")).strip().upper()
        if paired_status != "COMPLETE":
            audit_payload["status"] = "SKIP"
            audit_payload["error_code"] = "NONE"
            audit_payload["details"] = {"reason": "paired_status_not_complete", "paired_status": paired_status}
            _write_audit(audit_p, audit_payload)
            print(f"[skip] history corpus update: paired_status={paired_status or 'unknown'}")
            return

        stat_bundle = load_json_with_integrity(stat_bundle_p)
        doctor = load_json_with_integrity(doctor_p)
        commander = load_json_with_integrity(commander_p)
        history_sot = load_json_with_integrity(sot_p)

        reports = history_sot.get("reports", [])
        if not isinstance(reports, list):
            raise RuntimeError("history_sot_reports_not_array")

        new_entry, update_reason = _build_history_entry(
            run_id=run_id,
            paired_context=paired_context,
            doctor=doctor,
            commander=commander,
            stat_bundle=stat_bundle,
        )
        if new_entry is None:
            audit_payload["status"] = "SKIP"
            audit_payload["error_code"] = "NONE"
            audit_payload["details"] = {"reason": update_reason}
            _write_audit(audit_p, audit_payload)
            print(f"[skip] history corpus update: {update_reason}")
            return

        reports_updated, op = _upsert_report([row for row in reports if isinstance(row, dict)], new_entry)
        history_out = {
            "version": "history_sot_v1",
            "generated_at": _now_iso(),
            "reports": reports_updated,
        }
        index_out = _rebuild_vector_index(reports_updated)
        _write_json_with_sidecar(sot_p, history_out)
        _write_json_with_sidecar(index_p, index_out)

        audit_payload["status"] = "PASS"
        audit_payload["error_code"] = "NONE"
        audit_payload["details"] = {
            "operation": op,
            "reason": update_reason,
            "experiment_id": new_entry.get("experiment_id"),
            "reports_count": len(reports_updated),
            "vocab_size": len(index_out.get("vocab", [])),
            "vector_rows": len(index_out.get("vectors", [])),
        }
        _write_audit(audit_p, audit_payload)
        print(f"[ok] history corpus updated run_id={run_id} operation={op} reports={len(reports_updated)}")
    except Exception as exc:
        audit_payload["status"] = "FAIL"
        audit_payload["error_code"] = "METHODOLOGY_INVARIANT_BROKEN"
        audit_payload["details"] = {"error": str(exc)}
        _write_audit(audit_p, audit_payload)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

