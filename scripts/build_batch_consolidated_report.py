#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import verify_sha256_sidecar

NEEDS_DATA = "[Needs Data]"
TRANSPORT_POLICY_PATH = ROOT / "configs/contracts/batch_record_transport_policy_v2.json"
CONSOLIDATED_REPORT_CONTRACT_PATH = ROOT / "configs/contracts/consolidated_report_v1.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _short(text: str, max_len: int = 220) -> str:
    value = " ".join(str(text or "").strip().split())
    if not value:
        return NEEDS_DATA
    if len(value) <= max_len:
        return value
    return value[: max_len - 1].rstrip() + "…"


def _resolve_summary(batch_id: str, summary_path: str) -> Path:
    if summary_path:
        p = Path(summary_path)
        if not p.is_absolute():
            p = ROOT / p
        if not p.exists():
            raise SystemExit(f"Summary file not found: {p}")
        return p
    if not batch_id:
        raise SystemExit("Provide --batch-id or --summary")
    p = ROOT / f"data/batch_eval/{batch_id}_summary.json"
    if not p.exists():
        raise SystemExit(f"Summary file not found: {p}")
    return p


def _load_transport_policy_contract() -> dict[str, Any]:
    if not TRANSPORT_POLICY_PATH.exists():
        raise SystemExit(f"Transport policy contract not found: {TRANSPORT_POLICY_PATH}")
    ok, reason = verify_sha256_sidecar(TRANSPORT_POLICY_PATH, required=True)
    if not ok:
        raise SystemExit(f"Transport policy integrity error: {reason}")
    try:
        payload = json.loads(TRANSPORT_POLICY_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Invalid transport policy JSON: {TRANSPORT_POLICY_PATH}: {exc}") from exc
    policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
    summary_only_target = str(policy.get("summary_source_only", "")).strip()
    if not summary_only_target:
        raise SystemExit("Transport policy invalid: summary_source_only is required")
    return payload


def _load_consolidated_contract() -> dict[str, Any]:
    if not CONSOLIDATED_REPORT_CONTRACT_PATH.exists():
        raise SystemExit(f"Consolidated contract not found: {CONSOLIDATED_REPORT_CONTRACT_PATH}")
    ok, reason = verify_sha256_sidecar(CONSOLIDATED_REPORT_CONTRACT_PATH, required=True)
    if not ok:
        raise SystemExit(f"Consolidated contract integrity error: {reason}")
    try:
        payload = json.loads(CONSOLIDATED_REPORT_CONTRACT_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Invalid consolidated contract JSON: {CONSOLIDATED_REPORT_CONTRACT_PATH}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid consolidated contract payload: {CONSOLIDATED_REPORT_CONTRACT_PATH}")
    return payload


def _chunk(rows: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    n = 5 if size <= 0 else size
    return [rows[i : i + n] for i in range(0, len(rows), n)]


def _decision_bucket(decision: str) -> str:
    d = str(decision or "").upper().strip()
    if d == "GO":
        return "GO"
    if d in {"STOP", "STOP_ROLLOUT"}:
        return "STOP"
    return "HOLD"


def _nested_value(row: dict[str, Any], dotted: str) -> Any:
    cur: Any = row
    for key in str(dotted).split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _format_pct(raw: Any) -> str:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return ""
    value = value * 100.0 if abs(value) <= 1.5 else value
    sign = "+" if value > 0 else ""
    return f"{sign}{value:.2f}%"


def _estimated_metric_impact(row: dict[str, Any]) -> str:
    explicit = str(row.get("estimated_metric_impact") or "").strip()
    if explicit:
        return _short(explicit, 200)
    top_match = row.get("top_match") if isinstance(row.get("top_match"), dict) else {}
    primary = top_match.get("primary_metric_outcome") if isinstance(top_match.get("primary_metric_outcome"), dict) else {}
    breach = top_match.get("guardrail_breach") if isinstance(top_match.get("guardrail_breach"), dict) else {}
    p_metric = str(primary.get("metric_id") or "").strip()
    p_pct = _format_pct(primary.get("delta_pct"))
    g_metric = str(breach.get("metric_id") or "").strip()
    g_pct = _format_pct(breach.get("delta_pct"))
    parts: list[str] = []
    if p_metric and p_pct:
        parts.append(f"{p_pct} {p_metric}")
    if g_metric and g_pct:
        parts.append(f"{g_pct} {g_metric}")
    if parts:
        return _short("; ".join(parts), 200)
    return NEEDS_DATA


def _financial_exposure_risk(row: dict[str, Any]) -> str:
    explicit = str(row.get("financial_exposure_risk") or "").strip()
    if explicit:
        return _short(explicit, 220)
    top_match = row.get("top_match") if isinstance(row.get("top_match"), dict) else {}
    breach = top_match.get("guardrail_breach") if isinstance(top_match.get("guardrail_breach"), dict) else {}
    metric = str(breach.get("metric_id") or "").strip()
    delta = _format_pct(breach.get("delta_pct"))
    if metric and delta:
        return _short(f"Potential guardrail downside: {delta} on {metric}", 220)
    return NEEDS_DATA


def _enrich_record(index: int, row: dict[str, Any]) -> dict[str, Any]:
    run_id = str(row.get("run_id", "")).strip()
    query = str(row.get("query", "")).strip()
    decision = str(row.get("decision", "UNKNOWN")).upper()
    profile = str(row.get("profile", "")).strip()
    executive_summary = str(row.get("executive_summary", "")).strip()

    return {
        "n": index,
        "run_id": run_id or NEEDS_DATA,
        "decision": decision,
        "decision_bucket": _decision_bucket(decision),
        "profile": profile or NEEDS_DATA,
        "query": _short(query, 220),
        "executive_summary": _short(executive_summary, 220),
        "go_no_go_rationale": [str(x) for x in (row.get("go_no_go_rationale") or []) if str(x).strip()],
        "risk_signals": [str(x) for x in (row.get("risk_signals") or []) if str(x).strip()],
        "recommended_actions": [str(x) for x in (row.get("recommended_actions") or []) if str(x).strip()],
        "commander_next_steps": [str(x) for x in (row.get("commander_next_steps") or []) if str(x).strip()],
        "reasoning_observed_facts": [str(x) for x in (row.get("reasoning_observed_facts") or []) if str(x).strip()],
        "reasoning_causal_interpretation": str(row.get("reasoning_causal_interpretation") or "").strip(),
        "reasoning_why_not_opposite_decision": str(row.get("reasoning_why_not_opposite_decision") or "").strip(),
        "reasoning_confidence": row.get("reasoning_confidence") if isinstance(row.get("reasoning_confidence"), dict) else {},
        "reasoning_evidence_quality": row.get("reasoning_evidence_quality")
        if isinstance(row.get("reasoning_evidence_quality"), dict)
        else {},
        "reasoning_decision_tradeoffs": [
            str(x) for x in (row.get("reasoning_decision_tradeoffs") or []) if str(x).strip()
        ],
        "reasoning_mitigations": [str(x) for x in (row.get("reasoning_mitigations") or []) if str(x).strip()],
        "reasoning_uncertainty_gaps": [
            str(x) for x in (row.get("reasoning_uncertainty_gaps") or []) if str(x).strip()
        ],
        "estimated_metric_impact": _estimated_metric_impact(row),
        "financial_exposure_risk": _financial_exposure_risk(row),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build one grouped markdown report for a batch run.")
    parser.add_argument("--batch-id", default="", help="Batch id (expects data/batch_eval/<batch_id>_summary.json)")
    parser.add_argument("--summary", default="", help="Optional explicit summary path")
    parser.add_argument("--group-size", type=int, default=5)
    parser.add_argument("--out", default="", help="Optional output path")
    args = parser.parse_args()
    transport_contract = _load_transport_policy_contract()
    consolidated_contract = _load_consolidated_contract()
    transport_policy = transport_contract.get("policy") if isinstance(transport_contract.get("policy"), dict) else {}

    summary_path = _resolve_summary(args.batch_id, args.summary)
    summary_ok, summary_reason = verify_sha256_sidecar(summary_path, required=True)
    if not summary_ok:
        raise SystemExit(f"Summary integrity error: {summary_reason}")
    summary = _load_json(summary_path)
    if not isinstance(summary, dict):
        raise SystemExit(f"Invalid summary JSON object: {summary_path}")
    source_field = str(summary.get("records_source", "")).strip()
    if source_field and source_field != "summary.records_from_staging":
        raise SystemExit("Policy violation: consolidated report requires summary.records_from_staging source")
    summary_sot = str(summary.get("summary_source_of_truth", "")).strip()
    if summary_sot:
        expected_rel = f"data/batch_eval/{str(summary.get('batch_id') or args.batch_id or '').strip()}_summary.json"
        if summary_sot != expected_rel:
            raise SystemExit("Policy violation: summary_source_of_truth mismatch")
    if str(transport_policy.get("summary_source_only", "")).strip() != "data/batch_eval/<batch_id>_summary.json":
        raise SystemExit("Transport policy violation: summary_source_only must be data/batch_eval/<batch_id>_summary.json")
    if str(summary.get("record_format", "")).strip() and str(summary.get("record_format", "")).strip() != "batch_record_v2":
        raise SystemExit("Consolidated policy violation: summary record_format must be batch_record_v2")

    batch_id = str(summary.get("batch_id") or args.batch_id or "unknown_batch")
    records = summary.get("records", [])
    if not isinstance(records, list):
        records = []

    required_case_fields = consolidated_contract.get("required_case_fields", [])
    if isinstance(required_case_fields, list) and required_case_fields:
        violations: list[str] = []
        for idx, row in enumerate(records, start=1):
            if not isinstance(row, dict):
                violations.append(f"{idx}:record_not_object")
                continue
            missing = [k for k in required_case_fields if k not in row]
            if missing:
                violations.append(f"{idx}:missing={','.join(missing)}")
        if violations:
            raise SystemExit(f"Consolidated contract violation: required_case_fields: {'; '.join(violations[:20])}")

    required_quality = consolidated_contract.get("required_reasoning_quality_fields", [])
    if isinstance(required_quality, list) and required_quality:
        q_violations: list[str] = []
        for idx, row in enumerate(records, start=1):
            if not isinstance(row, dict):
                continue
            for path in required_quality:
                if _nested_value(row, str(path)) is None:
                    q_violations.append(f"{idx}:missing={path}")
        if q_violations:
            raise SystemExit(
                f"Consolidated contract violation: required_reasoning_quality_fields: {'; '.join(q_violations[:20])}"
            )

    enriched: list[dict[str, Any]] = []
    for i, row in enumerate(records, start=1):
        if isinstance(row, dict):
            enriched.append(_enrich_record(i, row))

    out_path = Path(args.out) if args.out else ROOT / f"data/reports/{batch_id}_BATCH_CONSOLIDATED_REPORT.md"
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    lines.append(f"# BATCH CONSOLIDATED REPORT — {batch_id}")
    lines.append("")
    lines.append(f"- Generated at: `{datetime.now(timezone.utc).isoformat()}`")
    lines.append(f"- Source summary: `{summary_path}`")
    lines.append(f"- Dataset: `{summary.get('dataset', 'unknown')}`")
    lines.append("")
    lines.append("## Portfolio Snapshot")
    lines.append(f"- Completed cases: `{summary.get('completed_cases', 0)}`")
    lines.append(f"- Availability KPI: `{summary.get('availability_kpi', NEEDS_DATA)}`")
    lines.append(f"- FPR: `{summary.get('false_positive_rate', NEEDS_DATA)}`")
    lines.append(f"- FNR: `{summary.get('false_negative_rate', NEEDS_DATA)}`")
    lines.append("")
    go_count = sum(1 for r in enriched if r.get("decision") == "GO")
    hold_count = sum(1 for r in enriched if str(r.get("decision", "")).startswith("HOLD"))
    stop_count = sum(1 for r in enriched if r.get("decision") in {"STOP", "STOP_ROLLOUT"})
    lines.append("## Go/No-Go")
    lines.append(f"- GO: `{go_count}`")
    lines.append(f"- HOLD: `{hold_count}`")
    lines.append(f"- STOP: `{stop_count}`")
    lines.append("")

    risk_counter: Counter[str] = Counter()
    mitigation_counter: Counter[str] = Counter()
    for row in enriched:
        risk_counter.update([str(x).strip() for x in row.get("risk_signals", []) if str(x).strip()])
        mitigation_counter.update([str(x).strip() for x in row.get("recommended_actions", []) if str(x).strip()])
        mitigation_counter.update([str(x).strip() for x in row.get("commander_next_steps", []) if str(x).strip()])

    lines.append("## Top Systemic Risks")
    top_risks = risk_counter.most_common(5)
    if not top_risks:
        lines.append(f"- {NEEDS_DATA}")
    else:
        for item, cnt in top_risks:
            lines.append(f"- `{item}` — `{cnt}` cases")
    lines.append("")

    lines.append("## Top Repeated Mitigations")
    top_mitigations = mitigation_counter.most_common(5)
    if not top_mitigations:
        lines.append(f"- {NEEDS_DATA}")
    else:
        for item, cnt in top_mitigations:
            lines.append(f"- `{item}` — `{cnt}` cases")
    lines.append("")

    lines.append("## Consolidated Decisions (Grouped)")
    lines.append("")

    decision_order = consolidated_contract.get("required_decision_group_order", ["GO", "HOLD", "STOP"])
    if not isinstance(decision_order, list) or not decision_order:
        decision_order = ["GO", "HOLD", "STOP"]
    bucket_rows: dict[str, list[dict[str, Any]]] = {"GO": [], "HOLD": [], "STOP": []}
    for row in enriched:
        bucket_rows.setdefault(str(row.get("decision_bucket") or "HOLD"), []).append(row)

    for bucket in [str(x).upper().strip() for x in decision_order]:
        rows_in_bucket = bucket_rows.get(bucket, [])
        lines.append(f"### Decision Group: {bucket}")
        lines.append(f"- Cases: `{len(rows_in_bucket)}`")
        lines.append("")
        for group_idx, chunk_rows in enumerate(_chunk(rows_in_bucket, int(args.group_size)), start=1):
            if not chunk_rows:
                continue
            start_n = chunk_rows[0]["n"]
            end_n = chunk_rows[-1]["n"]
            lines.append(f"#### Subgroup {group_idx} ({start_n}-{end_n})")
            lines.append("")
            for row in chunk_rows:
                lines.append(f"##### {row['n']}. `{row['run_id']}` — **{row['decision']}**")
                lines.append(f"- Hypothesis: {row['query']}")
                lines.append(f"- Executive Summary: {row['executive_summary']}")
                lines.append(f"- Estimated Metric Impact: {row['estimated_metric_impact']}")
                lines.append(f"- Financial Exposure / Risk: {row['financial_exposure_risk']}")
                lines.append(f"- Go/No-Go Rationale: {_short('; '.join(row['go_no_go_rationale']), 320) if row['go_no_go_rationale'] else NEEDS_DATA}")
                lines.append(f"- Risk Signals: {_short('; '.join(row['risk_signals']), 320) if row['risk_signals'] else NEEDS_DATA}")
                lines.append(
                    f"- Mitigations: {_short('; '.join(row['recommended_actions'] + row['commander_next_steps']), 320) if (row['recommended_actions'] or row['commander_next_steps']) else NEEDS_DATA}"
                )
                lines.append(
                    f"- Observed Facts: {_short('; '.join(row['reasoning_observed_facts']), 400) if row['reasoning_observed_facts'] else NEEDS_DATA}"
                )
                lines.append(
                    f"- Causal Interpretation: {row['reasoning_causal_interpretation'] or NEEDS_DATA}"
                )
                lines.append(
                    f"- Why Not Opposite Decision: {row['reasoning_why_not_opposite_decision'] or NEEDS_DATA}"
                )
                conf = row.get("reasoning_confidence") if isinstance(row.get("reasoning_confidence"), dict) else {}
                evq = (
                    row.get("reasoning_evidence_quality")
                    if isinstance(row.get("reasoning_evidence_quality"), dict)
                    else {}
                )
                lines.append(
                    f"- Confidence: score=`{conf.get('score', NEEDS_DATA)}` label=`{conf.get('label', NEEDS_DATA)}` basis={_short('; '.join([str(x) for x in (conf.get('basis') or [])]), 260) if isinstance(conf.get('basis'), list) and conf.get('basis') else NEEDS_DATA}"
                )
                lines.append(
                    f"- Evidence Quality: score=`{evq.get('score', NEEDS_DATA)}` label=`{evq.get('label', NEEDS_DATA)}` missing={_short('; '.join([str(x) for x in (evq.get('missing_evidence') or [])]), 260) if isinstance(evq.get('missing_evidence'), list) and evq.get('missing_evidence') else NEEDS_DATA}"
                )
                lines.append(
                    f"- Decision Tradeoffs: {_short('; '.join(row['reasoning_decision_tradeoffs']), 320) if row['reasoning_decision_tradeoffs'] else NEEDS_DATA}"
                )
                lines.append(
                    f"- Uncertainty Gaps: {_short('; '.join(row['reasoning_uncertainty_gaps']), 320) if row['reasoning_uncertainty_gaps'] else NEEDS_DATA}"
                )
                lines.append("")

    lines.append("## Notes")
    lines.append("- Numeric impacts are shown only when present in source artifacts.")
    lines.append("- Missing quantitative evidence is marked as `[Needs Data]` by design.")
    lines.append("")

    required_sections = consolidated_contract.get("required_sections", [])
    if isinstance(required_sections, list):
        missing_sections = [s for s in required_sections if isinstance(s, str) and f"## {s}" not in lines]
        if missing_sections:
            raise SystemExit(f"Consolidated contract violation: missing_sections={','.join(missing_sections)}")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"ok: consolidated report written {out_path}")


if __name__ == "__main__":
    main()
