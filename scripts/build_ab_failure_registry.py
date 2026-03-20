#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


FAIL_STATUSES = {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "INVALID", "INVALID_METHODS"}


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _safe_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _safe_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _run_family(run_id: str) -> str:
    parts = [p for p in str(run_id).split("_") if p]
    if len(parts) >= 3:
        return "_".join(parts[:3])
    if len(parts) >= 2:
        return "_".join(parts[:2])
    return str(run_id)


def _derive_failure_meta(status: str, notes: list[str], errors: list[str]) -> dict[str, str]:
    status_u = str(status or "").upper()
    notes_l = " | ".join(str(n) for n in notes).lower()
    errors_l = " | ".join(str(e) for e in errors).lower()
    pipeline_status = "FAIL" if status_u in FAIL_STATUSES else "PASS"
    if status_u == "METHODOLOGY_MISMATCH":
        if "customer_join" in notes_l:
            return {
                "pipeline_status": pipeline_status,
                "error_family": "DATA_JOIN",
                "error_code": "DATA_JOIN_CUSTOMER_GRAIN_UNAVAILABLE",
            }
        return {"pipeline_status": pipeline_status, "error_family": "METHOD", "error_code": "METHOD_ANALYSIS_UNIT_MISMATCH"}
    if status_u == "MISSING_ASSIGNMENT":
        if "missing_experiment_id" in notes_l:
            return {"pipeline_status": pipeline_status, "error_family": "CONTRACT", "error_code": "CONTRACT_EXPERIMENT_ID_MISSING"}
        if "customer_join_error:" in notes_l or "customer_join_unavailable_fallback_store" in notes_l:
            return {
                "pipeline_status": pipeline_status,
                "error_family": "DATA_JOIN",
                "error_code": "DATA_JOIN_CUSTOMER_GRAIN_UNAVAILABLE",
            }
        if "orders_have_experiment_but_assignment_log_empty" in errors_l:
            return {
                "pipeline_status": pipeline_status,
                "error_family": "DATA_CONTRACT",
                "error_code": "DATA_ASSIGNMENT_LOG_EMPTY_WITH_EXPERIMENT_ROWS",
            }
        if "assignment_recovery_failed" in notes_l:
            return {"pipeline_status": pipeline_status, "error_family": "DATA_ASSIGNMENT", "error_code": "DATA_ASSIGNMENT_RECOVERY_FAILED"}
        return {"pipeline_status": pipeline_status, "error_family": "DATA_ASSIGNMENT", "error_code": "DATA_ASSIGNMENT_MISSING"}
    if status_u == "INVALID_METHODS":
        return {"pipeline_status": pipeline_status, "error_family": "STATS", "error_code": "STATS_METHOD_INCONSISTENCY"}
    if status_u == "UNDERPOWERED":
        return {"pipeline_status": pipeline_status, "error_family": "STATS", "error_code": "STATS_UNDERPOWERED"}
    if status_u == "INCONCLUSIVE":
        return {"pipeline_status": pipeline_status, "error_family": "STATS", "error_code": "STATS_INCONCLUSIVE"}
    if status_u == "HOLD_RISK":
        return {"pipeline_status": pipeline_status, "error_family": "RISK", "error_code": "RISK_GUARDRAIL_OR_SRM_WARN"}
    return {"pipeline_status": pipeline_status, "error_family": "NONE", "error_code": "NONE"}


def _counter_to_rows(counter: Counter[tuple[str, ...]] | Counter[str], *, top_n: int | None = None) -> list[dict[str, Any]]:
    items = counter.most_common(top_n)
    rows: list[dict[str, Any]] = []
    for key, count in items:
        if isinstance(key, tuple):
            row = {f"k{i+1}": v for i, v in enumerate(key)}
            row["count"] = count
        else:
            row = {"key": key, "count": count}
        rows.append(row)
    return rows


def _fmt_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Build AB failure registry across all AB artifacts")
    parser.add_argument("--ab-dir", default="data/ab_reports")
    parser.add_argument("--out-json", default="data/diagnostics/ab_failure_registry.json")
    parser.add_argument("--out-md", default="reports/L1_ops/AB_FAILURE_REGISTRY.md")
    parser.add_argument("--top-n", type=int, default=20)
    args = parser.parse_args()

    ab_dir = Path(args.ab_dir)
    files = sorted(p for p in ab_dir.glob("*_ab.json") if not p.name.endswith("_ab_v2.json"))

    status_counts: Counter[str] = Counter()
    pipeline_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    code_counts: Counter[str] = Counter()
    by_unit_status: Counter[tuple[str, str]] = Counter()
    by_metric_status: Counter[tuple[str, str]] = Counter()
    by_run_family_status: Counter[tuple[str, str]] = Counter()
    note_counts: Counter[str] = Counter()
    raw_error_counts: Counter[str] = Counter()
    methodology_note_counts: Counter[str] = Counter()
    methodology_unit_counts: Counter[str] = Counter()

    rows_payload: list[dict[str, Any]] = []

    for p in files:
        payload = _load_json(p)
        if not isinstance(payload, dict):
            continue
        status = str(payload.get("status", "MISSING")).upper()
        run_id = str(payload.get("run_id", "unknown"))
        unit_type = str(payload.get("unit_type", "unknown")).lower()
        summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
        primary_metric = str(summary.get("primary_metric", "unknown")).lower()
        notes = payload.get("notes", []) if isinstance(payload.get("notes"), list) else []
        errors = payload.get("errors", []) if isinstance(payload.get("errors"), list) else []
        fm = payload.get("failure_meta", {}) if isinstance(payload.get("failure_meta"), dict) else {}
        if not fm:
            fm = _derive_failure_meta(status=status, notes=notes, errors=errors)
        pipeline_status = str(fm.get("pipeline_status", "PASS")).upper()
        error_family = str(fm.get("error_family", "NONE")).upper()
        error_code = str(fm.get("error_code", "NONE")).upper()

        status_counts[status] += 1
        pipeline_counts[pipeline_status] += 1
        family_counts[error_family] += 1
        code_counts[error_code] += 1
        by_unit_status[(unit_type, status)] += 1
        by_metric_status[(primary_metric, status)] += 1
        by_run_family_status[(_run_family(run_id), status)] += 1

        for n in notes:
            note = str(n).strip()
            if note:
                note_counts[note] += 1
                if status == "METHODOLOGY_MISMATCH":
                    methodology_note_counts[note] += 1
        for e in errors:
            err = str(e).strip()
            if err:
                raw_error_counts[err] += 1
        if status == "METHODOLOGY_MISMATCH":
            methodology_unit_counts[unit_type] += 1

        rows_payload.append(
            {
                "artifact": p.name,
                "run_id": run_id,
                "run_family": _run_family(run_id),
                "experiment_id": str(payload.get("experiment_id", "")),
                "unit_type": unit_type,
                "status": status,
                "pipeline_status": pipeline_status,
                "error_family": error_family,
                "error_code": error_code,
                "primary_metric": primary_metric,
                "notes": [str(x) for x in notes][:20],
                "errors": [str(x) for x in errors][:20],
            }
        )

    total = len(rows_payload)
    fail_total = sum(1 for r in rows_payload if r["pipeline_status"] == "FAIL")
    pass_total = total - fail_total

    result = {
        "generated_from": str(ab_dir),
        "total_ab_artifacts": total,
        "overview": {
            "pipeline_pass": pass_total,
            "pipeline_fail": fail_total,
            "fail_rate": (fail_total / total) if total else 0.0,
        },
        "blocks": {
            "status_counts": [{"status": k, "count": v} for k, v in status_counts.most_common()],
            "error_family_counts": [{"error_family": k, "count": v} for k, v in family_counts.most_common()],
            "error_code_counts": [{"error_code": k, "count": v} for k, v in code_counts.most_common()],
            "by_unit_status": [
                {"unit_type": unit, "status": status, "count": count}
                for (unit, status), count in by_unit_status.most_common()
            ],
            "by_primary_metric_status": [
                {"primary_metric": metric, "status": status, "count": count}
                for (metric, status), count in by_metric_status.most_common()
            ],
            "by_run_family_status": [
                {"run_family": fam, "status": status, "count": count}
                for (fam, status), count in by_run_family_status.most_common()
            ],
            "top_notes": [{"note": k, "count": v} for k, v in note_counts.most_common(args.top_n)],
            "top_errors": [{"error": k, "count": v} for k, v in raw_error_counts.most_common(args.top_n)],
        },
        "methodology_mismatch_breakdown": {
            "total": int(status_counts.get("METHODOLOGY_MISMATCH", 0)),
            "by_unit_type": [{"unit_type": k, "count": v} for k, v in methodology_unit_counts.most_common()],
            "top_notes": [{"note": k, "count": v} for k, v in methodology_note_counts.most_common(args.top_n)],
        },
        "rows": rows_payload,
    }

    _safe_write_json(Path(args.out_json), result)

    md: list[str] = []
    md.append("# AB Failure Registry")
    md.append("")
    md.append("This report aggregates AB artifacts and shows failure patterns by block (status/family/code/unit/metric).")
    md.append("")
    md.extend(
        _fmt_table(
            ["Metric", "Value"],
            [
                ["Total AB artifacts", str(total)],
                ["Pipeline FAIL", str(fail_total)],
                ["Pipeline PASS", str(pass_total)],
                ["Fail rate", f"{((fail_total / total) * 100) if total else 0:.2f}%"],
            ],
        )
    )
    md.append("")

    md.append("## Block A — Status Counts")
    md.append("")
    md.extend(_fmt_table(["Status", "Count"], [[k, str(v)] for k, v in status_counts.most_common()]))
    md.append("")

    md.append("## Block B — Error Families and Codes")
    md.append("")
    md.append("### Error Families")
    md.append("")
    md.extend(_fmt_table(["Error Family", "Count"], [[k, str(v)] for k, v in family_counts.most_common()]))
    md.append("")
    md.append("### Error Codes")
    md.append("")
    md.extend(_fmt_table(["Error Code", "Count"], [[k, str(v)] for k, v in code_counts.most_common(args.top_n)]))
    md.append("")

    md.append("## Block C — Where Failures Happen (Unit / Metric / Run Family)")
    md.append("")
    md.append("### By Unit + Status (useful for customer-vs-store AB issues)")
    md.append("")
    md.extend(
        _fmt_table(
            ["Unit Type", "Status", "Count"],
            [[unit, status, str(count)] for (unit, status), count in by_unit_status.most_common(args.top_n)],
        )
    )
    md.append("")
    md.append("### By Primary Metric + Status")
    md.append("")
    md.extend(
        _fmt_table(
            ["Primary Metric", "Status", "Count"],
            [[metric, status, str(count)] for (metric, status), count in by_metric_status.most_common(args.top_n)],
        )
    )
    md.append("")
    md.append("### By Run Family + Status (pattern spotting across phases)")
    md.append("")
    md.extend(
        _fmt_table(
            ["Run Family", "Status", "Count"],
            [[fam, status, str(count)] for (fam, status), count in by_run_family_status.most_common(args.top_n)],
        )
    )
    md.append("")

    md.append("## Block D — METHODOLOGY_MISMATCH Breakdown")
    md.append("")
    md.append(f"- total: `{int(status_counts.get('METHODOLOGY_MISMATCH', 0))}`")
    md.append("")
    md.append("### Top Notes (root-cause signals)")
    md.append("")
    md.extend(_fmt_table(["Note", "Count"], [[k, str(v)] for k, v in methodology_note_counts.most_common(args.top_n)]))
    md.append("")

    md.append("## Block E — Frequent Notes / Raw Errors")
    md.append("")
    md.append("### Top Notes")
    md.append("")
    md.extend(_fmt_table(["Note", "Count"], [[k, str(v)] for k, v in note_counts.most_common(args.top_n)]))
    md.append("")
    md.append("### Top Raw Errors")
    md.append("")
    md.extend(_fmt_table(["Error", "Count"], [[k, str(v)] for k, v in raw_error_counts.most_common(args.top_n)]))
    md.append("")

    _safe_write(Path(args.out_md), "\n".join(md))
    print(f"ok: ab failure registry written ({total} artifacts)")


if __name__ == "__main__":
    main()
