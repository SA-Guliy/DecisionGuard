#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar


SOURCE_PRIORITY = {
    "availability": [
        "batch_summary.availability_kpi",
        "derived:completed_cases/(total_cases OR completed+failed+failed_api)",
    ],
    "quality_rates": [
        "batch_summary.false_positive_rate/false_negative_rate",
        "derived:records(expected_block,predicted_block,status!=FAILED*)",
    ],
    "cost_usd": [
        "batch_summary.total_cost_usd_estimate",
        "sum(batch_summary.records[].cost_usd_estimate)",
        "sum(data/cost/*_cost_ledger.json.usd_estimate scoped by run_id)",
    ],
    "reconciliation": [
        "agent_reports.reconciliation.decision_match",
        "data/reconciliation/reconciliation_events.jsonl",
        "data/reconciliation/reconciliation_accuracy_summary.json",
    ],
}


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return int(default)


def _pct(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value * 100:.2f}%"


def _usd(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"${value:.6f}"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_json_with_integrity(path: Path, *, integrity_required: bool) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"Missing artifact: {path}")
    ok, reason = verify_sha256_sidecar(path, required=integrity_required)
    if not ok:
        raise SystemExit(f"Integrity check failed for {path}: {reason}")
    try:
        payload = _load_json(path)
    except Exception as exc:
        raise SystemExit(f"Invalid JSON artifact {path}: {exc}")
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid JSON object artifact (expected dict): {path}")
    return payload


def _latest_file(pattern: str) -> Path | None:
    files = sorted(ROOT.glob(pattern), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def _glob_paths(pattern: str) -> list[Path]:
    raw = str(pattern or "").strip()
    if not raw:
        return []
    p = Path(raw)
    if p.is_absolute():
        return sorted((Path(x) for x in glob.glob(raw, recursive=True) if Path(x).is_file()), key=lambda x: str(x))
    return sorted((x for x in ROOT.glob(raw) if x.is_file()), key=lambda x: str(x))


def _resolve_batch_summary_path(batch_summary: str, batch_id: str) -> Path:
    if batch_summary:
        path = Path(batch_summary)
        if not path.is_absolute():
            path = ROOT / path
        if not path.exists():
            raise SystemExit(f"Batch summary not found: {path}")
        return path
    if batch_id:
        candidate = ROOT / f"data/batch_eval/{batch_id}_summary.json"
        if candidate.exists():
            return candidate
        raise SystemExit(f"Batch summary for batch_id not found: {candidate}")
    path = _latest_file("data/batch_eval/*_summary.json")
    if path is None:
        raise SystemExit("No batch summary found under data/batch_eval/")
    return path


def _run_id_from_cost_ledger(path: Path) -> str:
    name = path.name
    suffix = "_cost_ledger.json"
    return name[: -len(suffix)] if name.endswith(suffix) else path.stem


def _select_priority_metric(candidates: list[tuple[str, Any, bool]], *, default: Any = None) -> tuple[Any, str]:
    for source, value, available in candidates:
        if available:
            return value, source
    return default, "unavailable"


def _compute_rates_from_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    risky_total = 0
    safe_total = 0
    false_negative_count = 0
    false_positive_count = 0

    for row in records:
        if str(row.get("status", "")).upper().startswith("FAILED"):
            continue
        expected_block = bool(row.get("expected_block"))
        if "predicted_block" in row:
            predicted_block = bool(row.get("predicted_block"))
        else:
            decision = str(row.get("decision", "HOLD_NEED_DATA")).upper()
            predicted_block = decision != "GO"

        if expected_block:
            risky_total += 1
            if not predicted_block:
                false_negative_count += 1
        else:
            safe_total += 1
            if predicted_block:
                false_positive_count += 1

    fnr = (false_negative_count / risky_total) if risky_total > 0 else None
    fpr = (false_positive_count / safe_total) if safe_total > 0 else None
    prevented_bad_decisions = max(0, risky_total - false_negative_count)
    return {
        "risky_total": risky_total,
        "safe_total": safe_total,
        "false_negative_count": false_negative_count,
        "false_positive_count": false_positive_count,
        "false_negative_rate": fnr,
        "false_positive_rate": fpr,
        "prevented_bad_decisions": prevented_bad_decisions,
    }


def _collect_reconciliation_stats(
    run_ids: set[str],
    agent_report_glob: str,
    reconciliation_events_path: Path,
    reconciliation_summary_path: Path,
    *,
    integrity_required: bool,
) -> dict[str, Any]:
    reports = _glob_paths(agent_report_glob)

    scoped_runs = 0
    provisional_runs = 0
    needs_reconciliation_runs = 0
    fallback_agent_hits = {"captain": 0, "doctor": 0, "commander": 0}
    match_flags: list[bool] = []
    report_level_match_by_run: dict[str, bool] = {}
    report_summary_candidate: tuple[int, int] | None = None
    match_source = "agent_reports.reconciliation.decision_match"

    for path in reports:
        run_id = path.name.replace("_poc_sprint2.json", "")
        if run_ids and run_id not in run_ids:
            continue

        scoped_runs += 1
        payload = _load_json_with_integrity(path, integrity_required=integrity_required)

        runtime_flags = payload.get("runtime_flags", {}) if isinstance(payload.get("runtime_flags"), dict) else {}
        fallback_agents = runtime_flags.get("fallback_agents", []) if isinstance(runtime_flags.get("fallback_agents"), list) else []

        provisional_local = bool(runtime_flags.get("provisional_local_fallback", False))
        needs_reconciliation = bool(
            payload.get("needs_cloud_reconciliation", False)
            or runtime_flags.get("needs_cloud_reconciliation", False)
        )

        if provisional_local:
            provisional_runs += 1
        if needs_reconciliation:
            needs_reconciliation_runs += 1

        for agent in fallback_agents:
            key = str(agent).strip().lower()
            if key in fallback_agent_hits:
                fallback_agent_hits[key] += 1

        reconciliation = payload.get("reconciliation", {})
        if isinstance(reconciliation, dict) and isinstance(reconciliation.get("decision_match"), bool):
            report_level_match_by_run[run_id] = bool(reconciliation.get("decision_match"))

        recon_summary = payload.get("reconciliation_accuracy_summary", {})
        if run_id not in report_level_match_by_run and isinstance(recon_summary, dict) and isinstance(
            recon_summary.get("match_rate"), (int, float)
        ):
            total = _safe_int(recon_summary.get("total_events"), 0)
            matched = _safe_int(recon_summary.get("matched_events"), 0)
            if total > 0:
                if report_summary_candidate is None or total > report_summary_candidate[0]:
                    report_summary_candidate = (total, matched)

    if report_level_match_by_run:
        match_source = "agent_reports.reconciliation.decision_match"
        match_flags.extend(report_level_match_by_run.values())
    elif report_summary_candidate is not None:
        match_source = "agent_reports.reconciliation_accuracy_summary"
        total, matched = report_summary_candidate
        match_flags.extend([True] * matched + [False] * max(0, total - matched))

    if not match_flags and reconciliation_events_path.exists():
        match_source = "reconciliation_events.jsonl"
        ok, reason = verify_sha256_sidecar(reconciliation_events_path, required=integrity_required)
        if not ok:
            raise SystemExit(f"Integrity check failed for {reconciliation_events_path}: {reason}")
        try:
            for raw in reconciliation_events_path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line:
                    continue
                row = json.loads(line)
                rid = str(row.get("run_id", "")).strip()
                if run_ids and rid and rid not in run_ids:
                    continue
                if isinstance(row.get("decision_match"), bool):
                    match_flags.append(bool(row.get("decision_match")))
        except Exception as exc:
            raise SystemExit(f"Invalid reconciliation events artifact {reconciliation_events_path}: {exc}")

    if not match_flags and reconciliation_summary_path.exists():
        match_source = "reconciliation_accuracy_summary.json"
        summary = _load_json_with_integrity(reconciliation_summary_path, integrity_required=integrity_required)
        total = _safe_int(summary.get("total_events"), 0)
        matched = _safe_int(summary.get("matched_events"), 0)
        if total > 0:
            match_flags.extend([True] * matched + [False] * max(0, total - matched))

    compared = len(match_flags)
    matched = len([x for x in match_flags if x])
    match_rate = (matched / compared) if compared > 0 else None

    return {
        "scoped_runs": scoped_runs,
        "provisional_runs": provisional_runs,
        "needs_reconciliation_runs": needs_reconciliation_runs,
        "fallback_agent_hits": fallback_agent_hits,
        "reconciliation_compared": compared,
        "reconciliation_matched": matched,
        "reconciliation_match_rate": match_rate,
        "reconciliation_match_source": match_source,
    }


def _build_go_no_go_checks(
    *,
    availability: float | None,
    fnr: float | None,
    fpr: float | None,
    risky_total: int,
    safe_total: int,
    needs_reconciliation_runs: int,
    reconciliation_match_rate: float | None,
    threshold_availability: float,
    threshold_fnr: float,
    threshold_fpr: float,
    threshold_reconciliation_match: float,
) -> list[tuple[str, str, str]]:
    checks: list[tuple[str, str, str]] = []

    availability_ok = availability is not None and availability >= threshold_availability
    checks.append(
        (
            "Availability",
            "PASS" if availability_ok else "FAIL",
            f"value={_pct(availability)} threshold>={_pct(threshold_availability)}",
        )
    )

    if risky_total > 0:
        fnr_ok = fnr is not None and fnr <= threshold_fnr
        checks.append(
            (
                "False Negative Rate",
                "PASS" if fnr_ok else "FAIL",
                f"value={_pct(fnr)} threshold<={_pct(threshold_fnr)} denominator={risky_total}",
            )
        )
    else:
        checks.append(("False Negative Rate", "N/A", "No risky cases in denominator."))

    if safe_total > 0:
        fpr_ok = fpr is not None and fpr <= threshold_fpr
        checks.append(
            (
                "False Positive Rate",
                "PASS" if fpr_ok else "FAIL",
                f"value={_pct(fpr)} threshold<={_pct(threshold_fpr)} denominator={safe_total}",
            )
        )
    else:
        checks.append(("False Positive Rate", "N/A", "No safe cases in denominator."))

    if needs_reconciliation_runs > 0:
        recon_ok = reconciliation_match_rate is not None and reconciliation_match_rate >= threshold_reconciliation_match
        checks.append(
            (
                "Reconciliation Match Rate",
                "PASS" if recon_ok else "FAIL",
                (
                    f"value={_pct(reconciliation_match_rate)} "
                    f"threshold>={_pct(threshold_reconciliation_match)}"
                ),
            )
        )
    else:
        checks.append(("Reconciliation Match Rate", "N/A", "No provisional runs requiring reconciliation."))

    return checks


def _derive_verdict(checks: list[tuple[str, str, str]]) -> tuple[str, str]:
    has_fail = any(status == "FAIL" for _, status, _ in checks)
    has_na = any(status == "N/A" for _, status, _ in checks)
    if has_fail:
        return "NO-GO", "Threshold breach detected."
    if has_na:
        return "CONDITIONAL GO", "Some thresholds are not evaluable (N/A). Treat as evidence gap."
    return "GO", "All configured thresholds passed."


def _build_roi_section(
    *,
    avg_rollout_cost_usd: float,
    prevented_bad_decisions: int,
    missed_harmful_rollouts: int,
) -> dict[str, Any]:
    avg_cost = float(avg_rollout_cost_usd)
    prevented = max(0, int(prevented_bad_decisions))
    missed = max(0, int(missed_harmful_rollouts))
    if avg_cost <= 0.0:
        return {
            "status": "estimate_unavailable",
            "reason": "avg_rollout_cost_usd_not_positive",
            "avg_rollout_cost_usd": avg_cost,
            "prevented_bad_decisions": prevented,
            "missed_harmful_rollouts": missed,
            "estimated_saved_usd": None,
        }
    prevented_loss = prevented * avg_cost
    missed_loss = missed * avg_cost
    net_saved = prevented_loss - missed_loss
    return {
        "status": "estimated",
        "avg_rollout_cost_usd": avg_cost,
        "prevented_bad_decisions": prevented,
        "missed_harmful_rollouts": missed,
        "estimated_prevented_loss_usd": round(prevented_loss, 2),
        "estimated_missed_loss_usd": round(missed_loss, 2),
        "estimated_saved_usd": round(net_saved, 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build executive-facing ROI scorecard from batch/cost/failover artifacts.")
    parser.add_argument("--batch-id", default="", help="Optional batch id (expects data/batch_eval/<batch_id>_summary.json)")
    parser.add_argument("--batch-summary", default="", help="Optional explicit batch summary path")
    parser.add_argument("--cost-ledger-glob", default="data/cost/*_cost_ledger.json")
    parser.add_argument("--agent-report-glob", default="data/agent_reports/*_poc_sprint2.json")
    parser.add_argument("--reconciliation-events", default="data/reconciliation/reconciliation_events.jsonl")
    parser.add_argument("--reconciliation-summary", default="data/reconciliation/reconciliation_accuracy_summary.json")
    parser.add_argument("--out", default="data/reports/EXECUTIVE_ROI_SCORECARD.md")
    parser.add_argument("--out-json", default="", help="Optional machine-readable output path")
    parser.add_argument(
        "--avg-rollout-cost-usd",
        type=float,
        default=50000.0,
        help="Average avoided rollout loss used for business value estimate (default: 50000)",
    )
    parser.add_argument(
        "--integrity-required",
        type=int,
        default=1,
        choices=(0, 1),
        help="Require valid .sha256 sidecar for all consumed artifacts (default: 1)",
    )
    parser.add_argument("--threshold-availability", type=float, default=0.95)
    parser.add_argument("--threshold-fnr", type=float, default=0.05)
    parser.add_argument("--threshold-fpr", type=float, default=0.20)
    parser.add_argument("--threshold-reconciliation-match", type=float, default=0.80)
    args = parser.parse_args()

    integrity_required = bool(args.integrity_required)

    batch_path = _resolve_batch_summary_path(args.batch_summary, args.batch_id)
    batch = _load_json_with_integrity(batch_path, integrity_required=integrity_required)

    records = batch.get("records", []) if isinstance(batch.get("records"), list) else []
    run_ids = {str(r.get("run_id", "")).strip() for r in records if str(r.get("run_id", "")).strip()}

    completed_cases = _safe_int(batch.get("completed_cases"), 0)
    failed_api_cases = _safe_int(batch.get("failed_api_cases"), 0)
    failed_cases = _safe_int(batch.get("failed_cases"), 0)
    attempted_cases_full = completed_cases + failed_cases + failed_api_cases
    canonical_total_cases = _safe_int(batch.get("total_cases"), 0)
    attempted_cases = canonical_total_cases if canonical_total_cases > 0 else attempted_cases_full

    availability_derived = (completed_cases / attempted_cases) if attempted_cases > 0 else None
    availability, availability_source = _select_priority_metric(
        [
            ("batch_summary.availability_kpi", batch.get("availability_kpi"), _is_number(batch.get("availability_kpi"))),
            ("derived.completed_over_attempted", availability_derived, availability_derived is not None),
        ],
        default=None,
    )

    rate_stats = _compute_rates_from_records(records)
    fpr, fpr_source = _select_priority_metric(
        [
            ("batch_summary.false_positive_rate", batch.get("false_positive_rate"), _is_number(batch.get("false_positive_rate"))),
            ("derived.from_records", rate_stats["false_positive_rate"], rate_stats["false_positive_rate"] is not None),
        ],
        default=None,
    )
    fnr, fnr_source = _select_priority_metric(
        [
            ("batch_summary.false_negative_rate", batch.get("false_negative_rate"), _is_number(batch.get("false_negative_rate"))),
            ("derived.from_records", rate_stats["false_negative_rate"], rate_stats["false_negative_rate"] is not None),
        ],
        default=None,
    )

    batch_total_cost = batch.get("total_cost_usd_estimate")
    batch_total_cost_num = _safe_float(batch_total_cost, 0.0) if _is_number(batch_total_cost) else None

    records_total_cost = sum(_safe_float(r.get("cost_usd_estimate"), 0.0) for r in records if isinstance(r, dict))
    records_cost_available = any(_is_number(r.get("cost_usd_estimate")) for r in records if isinstance(r, dict))

    ledger_total_cost = 0.0
    ledger_records_count = 0
    for path in _glob_paths(args.cost_ledger_glob):
        rid = _run_id_from_cost_ledger(path)
        if run_ids and rid not in run_ids:
            continue
        ledger = _load_json_with_integrity(path, integrity_required=integrity_required)
        ledger_total_cost += _safe_float(ledger.get("usd_estimate"), 0.0)
        ledger_records_count += 1

    total_cost, cost_source = _select_priority_metric(
        [
            ("batch_summary.total_cost_usd_estimate", batch_total_cost_num, batch_total_cost_num is not None),
            ("sum(batch_summary.records[].cost_usd_estimate)", records_total_cost, records_cost_available),
            ("sum(cost_ledger.usd_estimate)", ledger_total_cost, ledger_records_count > 0),
        ],
        default=0.0,
    )

    cost_per_audit = (total_cost / completed_cases) if completed_cases > 0 else None
    protected_decisions = _safe_int(rate_stats.get("prevented_bad_decisions"), 0)
    cost_per_protected_decision = (total_cost / protected_decisions) if (total_cost > 0 and protected_decisions > 0) else None
    protected_decisions_warning = (
        "No protected decisions in this batch; `cost_per_protected_decision` is reported as `N/A`."
        if protected_decisions <= 0
        else ""
    )

    recon_stats = _collect_reconciliation_stats(
        run_ids=run_ids,
        agent_report_glob=args.agent_report_glob,
        reconciliation_events_path=(ROOT / args.reconciliation_events),
        reconciliation_summary_path=(ROOT / args.reconciliation_summary),
        integrity_required=integrity_required,
    )

    risky_total = _safe_int(rate_stats["risky_total"])
    safe_total = _safe_int(rate_stats["safe_total"])
    fp_count = _safe_int(rate_stats["false_positive_count"])
    fn_count = _safe_int(rate_stats["false_negative_count"])
    prevented_bad_decisions = _safe_int(rate_stats["prevented_bad_decisions"])

    scoped_runs = _safe_int(recon_stats.get("scoped_runs"), 0)
    edge_fallback_runs = _safe_int(recon_stats.get("provisional_runs"), 0)
    cloud_only_runs = max(0, scoped_runs - edge_fallback_runs)
    edge_fallback_rate = (edge_fallback_runs / scoped_runs) if scoped_runs > 0 else None
    cloud_path_rate = (cloud_only_runs / scoped_runs) if scoped_runs > 0 else None

    checks = _build_go_no_go_checks(
        availability=availability,
        fnr=fnr,
        fpr=fpr,
        risky_total=risky_total,
        safe_total=safe_total,
        needs_reconciliation_runs=_safe_int(recon_stats.get("needs_reconciliation_runs"), 0),
        reconciliation_match_rate=(
            float(recon_stats["reconciliation_match_rate"]) if recon_stats.get("reconciliation_match_rate") is not None else None
        ),
        threshold_availability=float(args.threshold_availability),
        threshold_fnr=float(args.threshold_fnr),
        threshold_fpr=float(args.threshold_fpr),
        threshold_reconciliation_match=float(args.threshold_reconciliation_match),
    )
    verdict, verdict_note = _derive_verdict(checks)

    md_lines = [
        "# EXECUTIVE ROI SCORECARD",
        "",
        f"- Generated at: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Batch summary source: `{batch_path}`",
        f"- Batch id: `{batch.get('batch_id', 'unknown')}`",
        "",
        "## Go / No-Go Summary",
        f"- **Verdict: {verdict}**",
        f"- {verdict_note}",
        "",
        "## Platform Availability & Resilience",
        f"- Zero-Downtime Availability: **{_pct(availability)}**",
        f"- Completed audits: `{completed_cases}`",
        f"- Failed API cases: `{failed_api_cases}`",
        f"- Failed cases (non-API): `{failed_cases}`",
        f"- Total attempted audits: `{attempted_cases}`",
        f"- Cloud-path runs: `{cloud_only_runs}` ({_pct(cloud_path_rate)})",
        f"- Edge fallback runs: `{edge_fallback_runs}` ({_pct(edge_fallback_rate)})",
        "",
        "## Unit Economics (ROI)",
        f"- Total audit cost (USD): **{_usd(total_cost)}**",
        f"- Average cost per audit (USD): **{_usd(cost_per_audit)}**",
        f"- Cost per protected decision (USD): **{_usd(cost_per_protected_decision)}**",
    ]
    if protected_decisions_warning:
        md_lines.append(f"- Warning: {protected_decisions_warning}")

    roi_section = _build_roi_section(
        avg_rollout_cost_usd=float(args.avg_rollout_cost_usd),
        prevented_bad_decisions=prevented_bad_decisions,
        missed_harmful_rollouts=fn_count,
    )
    md_lines.extend(
        [
            "",
            "## Business Value Estimate",
        ]
    )
    if roi_section.get("status") == "estimate_unavailable":
        md_lines.append(
            f"- `estimate_unavailable`: avg rollout cost is not positive (`{roi_section.get('avg_rollout_cost_usd')}`)."
        )
    else:
        md_lines.extend(
            [
                f"- Avg rollout cost assumption (USD): **{_usd(float(roi_section.get('avg_rollout_cost_usd')))}**",
                f"- Estimated prevented loss (USD): **{_usd(float(roi_section.get('estimated_prevented_loss_usd')))}**",
                f"- Estimated missed loss (USD): **{_usd(float(roi_section.get('estimated_missed_loss_usd')))}**",
                f"- **Estimated net saved money (USD): {_usd(float(roi_section.get('estimated_saved_usd')))}**",
            ]
        )

    md_lines.extend(
        [
            "",
            "## Quality & Regret Prevention",
            f"- False Negative Rate (missed harmful rollouts): **{_pct(fnr)}**",
            f"- False Positive Rate (unnecessary blocks): **{_pct(fpr)}**",
            f"- Risky cases evaluated (FNR denominator): `{risky_total}`",
            f"- Safe cases evaluated (FPR denominator): `{safe_total}`",
            f"- Missed harmful rollouts (FN count): `{fn_count}`",
            f"- Unnecessary blocks (FP count): `{fp_count}`",
            f"- Prevented Bad Decisions (proxy): `{prevented_bad_decisions}`",
            "",
            "## Reconciliation",
            f"- Provisional runs requiring reconciliation: `{recon_stats['needs_reconciliation_runs']}`",
            (
                f"- Match-rate (local provisional vs cloud): **{_pct(recon_stats['reconciliation_match_rate'])}** "
                f"(`{recon_stats['reconciliation_matched']}` matched / `{recon_stats['reconciliation_compared']}` compared)"
            ),
            f"- Match-rate source: `{recon_stats['reconciliation_match_source']}`",
            f"- Fallback coverage by agent: `captain={recon_stats['fallback_agent_hits']['captain']}`, "
            f"`doctor={recon_stats['fallback_agent_hits']['doctor']}`, "
            f"`commander={recon_stats['fallback_agent_hits']['commander']}`",
            "",
            "## Threshold Checks",
        ]
    )

    for name, status, detail in checks:
        md_lines.append(f"- `{name}`: **{status}** ({detail})")

    md_lines.extend(
        [
            "",
            "## Methodology (SoT Rules)",
            "- Source priority:",
            f"  - Availability: `{SOURCE_PRIORITY['availability'][0]}` -> `{SOURCE_PRIORITY['availability'][1]}`",
            f"  - Quality rates: `{SOURCE_PRIORITY['quality_rates'][0]}` -> `{SOURCE_PRIORITY['quality_rates'][1]}`",
            f"  - Cost USD: `{SOURCE_PRIORITY['cost_usd'][0]}` -> `{SOURCE_PRIORITY['cost_usd'][1]}` -> `{SOURCE_PRIORITY['cost_usd'][2]}`",
            f"  - Reconciliation: `{SOURCE_PRIORITY['reconciliation'][0]}` -> `{SOURCE_PRIORITY['reconciliation'][1]}` -> `{SOURCE_PRIORITY['reconciliation'][2]}`",
            f"- Chosen source this run: availability=`{availability_source}`, fnr=`{fnr_source}`, fpr=`{fpr_source}`, cost=`{cost_source}`",
            "- Denominator policy:",
            "  - Availability uses `attempted_cases = total_cases OR (completed_cases + failed_cases + failed_api_cases)`.",
            "  - FNR uses risky records only; FPR uses safe records only; `status=FAILED*` is excluded.",
            f"- Integrity mode: `integrity_required={integrity_required}` (default fail-closed = `1`; legacy demo override = `0`).",
            "",
            "## Data Sources",
            f"- Batch summary: `{batch_path}`",
            f"- Cost ledger glob: `{args.cost_ledger_glob}`",
            f"- Agent report glob: `{args.agent_report_glob}`",
            f"- Reconciliation events: `{ROOT / args.reconciliation_events}`",
            f"- Reconciliation summary: `{ROOT / args.reconciliation_summary}`",
            "",
            "_Interpretation note: FNR approximates business regret leakage; FPR approximates conservative over-blocking._",
        ]
    )

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    write_sha256_sidecar(out_path)

    out_json_path = Path(args.out_json) if str(args.out_json or "").strip() else Path("data/reports/EXECUTIVE_ROI_SCORECARD.json")
    if not out_json_path.is_absolute():
        out_json_path = ROOT / out_json_path
    out_json_path.parent.mkdir(parents=True, exist_ok=True)
    machine_payload = {
        "version": "executive_roi_scorecard_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "batch_summary_source": str(batch_path),
        "batch_id": str(batch.get("batch_id", "unknown")),
        "verdict": verdict,
        "availability": availability,
        "false_negative_rate": fnr,
        "false_positive_rate": fpr,
        "total_cost_usd": total_cost,
        "cost_per_audit_usd": cost_per_audit,
        "cost_per_protected_decision_usd": cost_per_protected_decision,
        "prevented_bad_decisions": prevented_bad_decisions,
        "missed_harmful_rollouts": fn_count,
        "roi_section": roi_section,
    }
    out_json_path.write_text(json.dumps(machine_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out_json_path)

    print(f"ok: executive ROI scorecard written {out_path}")
    print(
        " ".join(
            [
                f"verdict={verdict}",
                f"availability={_pct(availability)}",
                f"cost_per_audit={_usd(cost_per_audit)}",
                f"fnr={_pct(fnr)}",
                f"fpr={_pct(fpr)}",
            ]
        )
    )


if __name__ == "__main__":
    main()
