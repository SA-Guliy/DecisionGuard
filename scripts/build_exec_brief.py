#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]


def _redact(text: str) -> str:
    out = text
    for pattern, repl in REDACTION_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _safe_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(text), encoding="utf-8")


def _load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _f(value: Any) -> float | None:
    try:
        return float(value)
    except Exception:
        return None


def _delta(cur: Any, base: Any) -> str:
    c = _f(cur)
    b = _f(base)
    if c is None or b is None:
        return "missing"
    return f"{(c - b):+.4f}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build monthly exec brief")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    day_id = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_dir = Path(f"reports/L3_exec/{day_id}")
    log_path = Path(f"data/logs/build_exec_brief_{run_id}.log")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}
        snap = _load(Path(f"data/metrics_snapshots/{run_id}.json")) or {}
        dq = _load(Path(f"data/dq_reports/{run_id}.json")) or {}
        doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
        evaluator = _load(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")) or {}
        m = snap.get("metrics", {}) if isinstance(snap.get("metrics"), dict) else {}

        control_id = None
        if isinstance(doctor.get("inputs"), dict):
            control_id = str((doctor.get("inputs") or {}).get("control_run_id", "")).strip() or None
        base_metrics = {}
        if control_id:
            control_snap = _load(Path(f"data/metrics_snapshots/{control_id}.json")) or {}
            base_metrics = control_snap.get("metrics", {}) if isinstance(control_snap.get("metrics"), dict) else {}

        top_priorities = cmd.get("top_priorities", []) if isinstance(cmd.get("top_priorities"), list) else []
        blocked = cmd.get("blocked_by", []) if isinstance(cmd.get("blocked_by"), list) else []
        next_exp = cmd.get("next_experiment", {}) if isinstance(cmd.get("next_experiment"), dict) else {}
        key_decisions = [str(x.get("title", "missing")) for x in top_priorities[:3] if isinstance(x, dict)] or ["missing"]
        next_big_bet = str(next_exp.get("name", "")).strip() or "missing"

        ab_status = str(evaluator.get("ab_status", "missing"))
        risks = [
            "goodhart" if any("goodhart" in str(x).lower() for x in blocked) else "goodhart_not_detected",
            "confounding" if any("competitor" in str(x).lower() or "confound" in str(x).lower() for x in blocked) else "confounding_not_detected",
            "underpowered" if ab_status.upper() == "UNDERPOWERED" else "underpowered_not_detected",
        ]

        decisions_3 = [
            f"Start: {next_big_bet if str(cmd.get('normalized_decision', cmd.get('decision', ''))).upper() in {'RUN_AB','ROLLOUT_CANDIDATE'} else 'none'}",
            f"Hold: {blocked[0] if blocked else 'none'}",
            f"Stop: {'yes' if str(cmd.get('normalized_decision', cmd.get('decision', ''))).upper() == 'STOP' else 'no'}",
        ]

        expected_range = "missing"
        ab_plan = doctor.get("ab_plan", []) if isinstance(doctor.get("ab_plan"), list) else []
        first = ab_plan[0] if ab_plan and isinstance(ab_plan[0], dict) else {}
        hyps = first.get("hypotheses", []) if isinstance(first.get("hypotheses"), list) else []
        if hyps and isinstance(hyps[0], dict):
            expected_range = str(hyps[0].get("expected_effect_range", "missing"))

        lines = [
            f"# Exec Brief — {day_id}",
            "",
            f"- Run: `{run_id}`",
            f"- Decision: `{cmd.get('normalized_decision', cmd.get('decision', 'unknown'))}`",
            f"- DQ status: `{dq.get('qa_status', 'unknown')}`",
            "",
            "## 3 KPI Trend Deltas (vs control if available)",
            f"- Goal1 writeoff_units delta: `{_delta(m.get('writeoff_units'), base_metrics.get('writeoff_units'))}`",
            f"- Goal2 aov delta: `{_delta(m.get('aov'), base_metrics.get('aov'))}`",
            f"- Goal3 new_buyers_7d delta: `{_delta(m.get('new_buyers_7d'), base_metrics.get('new_buyers_7d'))}`",
            "",
            "## 3 Decisions (Start / Hold / Stop)",
            f"1) {decisions_3[0]}",
            f"2) {decisions_3[1]}",
            f"3) {decisions_3[2]}",
            "",
            "## 3 Risks",
            f"1) {risks[0]}",
            f"2) {risks[1]}",
            f"3) {risks[2]}",
            "",
            "## Next Big Bet",
            f"- Experiment: `{next_big_bet}`",
            f"- Expected impact range: `{expected_range}`",
            "",
            "## Why this month",
            f"- Top priorities: `{key_decisions}`",
            "",
        ]
        _safe_write(out_dir / "exec_brief.md", "\n".join(lines))
        print(f"ok: exec brief written for run_id={run_id}")
    except Exception as exc:
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(_redact(traceback.format_exc()), encoding="utf-8")
        _safe_write(
            out_dir / "build_error.md",
            "\n".join(
                [
                    f"# Build Error — {day_id}",
                    "",
                    "- report_builder: `scripts/build_exec_brief.py`",
                    f"- error: `{exc}`",
                    f"- log: `{log_path}`",
                    "",
                ]
            ),
        )
        print(f"ok: exec brief fallback wrote {out_dir / 'build_error.md'}")


if __name__ == "__main__":
    main()
