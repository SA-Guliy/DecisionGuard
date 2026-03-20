#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import traceback
from collections import Counter
from datetime import datetime, timedelta, timezone
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


def _guess_week_id() -> str:
    now = datetime.now(timezone.utc)
    y, w, _ = now.isocalendar()
    return f"{y}-W{w:02d}"


def _parse_ts(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = raw.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        s = value.strip().lower()
        return bool(s and s not in {"missing", "none", "null", "nan", "n/a", "unknown"})
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def _run_time_from_run_id(run_id: str) -> datetime | None:
    # Supports run ids containing YYYY-MM-DD or YYYYMMDD.
    m_iso = re.search(r"(20\\d{2})-(\\d{2})-(\\d{2})", run_id)
    if m_iso:
        try:
            return datetime(
                int(m_iso.group(1)),
                int(m_iso.group(2)),
                int(m_iso.group(3)),
                tzinfo=timezone.utc,
            )
        except Exception:
            return None
    m_compact = re.search(r"(20\\d{2})(\\d{2})(\\d{2})", run_id)
    if m_compact:
        try:
            return datetime(
                int(m_compact.group(1)),
                int(m_compact.group(2)),
                int(m_compact.group(3)),
                tzinfo=timezone.utc,
            )
        except Exception:
            return None
    return None


def _discover_run_ids(days_back: int = 7) -> list[str]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    run_ids: list[str] = []
    for p in Path("data/agent_reports").glob("*_commander_priority.json"):
        rid = p.name.replace("_commander_priority.json", "")
        payload = _load(p) or {}
        ts = (
            _parse_ts(payload.get("generated_at"))
            or _parse_ts(payload.get("created_at"))
            or _run_time_from_run_id(rid)
        )
        if ts is not None and ts >= cutoff:
            run_ids.append(rid)
    return sorted(set(run_ids))


def _write_weekly_agent_quality_alias(out_dir: Path, week_id: str, fallback_body: str | None = None) -> None:
    """
    Keep backward-compatible `weekly_agent_quality.md`, but prefer the canonical
    `agent_quality_summary.md` produced by `scripts/make_agent_quality_summary.py`.
    """
    canonical = out_dir / "agent_quality_summary.md"
    alias_path = out_dir / "weekly_agent_quality.md"
    if canonical.exists():
        _safe_write(
            alias_path,
            "\n".join(
                [
                    f"# Weekly Agent Quality — {week_id}",
                    "",
                    "Canonical report moved to:",
                    f"- [agent_quality_summary.md]({canonical.name})",
                    "",
                    "This file is kept as a backward-compatible alias to reduce breakage in existing workflows.",
                    "",
                ]
            ),
        )
        return
    body = fallback_body or f"# Weekly Agent Quality — {week_id}\n\n- missing canonical summary\n"
    _safe_write(alias_path, body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build weekly management pack (L2)")
    parser.add_argument("--week-id", default="")
    parser.add_argument("--run-ids", default="")
    args = parser.parse_args()

    week_id = args.week_id.strip() or _guess_week_id()
    out_dir = Path(f"reports/L2_mgmt/weekly_{week_id.replace('-', '_')}")
    log_path = Path(f"data/logs/build_weekly_pack_{week_id.replace('-', '_')}.log")
    try:
        run_ids = [x.strip() for x in args.run_ids.split(",") if x.strip()] or _discover_run_ids()
        out_dir.mkdir(parents=True, exist_ok=True)

        if not run_ids:
            _safe_write(out_dir / "weekly_summary.md", f"# Weekly Summary — {week_id}\n\n- insufficient runs\n")
            with (out_dir / "weekly_scorecard.csv").open("w", encoding="utf-8", newline="") as f:
                csv.writer(f).writerow(["run_id", "status"])
            _write_weekly_agent_quality_alias(
                out_dir,
                week_id,
                fallback_body=f"# Weekly Agent Quality — {week_id}\n\n- insufficient runs\n",
            )
            print(f"ok: weekly pack written to {out_dir}")
            return

        decisions = Counter()
        blockers = Counter()
        hold_reasons = Counter()
        design_gap_codes = Counter()
        design_coverage_vals: list[float] = []
        design_complete_count = 0
        fallback_true = 0
        captain_total = 0
        doctor_hyp_valid = 0
        doctor_total = 0
        started_exp: list[str] = []
        held_or_stopped: list[str] = []

        scorecard_rows: list[list[Any]] = []
        for rid in run_ids:
            cmd = _load(Path(f"data/agent_reports/{rid}_commander_priority.json")) or {}
            doc = _load(Path(f"data/agent_reports/{rid}_doctor_variance.json")) or {}
            ev = _load(Path(f"data/agent_reports/{rid}_experiment_evaluator.json")) or {}
            dq = _load(Path(f"data/dq_reports/{rid}.json")) or {}
            snap = _load(Path(f"data/metrics_snapshots/{rid}.json")) or {}
            cap = _load(Path(f"data/llm_reports/{rid}_captain.json")) or {}

            decision = str(cmd.get("normalized_decision", cmd.get("decision", "unknown")))
            decisions[decision] += 1
            blocked = cmd.get("blocked_by", []) if isinstance(cmd.get("blocked_by"), list) else []
            for b in blocked:
                blockers[str(b)] += 1
                if "hold" in str(b).lower() or "missing" in str(b).lower():
                    hold_reasons[str(b)] += 1

            m = snap.get("metrics", {}) if isinstance(snap.get("metrics"), dict) else {}
            scorecard_rows.append(
                [
                    rid,
                    decision,
                    m.get("writeoff_units", "missing"),
                    m.get("aov", "missing"),
                    m.get("new_buyers_7d", "missing"),
                    m.get("gp_margin", "missing"),
                    m.get("fill_rate_units", "missing"),
                    m.get("oos_lost_gmv_rate", "missing"),
                    ";".join(str(x) for x in blocked[:5]) if blocked else "",
                ]
            )

            captain_total += 1
            if bool(cap.get("fallback_used")):
                fallback_true += 1
            doctor_total += 1
            plan = doc.get("ab_plan", []) if isinstance(doc.get("ab_plan"), list) else []
            recommended_experiment = doc.get("recommended_experiment", {}) if isinstance(doc.get("recommended_experiment"), dict) else {}
            first = plan[0] if plan and isinstance(plan[0], dict) else (recommended_experiment if isinstance(recommended_experiment, dict) else {})
            hyps = first.get("hypotheses", []) if isinstance(first.get("hypotheses"), list) else []
            if hyps and isinstance(hyps[0], dict) and str(hyps[0].get("hypothesis_statement", "")).strip():
                doctor_hyp_valid += 1
            measurement_fix_plan = doc.get("measurement_fix_plan", {}) if isinstance(doc.get("measurement_fix_plan"), dict) else {}
            required_raw = measurement_fix_plan.get("required_design_fields")
            required_fields = [str(x).strip() for x in required_raw] if isinstance(required_raw, list) else []
            if not required_fields:
                required_fields = [
                    "pre_period_weeks",
                    "test_period_weeks",
                    "wash_in_days",
                    "attribution_window_rule",
                    "test_side",
                    "randomization_unit",
                    "analysis_unit",
                ]
            required_fields = [x for x in required_fields if x]
            aliases = {
                "randomization_unit": "randomization_unit_cfg",
                "analysis_unit": "analysis_unit_realized",
                "randomization_unit_cfg": "randomization_unit",
                "analysis_unit_realized": "analysis_unit",
            }
            if required_fields:
                present = 0
                run_missing: list[str] = []
                for key in required_fields:
                    value = first.get(key) if isinstance(first, dict) else None
                    if value is None and key in aliases and isinstance(first, dict):
                        value = first.get(aliases[key])
                    if _is_present(value):
                        present += 1
                    else:
                        run_missing.append(key)
                        design_gap_codes[key] += 1
                design_coverage_vals.append(present / len(required_fields))
                if not run_missing:
                    design_complete_count += 1

            if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                nex = cmd.get("next_experiment", {}) if isinstance(cmd.get("next_experiment"), dict) else {}
                started_exp.append(f"{rid}: {nex.get('name', 'missing')}")
            if decision in {"HOLD_NEED_DATA", "HOLD_RISK", "STOP"}:
                reason = blocked[0] if blocked else (ev.get("blocked_by", ["missing"]))[0] if isinstance(ev.get("blocked_by"), list) and ev.get("blocked_by") else "missing"
                held_or_stopped.append(f"{rid}: {decision} ({reason})")

        with (out_dir / "weekly_scorecard.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "run_id",
                    "commander_decision",
                    "goal1_writeoff_units",
                    "goal2_aov",
                    "goal3_new_buyers_7d",
                    "gp_margin",
                    "fill_rate_units",
                    "oos_lost_gmv_rate",
                    "blockers",
                ]
            )
            writer.writerows(scorecard_rows)

        summary_lines = [
            f"# Weekly Summary — {week_id}",
            "",
            f"- runs_count: `{len(run_ids)}`",
            f"- decisions: `{dict(decisions)}`",
            f"- top_blockers: `{blockers.most_common(5)}`",
            f"- doctor_design_contract_complete_pct: `{(design_complete_count / doctor_total) if doctor_total else 'missing'}`",
            f"- doctor_avg_design_field_coverage: `{(sum(design_coverage_vals) / len(design_coverage_vals)) if design_coverage_vals else 'missing'}`",
            f"- doctor_top_design_gap_codes: `{design_gap_codes.most_common(10)}`",
            "",
            "## What Changed",
            "- New experiments started this week:",
            *([f"  - {x}" for x in started_exp[:10]] if started_exp else ["  - none"]),
            "- Experiments held/stopped and why:",
            *([f"  - {x}" for x in held_or_stopped[:10]] if held_or_stopped else ["  - none"]),
        ]
        _safe_write(out_dir / "weekly_summary.md", "\n".join(summary_lines) + "\n")

        aq_lines = [
            f"# Weekly Agent Quality — {week_id}",
            "",
            f"- captain_fallback_rate: `{(fallback_true / captain_total) if captain_total else 'missing'}`",
            f"- doctor_hypothesis_valid_pct: `{(doctor_hyp_valid / doctor_total) if doctor_total else 'missing'}`",
            f"- doctor_design_contract_complete_pct: `{(design_complete_count / doctor_total) if doctor_total else 'missing'}`",
            f"- doctor_avg_design_field_coverage: `{(sum(design_coverage_vals) / len(design_coverage_vals)) if design_coverage_vals else 'missing'}`",
            f"- doctor_top_design_gap_codes: `{design_gap_codes.most_common(10)}`",
            f"- hold_reasons_top: `{hold_reasons.most_common(10)}`",
        ]
        _write_weekly_agent_quality_alias(out_dir, week_id, fallback_body="\n".join(aq_lines) + "\n")
        print(f"ok: weekly pack written to {out_dir}")
    except Exception as exc:
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(_redact(traceback.format_exc()), encoding="utf-8")
        _safe_write(
            out_dir / "build_error.md",
            "\n".join(
                [
                    f"# Build Error — {week_id}",
                    "",
                    "- report_builder: `scripts/build_weekly_pack.py`",
                    f"- error: `{exc}`",
                    f"- log: `{log_path}`",
                    "",
                ]
            ),
        )
        print(f"ok: weekly pack fallback wrote {out_dir / 'build_error.md'}")


if __name__ == "__main__":
    main()
