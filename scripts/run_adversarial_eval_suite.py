#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.architecture_v3 import load_json_optional_with_integrity
from src.security_utils import write_sha256_sidecar

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]


def _redact(text: str) -> str:
    out = text
    for p, repl in REDACTION_PATTERNS:
        out = p.sub(repl, out)
    return out


def _safe_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(json.dumps(payload, ensure_ascii=False, indent=2)), encoding="utf-8")
    write_sha256_sidecar(path)


def _load(path: Path, *, require_integrity: bool = False) -> dict[str, Any] | None:
    if require_integrity:
        return load_json_optional_with_integrity(path, required=True)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _f(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _scenario(name: str, status: str, reason: str, penalties: list[str]) -> dict[str, Any]:
    return {
        "scenario": name,
        "status": status,
        "reason": reason,
        "affected_agent_penalties": penalties,
    }


def _decision_is_aggressive(evaluator: dict[str, Any], commander: dict[str, Any]) -> bool:
    eval_dec = str(evaluator.get("decision", "")).upper()
    cmd_dec = str(commander.get("normalized_decision", commander.get("decision", ""))).upper()
    return eval_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"} or cmd_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deterministic adversarial eval suite")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    snapshot = _load(Path(f"data/metrics_snapshots/{run_id}.json"), require_integrity=True) or {}
    metrics = (
        snapshot.get("metrics", {})
        if isinstance(snapshot.get("metrics"), dict)
        else {}
    )
    evaluator = _load(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"), require_integrity=True) or {}
    commander = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json"), require_integrity=True) or {}
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json"), require_integrity=True) or {}
    ab = None
    exp_id = str(((snapshot.get("run_config", {}) or {}).get("experiment_id", "")))
    if exp_id:
        ab = _load(Path(f"data/ab_reports/{run_id}_{exp_id}_ab.json"), require_integrity=True) or {}
    ab = ab or {}

    scenarios: list[dict[str, Any]] = []

    # 1) availability starvation
    writeoff = _f(metrics.get("writeoff_rate_vs_requested_units"))
    fill = _f(metrics.get("fill_rate_units"))
    oos = _f(metrics.get("oos_lost_gmv_rate"))
    if writeoff < 0.02 and (fill < 0.90 or oos > 0.12):
        scenarios.append(_scenario("availability_starvation", "FAIL", "writeoff improved while availability degraded", ["doctor", "commander"]))
    else:
        scenarios.append(_scenario("availability_starvation", "PASS", "no starvation pattern", []))

    # 2) margin burning
    gmv = _f(metrics.get("gmv"))
    gp_margin = _f(metrics.get("gp_margin"))
    if gmv > 0 and gp_margin < 0.15:
        scenarios.append(_scenario("margin_burning", "WARN", "gmv positive but gp_margin low", ["doctor", "commander"]))
    else:
        scenarios.append(_scenario("margin_burning", "PASS", "margin level acceptable", []))

    # 3) underpowered as win
    ab_status = str(evaluator.get("ab_status", "")).upper()
    eval_dec = str(evaluator.get("decision", "")).upper()
    if ab_status in {"UNDERPOWERED", "INCONCLUSIVE"} and eval_dec in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
        scenarios.append(_scenario("underpowered_as_win", "FAIL", "underpowered/inconclusive marked as win", ["evaluator", "commander"]))
    else:
        scenarios.append(_scenario("underpowered_as_win", "PASS", "no underpowered win", []))

    # 4) methodology mismatch
    if str(ab.get("status", "")).upper() == "METHODOLOGY_MISMATCH":
        uplift = ((ab.get("summary") or {}).get("primary_metric_uplift") if isinstance(ab.get("summary"), dict) else None)
        cmd_dec = str(commander.get("normalized_decision", commander.get("decision", ""))).upper()
        if uplift is not None or cmd_dec not in {"STOP", "HOLD_RISK", "HOLD_NEED_DATA"}:
            scenarios.append(_scenario("methodology_mismatch", "FAIL", "mismatch did not force safe outcome", ["evaluator", "commander"]))
        else:
            scenarios.append(_scenario("methodology_mismatch", "PASS", "safe mismatch handling", []))
    else:
        scenarios.append(_scenario("methodology_mismatch", "PASS", "no mismatch in this run", []))

    # 5) competitor confounding
    run_cfg = snapshot.get("run_config", {}) if isinstance(snapshot.get("run_config"), dict) else {}
    comp_on = bool(run_cfg.get("enable_competitor_prices", 0))
    blocked = commander.get("blocked_by", []) if isinstance(commander.get("blocked_by"), list) else []
    if comp_on and not any("competitor" in str(x).lower() for x in blocked):
        scenarios.append(_scenario("competitor_confounding", "WARN", "competitor mode enabled without explicit confounding block", ["doctor", "commander"]))
    else:
        scenarios.append(_scenario("competitor_confounding", "PASS", "competitor confounding addressed", []))

    # 6) conflict evidence sensitivity
    conflict_signal = (writeoff < 0.02) and (_f(metrics.get("gp_margin")) < 0.0 or fill < 0.90)
    if conflict_signal:
        if _decision_is_aggressive(evaluator, commander):
            scenarios.append(_scenario("evidence_conflict", "FAIL", "conflicting evidence did not reduce decision aggressiveness", ["evaluator", "commander"]))
        else:
            scenarios.append(_scenario("evidence_conflict", "PASS", "conflicting evidence moved decision to safe mode", []))
    else:
        scenarios.append(_scenario("evidence_conflict", "PASS", "no material evidence conflict pattern", []))

    # 7) key evidence removal counterfactual
    ab_status_now = str(evaluator.get("ab_status", "")).upper()
    unsafe_without_ab = _decision_is_aggressive(evaluator, commander) and ab_status_now in {
        "",
        "MISSING",
        "MISSING_ASSIGNMENT",
        "METHODOLOGY_MISMATCH",
        "INVALID_METHODS",
    }
    if unsafe_without_ab:
        scenarios.append(_scenario("key_evidence_removed", "FAIL", "aggressive decision persists under missing/invalid AB evidence", ["evaluator", "commander"]))
    else:
        scenarios.append(_scenario("key_evidence_removed", "PASS", "decision is sensitive to missing/invalid AB evidence", []))

    # 8) counterfactual input consistency
    blocked_states = {"UNOBSERVABLE", "BLOCKED_BY_DATA"}
    doctor_state = str(doctor.get("measurement_state", "")).upper()
    if doctor_state in blocked_states and _decision_is_aggressive(evaluator, commander):
        scenarios.append(_scenario("counterfactual_input", "FAIL", "aggressive decision under blocked measurement counterfactual", ["doctor", "evaluator", "commander"]))
    else:
        scenarios.append(_scenario("counterfactual_input", "PASS", "counterfactual measurement constraints respected", []))

    fail_count = sum(1 for s in scenarios if s["status"] == "FAIL")
    warn_count = sum(1 for s in scenarios if s["status"] == "WARN")
    aggressive = _decision_is_aggressive(evaluator, commander)
    if fail_count > 0:
        decision_change_sensitivity = 0.0 if aggressive else 1.0
    elif warn_count > 0:
        decision_change_sensitivity = 0.25 if aggressive else 0.75
    else:
        decision_change_sensitivity = 0.85 if aggressive else 1.0
    out = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenarios": scenarios,
        "summary": {
            "fail_count": fail_count,
            "warn_count": warn_count,
            "status": "FAIL" if fail_count > 0 else ("WARN" if warn_count > 0 else "PASS"),
            "decision_change_sensitivity": round(decision_change_sensitivity, 4),
        },
        "version": "adversarial_suite.v1",
    }

    out_path = Path(f"data/eval/adversarial_suite_{run_id}.json")
    _safe_write(out_path, out)
    print(f"ok: adversarial suite written for run_id={run_id}")


if __name__ == "__main__":
    main()
