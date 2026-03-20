#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.decision_contract import load_decision_contract, validate_decision, validate_required_fields
from src.architecture_v3 import load_anti_goodhart_verdict
from src.domain_template import ConfigurationError, domain_guardrails_for, domain_template_source, set_domain_template_override
from src.security_utils import write_sha256_sidecar

VERSION = "experiment_evaluator.v1"

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]


def _redact_text(value: str) -> str:
    out = value
    for pattern, repl in REDACTION_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_redact_obj(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_obj(v) for k, v in value.items()}
    return value


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, f"missing_input:{path}"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except Exception:
        return None, f"invalid_input:{path}"


def _metric(metrics: dict[str, Any], key: str) -> float | None:
    try:
        value = metrics.get(key)
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _ab_ci_crosses_zero(ab: dict[str, Any]) -> bool | None:
    summary = ab.get("summary", {}) if isinstance(ab.get("summary"), dict) else {}
    ci = summary.get("primary_metric_uplift_ci95")
    if not isinstance(ci, list) or len(ci) != 2:
        return None
    try:
        lo = float(ci[0])
        hi = float(ci[1])
    except Exception:
        return None
    return lo <= 0.0 <= hi


def _ab_sign_matches_expected(ab: dict[str, Any], expected_direction: str) -> bool | None:
    summary = ab.get("summary", {}) if isinstance(ab.get("summary"), dict) else {}
    uplift = summary.get("primary_metric_uplift")
    if uplift is None:
        return None
    try:
        val = float(uplift)
    except Exception:
        return None
    direction = expected_direction.strip()
    if direction == "-":
        return val < 0.0
    return val > 0.0


def _guardrail_breach(metrics: dict[str, Any], guardrails: list[str]) -> list[str]:
    breaches: list[str] = []
    threshold_map: dict[str, float] = {}
    for row in domain_guardrails_for("experiment_evaluator"):
        metric = str(row.get("metric", "")).strip()
        threshold = row.get("threshold")
        if metric and isinstance(threshold, (int, float)):
            threshold_map[metric] = float(threshold)
    gp_floor = float(threshold_map.get("gp_margin", 0.0))
    fill_floor = float(threshold_map.get("fill_rate_units", 0.92))
    oos_ceiling = float(threshold_map.get("oos_lost_gmv_rate", 0.20))
    gp_margin = _metric(metrics, "gp_margin")
    fill_rate = _metric(metrics, "fill_rate_units")
    oos = _metric(metrics, "oos_lost_gmv_rate")
    if "gp_margin" in guardrails and gp_margin is not None and gp_margin < gp_floor:
        breaches.append("gp_margin<0" if abs(gp_floor) < 1e-12 else f"gp_margin<{gp_floor:.2f}")
    if "fill_rate_units" in guardrails and fill_rate is not None and fill_rate < fill_floor:
        breaches.append(f"fill_rate_units<{fill_floor:.2f}")
    if "oos_lost_gmv_rate" in guardrails and oos is not None and oos > oos_ceiling:
        breaches.append(f"oos_lost_gmv_rate>{oos_ceiling:.2f}")
    return breaches


def _pick_expected_direction(doctor: dict[str, Any]) -> str:
    plan = doctor.get("ab_plan") if isinstance(doctor.get("ab_plan"), list) else []
    if not plan or not isinstance(plan[0], dict):
        return "+"
    exp = plan[0]
    hypotheses = exp.get("hypotheses") if isinstance(exp.get("hypotheses"), list) else []
    if hypotheses and isinstance(hypotheses[0], dict):
        direction = str(hypotheses[0].get("expected_direction", "+")).strip()
        if direction in {"+", "-"}:
            return direction
    return "+"


def _pick_guardrails(doctor: dict[str, Any]) -> list[str]:
    g = doctor.get("guardrails")
    if isinstance(g, list) and g:
        return [str(x) for x in g]
    plan = doctor.get("ab_plan") if isinstance(doctor.get("ab_plan"), list) else []
    if plan and isinstance(plan[0], dict):
        pg = plan[0].get("guardrails")
        if isinstance(pg, list):
            return [str(x) for x in pg]
    template_guardrails = domain_guardrails_for("experiment_evaluator")
    metrics = [str(row.get("metric", "")).strip() for row in template_guardrails if isinstance(row, dict)]
    if metrics:
        return metrics
    return ["gp_margin", "fill_rate_units", "oos_lost_gmv_rate"]


def _anti_goodhart_from_sot(run_id: str) -> tuple[bool, str | None]:
    try:
        verdict = load_anti_goodhart_verdict(run_id)
    except Exception as exc:
        return False, f"ANTI_GOODHART_MISMATCH:{exc}"
    if str(verdict.get("status", "")).upper() != "PASS":
        return False, "ANTI_GOODHART_MISMATCH:verdict_status_fail"
    return bool(verdict.get("anti_goodhart_triggered", False)), None


def _base_payload(run_id: str, experiment_id: str, blocked_by: list[str], decision_contract_version: str = "decision_contract_v1") -> dict[str, Any]:
    return {
        "run_id": run_id,
        "experiment_id": experiment_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "decision": "HOLD_NEED_DATA",
        "decision_contract_version": decision_contract_version,
        "blocked_by": sorted({b for b in blocked_by if b})[:20],
        "reasons": ["insufficient inputs for deterministic evaluation"],
        "assignment_status": "missing",
        "version": VERSION,
    }


def _to_md(payload: dict[str, Any]) -> str:
    lines = [
        f"# Experiment Evaluator: {payload.get('run_id')}",
        "",
        f"- decision: `{payload.get('decision')}`",
        f"- experiment_id: `{payload.get('experiment_id')}`",
        "",
        "## Blocked By",
    ]
    blocked = payload.get("blocked_by") if isinstance(payload.get("blocked_by"), list) else []
    if blocked:
        lines.extend([f"- {x}" for x in blocked])
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic experiment evaluator")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--domain-template", default="", help="Optional path to domain template JSON")
    args = parser.parse_args()
    set_domain_template_override(args.domain_template)

    run_id = args.run_id
    log_path = Path(f"data/logs/experiment_evaluator_{run_id}.log")
    out_json = Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")
    out_md = Path(f"data/agent_reports/{run_id}_experiment_evaluator.md")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        decision_contract = load_decision_contract()
        doctor, doctor_err = _load_json(Path(f"data/agent_reports/{run_id}_doctor_variance.json"))
        metrics_snapshot, metrics_err = _load_json(Path(f"data/metrics_snapshots/{run_id}.json"))
        exp_id = args.experiment_id.strip()
        if not exp_id and isinstance(metrics_snapshot, dict):
            run_cfg = metrics_snapshot.get("run_config", {}) if isinstance(metrics_snapshot.get("run_config"), dict) else {}
            exp_id = str(run_cfg.get("experiment_id", "") or "").strip()
        ab, ab_err = (None, None)
        if exp_id:
            ab, ab_err = _load_json(Path(f"data/ab_reports/{run_id}_{exp_id}_ab.json"))

        blocked: list[str] = []
        if doctor_err:
            blocked.append(doctor_err)
        if metrics_err:
            blocked.append(metrics_err)
        if exp_id and ab_err:
            blocked.append(ab_err)

        if doctor is None or metrics_snapshot is None:
            payload = _base_payload(
                run_id,
                exp_id or "missing",
                blocked,
                str(decision_contract.get("version", "decision_contract_v1")),
            )
            payload["domain_template_path"] = domain_template_source()
        else:
            run_cfg = metrics_snapshot.get("run_config", {}) if isinstance(metrics_snapshot.get("run_config"), dict) else {}
            metrics = metrics_snapshot.get("metrics", {}) if isinstance(metrics_snapshot.get("metrics"), dict) else {}
            raw_assignment = str(run_cfg.get("assignment_status", doctor.get("assignment_status", "missing")) or "missing").strip().lower()
            assignment_ready = raw_assignment in {"present", "ready"}

            doctor_decision = str(doctor.get("normalized_decision", doctor.get("decision", "HOLD_NEED_DATA"))).upper()
            guardrails = _pick_guardrails(doctor)
            expected_direction = _pick_expected_direction(doctor)
            breaches = _guardrail_breach(metrics, guardrails)

            decision = doctor_decision if doctor_decision in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"} else "HOLD_NEED_DATA"
            reasons: list[str] = []
            anti_goodhart_triggered, anti_goodhart_err = _anti_goodhart_from_sot(run_id)
            if anti_goodhart_err:
                decision = "HOLD_NEED_DATA"
                blocked.append(anti_goodhart_err)

            if decision == "RUN_AB" and not assignment_ready:
                decision = "HOLD_NEED_DATA"
                blocked.append("assignment_missing")

            ab_status = str((ab or {}).get("status", "")).upper() if isinstance(ab, dict) else ""
            if ab_status in {"MISSING_ASSIGNMENT", "MISSING", "INVALID"}:
                assignment_ready = False
            if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and not ab_status:
                decision = "HOLD_NEED_DATA"
                blocked.append("missing_ab_report")
            elif ab_status in {"MISSING_ASSIGNMENT", "HOLD_NEED_DATA"}:
                decision = "HOLD_NEED_DATA"
                blocked.append("missing_assignment_log")
            elif ab_status == "METHODOLOGY_MISMATCH":
                decision = "STOP"
                blocked.append("measurement_blind_spot")
            elif ab_status == "INVALID_METHODS":
                decision = "HOLD_NEED_DATA"
                blocked.append("invalid_methods")
            elif ab_status == "ASSIGNMENT_RECOVERED":
                decision = "HOLD_RISK"
                blocked.append("assignment_recovered_post_hoc")
            elif ab_status == "UNDERPOWERED":
                decision = "HOLD_NEED_DATA"
                blocked.append("ab_underpowered")
            elif ab_status == "INCONCLUSIVE":
                decision = "HOLD_RISK"
                blocked.append("ab_inconclusive")
            elif ab_status == "HOLD_RISK":
                decision = "HOLD_RISK"
                blocked.append("ab_guardrail_or_srm_risk")

            if breaches:
                decision = "STOP"
                blocked.extend([f"guardrail_breach:{b}" for b in breaches])

            if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and anti_goodhart_triggered:
                decision = "STOP"
                blocked.append("goodhart_guardrail_violation")

            base_run_id = re.sub(r"_s\\d+$", "", run_id)
            ensemble_path = Path(f"data/ensemble_reports/{base_run_id}_ensemble.json")
            if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and ensemble_path.exists():
                ens, ens_err = _load_json(ensemble_path)
                if ens_err:
                    blocked.append("ensemble_summary_unreadable")
                elif isinstance(ens, dict) and bool(ens.get("stability_pass", True)) is False:
                    decision = "HOLD_RISK"
                    blocked.append("ensemble_stability_fail")

            if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and isinstance(ab, dict) and ab_status == "OK":
                crosses = _ab_ci_crosses_zero(ab)
                sign_ok = _ab_sign_matches_expected(ab, expected_direction)
                if crosses is True:
                    decision = "HOLD_RISK"
                    blocked.append("ci_crosses_zero")
                elif sign_ok is False:
                    decision = "HOLD_RISK"
                    blocked.append("unexpected_effect_direction")
                elif crosses is False and sign_ok is True:
                    decision = "ROLLOUT_CANDIDATE"

            reasons.extend(str(r.get("message", "")) for r in (doctor.get("reasons", []) if isinstance(doctor.get("reasons"), list) else []) if isinstance(r, dict))
            payload = {
                "run_id": run_id,
                "experiment_id": exp_id or "missing",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "decision": decision,
                "decision_contract_version": str(decision_contract.get("version", "decision_contract_v1")),
                "domain_template_path": domain_template_source(),
                "blocked_by": sorted({b for b in blocked if b})[:20],
                "ab_status": ab_status or "missing",
                "assignment_status": "ready" if assignment_ready else "missing",
                "guardrail_breaches": breaches,
                "expected_direction": expected_direction,
                "anti_goodhart_triggered": anti_goodhart_triggered,
                "reasons": reasons[:20],
                "version": VERSION,
            }

        validate_decision(str(payload.get("decision", "")), decision_contract, "decision")
        validate_required_fields(payload, decision_contract, "evaluator")
        safe_payload = _redact_obj(payload)
        out_json.write_text(json.dumps(safe_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(out_json)
        out_md.write_text(_redact_text(_to_md(safe_payload)), encoding="utf-8")
        print(f"ok: experiment_evaluator decision={safe_payload.get('decision')}")
    except ConfigurationError as exc:
        raise SystemExit(f"ConfigurationError: {exc}")
    except Exception:
        log_path.write_text(_redact_text(traceback.format_exc()), encoding="utf-8")
        payload = _base_payload(
            run_id,
            args.experiment_id.strip() or "missing",
            ["invalid_input:unexpected_error"],
        )
        payload["domain_template_path"] = domain_template_source()
        safe_payload = _redact_obj(payload)
        out_json.write_text(json.dumps(safe_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(out_json)
        out_md.write_text(_redact_text(_to_md(safe_payload)), encoding="utf-8")
        print(f"ok: experiment_evaluator decision={safe_payload.get('decision')} (fail-safe)")


if __name__ == "__main__":
    main()
