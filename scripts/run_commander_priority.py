#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import traceback
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.model_policy import COMMANDER_GROQ_FALLBACK_MODEL, COMMANDER_GROQ_PRIMARY_MODEL
from src.architecture_v3 import load_anti_goodhart_verdict, load_json_with_integrity
from src.decision_contract import load_decision_contract, validate_decision, validate_required_fields
from src.domain_template import (
    ConfigurationError,
    domain_goal_definitions,
    domain_goal_expected_direction,
    domain_guardrails_for,
    domain_target_metric_alias_to_goal,
    domain_template_source,
    set_domain_template_override,
)
from src.reasoning_feature_flags import load_reasoning_feature_flags
from src.llm_contract_utils import coerce_string, coerce_string_list, normalize_confidence_label, parse_json_object_loose
from src.runtime_failover import build_runtime_failover_tiers, generate_with_runtime_failover
from src.runtime_controls import get_retry_budget_status, load_retry_policy_contract, register_retry_outcome, write_retry_guard_report
from src.status_taxonomy import (
    AB_DECISION_INVALID_STATUSES,
    AB_METHOD_VALIDITY_ERROR_STATUSES,
    goal_from_metric,
    is_ab_decision_invalid,
    is_measurement_blocked,
)
from src.semantic_scoring import hypothesis_format_ok
from src.visible_reasoning_trace import build_visible_reasoning_trace_advisory
from src.security_utils import sha256_sidecar_path, write_sha256_sidecar

VERSION = "v1"
ENABLE_VISIBLE_REASONING_TRACE = 0
CAPTAIN_ALLOW_NOVEL_ISSUES = 0
DOCTOR_DYNAMIC_HYPOTHESES = 0
COMMANDER_SYSTEM_PROMPT_V2 = """SYSTEM: You are Commander Priority, a principal retail PM + decision scientist.
You own the final decision: STOP / HOLD_NEED_DATA / HOLD_RISK / RUN_AB / ROLLOUT_CANDIDATE.
Your job is to prevent bad or unmeasurable experiments and approve only defensible, high-value ones.

NON-NEGOTIABLE RULES
1) Never invent facts; use only provided artifacts and numeric fields.
2) Measurement is mandatory:
   If ab_status in {MISSING_ASSIGNMENT, METHODOLOGY_MISMATCH, INVALID_METHODS, ASSIGNMENT_RECOVERED} OR measurement_state in {UNOBSERVABLE, BLOCKED_BY_DATA}:
   - Decision cannot be RUN_AB or ROLLOUT_CANDIDATE.
   - Must output HOLD_NEED_DATA or STOP with "measurement_blind_spot".
3) Guardrails are hard constraints. Mandatory guardrails come from domain_template and must be enforced as hard ceilings/floors.
4) Goal alignment is mandatory: hypothesis_target_goal must match AB primary_metric goal; if mismatch => STOP ("goal_metric_misalignment").
5) Statistics consistency gate: contradictory p-value / CI => INCONCLUSIVE => HOLD_RISK.
6) JSON only, schema-valid.
"""
COMMANDER_DECISION_PROPOSAL_SYSTEM_PROMPT = """SYSTEM: You are Commander Priority (Decision Proposal Layer).
Produce a structured decision proposal from provided evidence. You do not bypass safety gates.

Rules:
- JSON only. No markdown.
- Use only provided fields.
- Be explicit about causal logic, evidence gaps, and human-in-the-loop checks.
- If evidence is unobservable/invalid, propose HOLD/STOP and explain why.
"""

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]

_RETRY_POLICY_CACHE: dict[str, Any] | None = None
HYPOTHESIS_REVIEW_STATUSES = {"SUPPORTED", "WEAK", "REFUTED", "UNTESTABLE"}
AGGRESSIVE_DECISIONS = {"GO", "RUN_AB", "ROLLOUT_CANDIDATE"}
DOCTOR_HYPOTHESIS_REVIEW_CONTRACT_PATH = Path("configs/contracts/doctor_hypothesis_review_v1.json")
_DOCTOR_HYPOTHESIS_REVIEW_CONTRACT_CACHE: dict[str, Any] | None = None


def _load_retry_policy_cached() -> dict[str, Any] | None:
    global _RETRY_POLICY_CACHE
    if _RETRY_POLICY_CACHE is not None:
        return _RETRY_POLICY_CACHE
    try:
        _RETRY_POLICY_CACHE = load_retry_policy_contract()
    except Exception:
        _RETRY_POLICY_CACHE = None
    return _RETRY_POLICY_CACHE


def _retry_budget_status(run_id: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    policy = _load_retry_policy_cached()
    if policy is None:
        return None, {"allowed": True, "reason": "retry_policy_unavailable", "state": {}}
    status = get_retry_budget_status(run_id, policy)
    return policy, status


def _record_retry_result(run_id: str, *, success: bool, reason: str) -> None:
    policy = _load_retry_policy_cached()
    if policy is None:
        return
    state = register_retry_outcome(run_id, policy, success=success, failure_reason=reason)
    write_retry_guard_report(
        run_id,
        status="PASS" if success else "FAIL",
        reason=("ok:run_commander_priority" if success else f"{reason}:run_commander_priority"),
        retry_policy=policy,
        state=state,
    )


def _active_feature_flags() -> dict[str, int]:
    return load_reasoning_feature_flags(
        {
            "ENABLE_VISIBLE_REASONING_TRACE": ENABLE_VISIBLE_REASONING_TRACE,
            "CAPTAIN_ALLOW_NOVEL_ISSUES": CAPTAIN_ALLOW_NOVEL_ISSUES,
            "DOCTOR_DYNAMIC_HYPOTHESES": DOCTOR_DYNAMIC_HYPOTHESES,
        }
    )


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


def _try_load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, f"missing_input:{path}"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except Exception:
        return None, f"invalid_input:{path}"


def _pick_mean_activity_proxy(row: dict[str, Any], *, primary_proxy_key: str) -> Any:
    explicit = row.get("mean_activity_proxy")
    if explicit is not None:
        return explicit
    if primary_proxy_key and primary_proxy_key in row:
        return row.get(primary_proxy_key)

    candidates: list[tuple[str, Any]] = []
    for key, value in row.items():
        key_s = str(key)
        if not key_s.startswith("mean_"):
            continue
        if key_s in {"mean_primary_metric_proxy", "mean_reference_metric"}:
            continue
        if key_s.endswith(("_cnt", "_count", "_units")) or "volume" in key_s:
            candidates.append((key_s, value))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def _pick_mean_reference_metric(row: dict[str, Any], *, primary_proxy_key: str) -> Any:
    explicit = row.get("mean_reference_metric")
    if explicit is not None:
        return explicit
    if primary_proxy_key and primary_proxy_key in row:
        return row.get(primary_proxy_key)
    return row.get("mean_primary_metric_proxy")


def _anti_goodhart_from_sot(run_id: str) -> tuple[bool, str | None]:
    try:
        verdict = load_anti_goodhart_verdict(run_id)
    except Exception as exc:
        return False, f"ANTI_GOODHART_MISMATCH:{exc}"
    if str(verdict.get("status", "")).upper() != "PASS":
        return False, "ANTI_GOODHART_MISMATCH:verdict_status_fail"
    return bool(verdict.get("anti_goodhart_triggered", False)), None


def _load_cohort_analysis_for_commander(run_id: str, doctor_context: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = doctor_context
    path = Path(f"reports/L1_ops/{run_id}/cohort_evidence_pack.json")
    doc, err = _try_load_json(path)
    if err or not isinstance(doc, dict):
        return {
            "status": "BLOCKED_BY_DATA",
            "cuts": [],
            "notes": [f"cohort_evidence_pack unavailable ({err or 'invalid'})"],
            "source": str(path),
        }

    status = str(doc.get("status", "BLOCKED_BY_DATA") or "BLOCKED_BY_DATA").upper()
    notes = [str(x) for x in (doc.get("notes", []) if isinstance(doc.get("notes"), list) else []) if str(x).strip()][:8]
    if status != "READY":
        extra = []
        if doc.get("error_code"):
            extra.append(f"cohort_pack_error_code:{doc.get('error_code')}")
        if doc.get("error_family"):
            extra.append(f"cohort_pack_error_family:{doc.get('error_family')}")
        return {
            "status": "BLOCKED_BY_DATA" if status in {"BLOCKED_BY_DATA", "FAIL"} else status,
            "cuts": [],
            "notes": notes + extra,
            "source": str(path),
        }

    cuts_in = doc.get("cuts", []) if isinstance(doc.get("cuts"), list) else []
    cuts: list[dict[str, Any]] = []
    for cut in cuts_in:
        if not isinstance(cut, dict):
            continue
        rows = cut.get("rows", []) if isinstance(cut.get("rows"), list) else []
        rows_slim = []
        goal_defaults = _goal_defaults()
        proxy_metric = goal_defaults[1][1] if len(goal_defaults) > 1 else goal_defaults[0][1]
        proxy_key = f"mean_{proxy_metric}_proxy"
        for r in rows[:8]:
            if not isinstance(r, dict):
                continue
            rows_slim.append(
                {
                    "bucket": r.get("bucket"),
                    "arm": r.get("arm"),
                    "n_customers": r.get("n_customers"),
                    "mean_reference_metric": _pick_mean_reference_metric(r, primary_proxy_key=proxy_key),
                    "mean_activity_proxy": _pick_mean_activity_proxy(r, primary_proxy_key=proxy_key),
                    "mean_primary_metric_proxy": r.get("mean_primary_metric_proxy", r.get(proxy_key)),
                }
            )
        cuts.append(
            {
                "cut_name": cut.get("cut_name"),
                "bucket_definition": cut.get("bucket_definition"),
                "row_count": len(rows),
                "summary": (cut.get("summary") if isinstance(cut.get("summary"), dict) else {}),
                "sample_rows": rows_slim,
            }
        )

    qprov = doc.get("query_provenance") if isinstance(doc.get("query_provenance"), dict) else {}
    pack_notes = list(notes)
    if isinstance(qprov, dict):
        if qprov.get("customer_id_source"):
            pack_notes.append(f"customer_id_source:{qprov.get('customer_id_source')}")
        if qprov.get("used_raw_join_for_customer_id") is True:
            pack_notes.append("customer_id_derived_via_raw_join")

    return {
        "status": "READY" if cuts else "BLOCKED_BY_DATA",
        "cuts": cuts,
        "notes": pack_notes[:12] if cuts else (pack_notes[:12] + ["cohort_pack_ready_but_no_rows"]),
        "source": str(path),
    }


def _count_dq(rows: list[dict[str, Any]]) -> tuple[int, int]:
    fail_count = 0
    warn_count = 0
    for row in rows:
        status = str(row.get("status", ""))
        if status == "FAIL":
            fail_count += 1
        elif status == "WARN":
            warn_count += 1
    return fail_count, warn_count


def _map_doctor_decision(raw_decision: str | None) -> tuple[str, str]:
    if raw_decision is None:
        return "HOLD_NEED_DATA", "unknown"
    val = str(raw_decision).upper().strip()
    if val in {"STOP"}:
        return "STOP", "STOP"
    if val in {"RUN_AB", "ROLLOUT_CANDIDATE", "HOLD_NEED_DATA", "HOLD_RISK"}:
        return val, val
    if val in {"GO"}:
        return "RUN_AB", "RUN_AB"
    if val in {"HOLD"}:
        return "HOLD_NEED_DATA", "HOLD_NEED_DATA"
    return "HOLD_NEED_DATA", "unknown"


def _map_evaluator_decision(raw_decision: str | None) -> tuple[str, str]:
    if raw_decision is None:
        return "HOLD_NEED_DATA", "unknown"
    val = str(raw_decision).upper().strip()
    if val in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}:
        return val, val
    return "HOLD_NEED_DATA", "unknown"


def _pick_doctor_experiment(doctor: dict[str, Any]) -> dict[str, Any] | None:
    candidates: list[dict[str, Any]] = []
    for key in ("recommended_experiments", "next_experiment", "experiments", "ab_plan"):
        value = doctor.get(key)
        if isinstance(value, list) and value and isinstance(value[0], dict):
            candidates.extend([x for x in value if isinstance(x, dict)])
        if isinstance(value, dict):
            candidates.append(value)
    if not candidates:
        return None
    def _priority_score(exp: dict[str, Any]) -> float:
        try:
            impact = float(exp.get("estimated_impact", 0) or 0)
            conf_raw = str(exp.get("confidence", "")).strip().lower()
            confidence = {"high": 0.8, "med": 0.5, "low": 0.3}.get(conf_raw, 0.0)
            # Legacy field is "ease" (higher=better). Convert to effort proxy.
            ease = max(1.0, min(10.0, float(exp.get("ease", 5) or 5)))
            effort = max(1.0, 11.0 - ease)
            return round(impact * confidence / effort, 4)
        except Exception:
            return 0.0

    ranked = sorted(candidates, key=_priority_score, reverse=True)
    top = dict(ranked[0])
    top["priority_score"] = _priority_score(top)
    return top


def _coerce_scope(value: Any) -> list[str]:
    if isinstance(value, list):
        out = [str(x) for x in value if str(x).strip()]
        return out if out else ["all"]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return ["all"]


def _build_next_experiment(doctor: dict[str, Any], decision: str, start_date: date) -> dict[str, Any] | None:
    if decision not in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
        return None
    base = _pick_doctor_experiment(doctor)
    if base is None:
        return None
    success_metrics = base.get("success_metrics", doctor.get("success_metrics", []))
    guardrails = base.get("guardrails", doctor.get("guardrails", []))
    if not isinstance(success_metrics, list):
        success_metrics = []
    if not isinstance(guardrails, list):
        guardrails = []
    rollback_guardrail = next(
        (
            str(g.get("metric", "")).strip()
            for g in guardrails
            if isinstance(g, dict) and str(g.get("metric", "")).strip()
        ),
        "",
    )
    rollback_line = (
        f"{rollback_guardrail} breaches configured threshold versus baseline"
        if rollback_guardrail
        else "configured guardrail breaches threshold versus baseline"
    )
    return {
        "name": str(base.get("name", "pm_safe_experiment_v1")),
        "priority_score": base.get("priority_score"),
        "goal": str(base.get("goal", "Improve KPI trajectory while preserving guardrails")),
        "lever_type": str(base.get("lever_type", "bundle")),
        "unit": str(base.get("unit", "customer")),
        "scope": _coerce_scope(base.get("scope", ["all"])),
        "start_date": start_date.isoformat(),
        "duration_days": 14,
        "freeze_window_days": 14,
        "success_metrics": [str(x) for x in success_metrics][:5],
        "guardrails": [str(x) for x in guardrails][:5],
        "rollout_criteria": [
            "success metrics improve versus baseline",
            "guardrails stay stable through experiment window",
        ],
        "rollback_criteria": [
            "any guardrail breach occurs",
            rollback_line,
        ],
        "interference": {
            "risk_level": "low",
            "conflicts": [],
        },
    }


def _doctor_hypothesis_valid(doctor: dict[str, Any]) -> tuple[bool, str | None]:
    exp = _pick_doctor_experiment(doctor)
    if not isinstance(exp, dict):
        return False, "missing_hypothesis"
    hypotheses = exp.get("hypotheses")
    if not isinstance(hypotheses, list) or not hypotheses:
        return False, "missing_hypothesis"
    h0 = hypotheses[0] if isinstance(hypotheses[0], dict) else {}
    statement = str(h0.get("hypothesis_statement", "")).strip()
    if not statement:
        return False, "missing_hypothesis"
    if not hypothesis_format_ok(statement):
        return False, "bad_hypothesis_format"
    if not str(h0.get("expected_effect_range", "")).strip():
        return False, "missing_hypothesis"
    if not str(h0.get("analysis_method", "")).strip():
        return False, "missing_methodology"
    if not str(exp.get("methodology", "")).strip():
        return False, "missing_methodology"
    sample_gate = exp.get("sample_size_gate")
    if not isinstance(sample_gate, dict):
        return False, "missing_sample_size_gate"
    if int(sample_gate.get("min_orders", 0) or 0) <= 0 or int(sample_gate.get("min_units", 0) or 0) <= 0:
        return False, "missing_sample_size_gate"
    try:
        if float(exp.get("mde", 0) or 0) <= 0:
            return False, "missing_mde"
        cl = float(exp.get("confidence_level", 0) or 0)
        if cl <= 0 or cl >= 1:
            return False, "missing_confidence_level"
        if int(exp.get("min_sample_size", 0) or 0) <= 0:
            return False, "missing_min_sample_size"
    except Exception:
        return False, "missing_evidence_fields"
    return True, None


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except Exception:
        return None


def _scope_overlap(a_scope: list[str], b_scope: list[str]) -> bool:
    a = {x.strip() for x in a_scope if x.strip()}
    b = {x.strip() for x in b_scope if x.strip()}
    if not a:
        a = {"all"}
    if not b:
        b = {"all"}
    if "all" in a or "all" in b:
        return True
    return len(a & b) > 0


def _window_overlap(start_a: date, days_a: int, start_b: date, days_b: int) -> bool:
    end_a = start_a + timedelta(days=max(1, int(days_a)) - 1)
    end_b = start_b + timedelta(days=max(1, int(days_b)) - 1)
    return max(start_a, start_b) <= min(end_a, end_b)


def _apply_interference(next_exp: dict[str, Any] | None, active_experiments: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, list[str]]:
    if next_exp is None:
        return None, []
    conflicts: list[dict[str, Any]] = []
    high_hits = 0
    medium_hits = 0
    blocked: list[str] = []

    n_unit = str(next_exp.get("unit", ""))
    n_lever = str(next_exp.get("lever_type", ""))
    n_scope = _coerce_scope(next_exp.get("scope", ["all"]))
    n_start = _parse_date(next_exp.get("start_date"))
    n_days = int(next_exp.get("duration_days", 14)) + int(next_exp.get("freeze_window_days", 14))
    if n_start is None:
        n_start = datetime.now(timezone.utc).date()

    for exp in active_experiments:
        if not isinstance(exp, dict):
            continue
        overlap_keys: list[str] = []
        if str(exp.get("unit", "")) == n_unit:
            overlap_keys.append("unit")
        if str(exp.get("lever_type", "")) == n_lever:
            overlap_keys.append("lever_type")
        if _scope_overlap(n_scope, _coerce_scope(exp.get("scope", ["all"]))):
            overlap_keys.append("scope")

        if len(overlap_keys) < 3:
            continue

        e_start = _parse_date(exp.get("start_date"))
        e_days_raw = exp.get("duration_days", 14)
        try:
            e_days = int(e_days_raw)
        except Exception:
            e_days = 14

        if e_start is None:
            # unknown window: medium risk by policy
            medium_hits += 1
            conflicts.append(
                {
                    "with_experiment": str(exp.get("name", "unknown")),
                    "reason": "window_unknown",
                    "overlap_keys": overlap_keys + ["window"],
                }
            )
            continue

        if _window_overlap(n_start, n_days, e_start, e_days):
            overlap_keys.append("window")
            high_hits += 1
            conflicts.append(
                {
                    "with_experiment": str(exp.get("name", "unknown")),
                    "reason": "unit+lever+scope+window overlap",
                    "overlap_keys": overlap_keys,
                }
            )

    risk_level = "low"
    if high_hits > 0:
        risk_level = "high"
        blocked.append("interference_high")
    elif medium_hits > 0:
        risk_level = "medium"
    next_exp["interference"] = {"risk_level": risk_level, "conflicts": conflicts}
    return next_exp, blocked


def _collect_blocked_by(
    doctor: dict[str, Any] | None,
    captain: dict[str, Any] | None,
    pre_blocked: list[str],
) -> list[str]:
    out = list(pre_blocked)
    if doctor:
        reasons = doctor.get("reasons", [])
        if isinstance(reasons, list):
            for r in reasons:
                if isinstance(r, dict):
                    code = str(r.get("code", "")).strip()
                    msg = str(r.get("message", "")).strip()
                    if code or msg:
                        out.append(f"{code}: {msg}".strip(": "))
        extra = doctor.get("blocked_by", [])
        if isinstance(extra, list):
            out.extend(str(x) for x in extra if str(x).strip())
    if captain:
        result = captain.get("result", {})
        verdict = str(result.get("verdict", ""))
        if verdict in {"WARN", "FAIL"}:
            issues = result.get("issues", [])
            if isinstance(issues, list):
                for issue in issues:
                    if isinstance(issue, dict):
                        chk = str(issue.get("check_name", "")).strip()
                        if chk:
                            out.append(f"captain:{chk}")
    # stable unique, sorted, capped
    uniq = sorted({x for x in out if x})
    return uniq[:20]


def _top_priorities(decision: str, blocked_by: list[str], next_exp: dict[str, Any] | None) -> list[dict[str, Any]]:
    if decision == "STOP":
        return [
            {"title": "Stop rollout and resolve blockers", "rationale": "Doctor decision is STOP", "eta_days": 14},
            {"title": "Stabilize data quality and guardrails", "rationale": "; ".join(blocked_by[:2]) if blocked_by else "Critical blockers detected", "eta_days": 14},
            {"title": "Re-baseline after fixes", "rationale": "Need clean baseline before new PM rollout", "eta_days": 14},
        ]
    if decision in {"HOLD_NEED_DATA", "HOLD_RISK"}:
        return [
            {"title": "Address HOLD blockers", "rationale": "; ".join(blocked_by[:2]) if blocked_by else "Hold conditions present", "eta_days": 14},
            {"title": "Prepare staged release criteria", "rationale": "Define GO conditions clearly", "eta_days": 14},
            {"title": "Run controlled follow-up", "rationale": "Re-evaluate after blockers are resolved", "eta_days": 14},
        ]
    exp_name = str(next_exp.get("name", "next_experiment")) if isinstance(next_exp, dict) else "next_experiment"
    return [
        {"title": f"Launch {exp_name}", "rationale": "Doctor indicates GO; proceed with guardrails", "eta_days": 14},
        {"title": "Monitor guardrails daily", "rationale": "Prevent regressions during experiment", "eta_days": 14},
        {"title": "Prepare rollout decision pack", "rationale": "Compile evidence for scale-up decision", "eta_days": 14},
    ]


def _fallback_bullets(payload: dict[str, Any]) -> list[str]:
    s = payload["inputs_summary"]
    out = [
        f"Decision for this cycle: {payload['decision']}.",
        f"Inputs: captain_verdict={s['captain_verdict']}, doctor_decision={s['doctor_decision']}.",
        f"DQ status summary: fail={s['dq_fail_count']}, warn={s['dq_warn_count']}.",
        "Prioritize guardrail stability before scaling rollout.",
    ]
    if payload["blocked_by"]:
        out.append("Primary blockers: " + "; ".join(payload["blocked_by"][:2]) + ".")
    if payload.get("next_experiment"):
        exp = payload["next_experiment"]
        out.append(f"Planned experiment window: {exp['duration_days']}d + freeze {exp['freeze_window_days']}d.")
        if exp.get("interference", {}).get("risk_level") == "high":
            out.append("Interference risk is high: sequence experiments, do not parallelize.")
    out.append("Review end-of-window metrics and decide GO/HOLD/STOP for next cycle.")
    return out[:7]


def _llm_bullets(payload: dict[str, Any], backend_name: str) -> list[str]:
    run_id = str(payload.get("run_id", "")).strip()
    policy, status = _retry_budget_status(run_id)
    if policy is not None and not bool(status.get("allowed", False)):
        write_retry_guard_report(
            run_id,
            status="FAIL",
            reason=f"{status.get('reason', 'retry_policy_blocked')}:commander_bullets",
            retry_policy=policy,
            state=(status.get("state") if isinstance(status.get("state"), dict) else {}),
        )
        return _fallback_bullets(payload)
    if os.getenv("LLM_ALLOW_REMOTE", "0") != "1":
        return _fallback_bullets(payload)
    prompt = (
        "Write 5-7 concise PM weekly bullets from this JSON. "
        "Do not alter decision or invent experiments. Bullets only.\n"
        + json.dumps(
            {
                "decision": payload["decision"],
                "inputs_summary": payload["inputs_summary"],
                "blocked_by": payload["blocked_by"],
                "top_priorities": payload["top_priorities"],
                "next_experiment": payload["next_experiment"],
            },
            ensure_ascii=False,
        )
    )
    try:
        groq_candidates = [COMMANDER_GROQ_PRIMARY_MODEL, COMMANDER_GROQ_FALLBACK_MODEL]
        tiers = build_runtime_failover_tiers(
            backend_requested=backend_name,
            groq_models=[str(x).strip() for x in groq_candidates if str(x).strip()],
            include_ollama=True,
        )
        raw, _ = generate_with_runtime_failover(
            run_id=run_id or "unknown_run",
            agent_name="commander",
            call_name="weekly_bullets",
            prompt=prompt,
            system_prompt="You are a concise product manager.",
            tiers=tiers,
            deterministic_generator=lambda: "\n".join(f"- {x}" for x in _fallback_bullets(payload)),
        )
    except Exception:
        if run_id:
            _record_retry_result(run_id, success=False, reason="commander_bullets_runtime_error")
        return _fallback_bullets(payload)
    lines: list[str] = []
    for line in raw.splitlines():
        txt = line.strip().lstrip("-").strip()
        if txt:
            lines.append(txt)
    if len(lines) < 5:
        if run_id:
            _record_retry_result(run_id, success=False, reason="commander_bullets_underfilled")
        return _fallback_bullets(payload)
    if run_id:
        _record_retry_result(run_id, success=True, reason="commander_bullets_ok")
    return lines[:7]


def _validate_commander_llm_proposal(obj: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    alias_map = {
        "rationale": "decision_rationale",
        "reasoning": "decision_rationale",
        "why": "decision_rationale",
        "requested_data_items": "requested_data",
        "data_requests": "requested_data",
        "confidence_level": "confidence",
        "confidence_score": "confidence",
        "causal_chain": "causal_chain_summary",
        "change_my_mind": "what_would_change_my_mind",
    }
    norm_obj: dict[str, Any] = dict(obj)
    repair_actions: list[str] = []
    for src_key, dst_key in alias_map.items():
        if dst_key not in norm_obj and src_key in norm_obj:
            norm_obj[dst_key] = norm_obj[src_key]
            repair_actions.append(f"alias:{src_key}->{dst_key}")

    issues: list[str] = []
    proposed_decision = str(norm_obj.get("proposed_decision", "")).strip().upper()
    if proposed_decision not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}:
        issues.append("invalid_proposed_decision")
    rationale = coerce_string(norm_obj.get("decision_rationale", ""), max_len=1000)
    if not rationale:
        issues.append("missing_decision_rationale")
    if not isinstance(norm_obj.get("causal_chain_summary", []), list):
        repair_actions.append("coerced:causal_chain_summary_to_list")
    causal = coerce_string_list(norm_obj.get("causal_chain_summary", []), max_items=6)
    if not causal:
        issues.append("missing_causal_chain_summary")
    if not isinstance(norm_obj.get("human_loop_checks", []), list):
        repair_actions.append("coerced:human_loop_checks_to_list")
    human_checks = coerce_string_list(norm_obj.get("human_loop_checks", []), max_items=6)
    if not isinstance(norm_obj.get("what_would_change_my_mind", []), list):
        repair_actions.append("coerced:what_would_change_my_mind_to_list")
    change_mind = coerce_string_list(norm_obj.get("what_would_change_my_mind", []), max_items=6)
    if not isinstance(norm_obj.get("requested_data", []), list):
        repair_actions.append("coerced:requested_data_to_list")
    requested_data = coerce_string_list(norm_obj.get("requested_data", []), max_items=8)
    confidence_raw = norm_obj.get("confidence", "")
    confidence = normalize_confidence_label(confidence_raw, default="medium")
    if str(confidence_raw).strip() and str(confidence_raw).strip().lower() not in {"low", "medium", "high"}:
        repair_actions.append("normalized:confidence_label")
    if issues:
        return None, issues
    out = {
        "proposed_decision": proposed_decision,
        "decision_rationale": rationale,
        "causal_chain_summary": causal,
        "human_loop_checks": human_checks,
        "what_would_change_my_mind": change_mind,
        "requested_data": requested_data,
        "confidence": confidence or "medium",
    }
    if repair_actions:
        out["_repair_actions"] = repair_actions[:12]
    return out, []


def _commander_llm_input(payload: dict[str, Any]) -> dict[str, Any]:
    methodology = payload.get("methodology_check", {}) if isinstance(payload.get("methodology_check"), dict) else {}
    goals = payload.get("goals", []) if isinstance(payload.get("goals"), list) else []
    top_goals = []
    for g in goals[:3]:
        if not isinstance(g, dict):
            continue
        top_goals.append(
            {
                "goal_id": g.get("goal_id"),
                "primary_metric": g.get("primary_metric"),
                "target_status": g.get("target_status"),
                "expected_impact_range": g.get("expected_impact_range"),
                "expected_impact_accepted": g.get("expected_impact_accepted"),
                "expected_impact_changed": g.get("expected_impact_changed"),
                "correction_reason": g.get("correction_reason"),
            }
        )
    return {
        "run_id": payload.get("run_id"),
        "top_reasons": (payload.get("top_reasons", []) if isinstance(payload.get("top_reasons"), list) else [])[:6],
        "blocked_by": (payload.get("blocked_by", []) if isinstance(payload.get("blocked_by"), list) else [])[:10],
        "inputs_summary": payload.get("inputs_summary", {}),
        "methodology_check": {
            "ab_status": methodology.get("ab_status"),
            "measurement_state": methodology.get("measurement_state"),
            "goal_metric_alignment_ok": methodology.get("goal_metric_alignment_ok"),
            "unit_alignment_ok": methodology.get("unit_alignment_ok"),
            "stats_consistent": methodology.get("stats_consistent"),
            "decision_rule_result": methodology.get("decision_rule_result"),
            "underpowered": methodology.get("underpowered"),
            "sample_size_imbalance": methodology.get("sample_size_imbalance"),
            "errors": methodology.get("errors", []),
        },
        "goals": top_goals,
        "cohort_analysis": {
            "status": ((payload.get("cohort_analysis") or {}).get("status") if isinstance(payload.get("cohort_analysis"), dict) else None),
            "notes": (((payload.get("cohort_analysis") or {}).get("notes")) if isinstance(payload.get("cohort_analysis"), dict) else []),
        },
        "next_experiment": payload.get("next_experiment"),
        "data_requests_count": len(payload.get("data_requests", []) if isinstance(payload.get("data_requests"), list) else []),
        "decision_options": ["STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"],
        "safety_constraints": {
            "measurement_blind_spot_ceiling": True,
            "goal_metric_misalignment_forces_stop": True,
            "guardrails_hard_constraints": True,
        },
    }


def _commander_llm_decision_proposal(payload: dict[str, Any], backend_name: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    run_id = str(payload.get("run_id", "")).strip()
    remote_allowed = os.getenv("LLM_ALLOW_REMOTE", "0") == "1"
    provenance: dict[str, Any] = {
        "enabled": True,
        "backend_requested": backend_name,
        "remote_allowed": remote_allowed,
        "model": None,
        "used_fallback": False,
        "fallback_reason": None,
        "fallback_tier": "none",
        "provisional_local_fallback": False,
        "needs_cloud_reconciliation": False,
        "validation_issues": [],
        "repair_actions": [],
    }
    policy, status = _retry_budget_status(run_id)
    if policy is not None and not bool(status.get("allowed", False)):
        provenance["used_fallback"] = True
        provenance["fallback_reason"] = f"retry_policy_blocked:{status.get('reason', 'retry_policy_blocked')}"
        write_retry_guard_report(
            run_id,
            status="FAIL",
            reason=f"{status.get('reason', 'retry_policy_blocked')}:commander_decision_proposal",
            retry_policy=policy,
            state=(status.get("state") if isinstance(status.get("state"), dict) else {}),
        )
        return None, provenance
    prompt = (
        "Return one JSON object with keys exactly: "
        "proposed_decision, decision_rationale, causal_chain_summary, human_loop_checks, "
        "what_would_change_my_mind, requested_data, confidence.\n"
        "Use short concrete text. Do not include markdown.\n\n"
        + json.dumps(_commander_llm_input(payload), ensure_ascii=False)
    )
    try:
        groq_candidates = [COMMANDER_GROQ_PRIMARY_MODEL, COMMANDER_GROQ_FALLBACK_MODEL]
        tiers = build_runtime_failover_tiers(
            backend_requested=backend_name,
            groq_models=[str(x).strip() for x in groq_candidates if str(x).strip()],
            include_ollama=True,
        )
        raw, gen_meta = generate_with_runtime_failover(
            run_id=run_id or "unknown_run",
            agent_name="commander",
            call_name="decision_proposal",
            prompt=prompt,
            system_prompt=COMMANDER_DECISION_PROPOSAL_SYSTEM_PROMPT,
            tiers=tiers,
            deterministic_generator=lambda: json.dumps(
                {
                    "proposed_decision": "HOLD_NEED_DATA",
                    "decision_rationale": "Deterministic failover due to unavailable cloud/local LLM tiers.",
                    "causal_chain_summary": ["LLM failover exhausted; deterministic safety policy selected HOLD_NEED_DATA."],
                    "human_loop_checks": ["Review fallback telemetry and reconcile with cloud as soon as available."],
                    "what_would_change_my_mind": ["Successful cloud reconciliation with consistent evidence."],
                    "requested_data": ["cloud_reconciliation_result"],
                    "confidence": "low",
                },
                ensure_ascii=False,
            ),
        )
        provenance["model"] = str(gen_meta.get("model", "")).strip() or None
        provenance["used_fallback"] = bool(gen_meta.get("used_fallback", False))
        provenance["fallback_reason"] = str(gen_meta.get("fallback_reason", "")).strip() or None
        provenance["fallback_tier"] = str(gen_meta.get("fallback_tier", "none") or "none")
        provenance["provisional_local_fallback"] = bool(gen_meta.get("provisional_local_fallback", False))
        provenance["needs_cloud_reconciliation"] = bool(gen_meta.get("needs_cloud_reconciliation", False))
        if isinstance(gen_meta.get("attempts"), list):
            provenance["runtime_failover_attempts"] = [x for x in gen_meta.get("attempts", []) if isinstance(x, dict)][:12]
        map_ref = str(gen_meta.get("obfuscation_map_ref", "")).strip()
        if map_ref:
            provenance["obfuscation_map_ref"] = map_ref
        parsed = parse_json_object_loose(raw)
        if not isinstance(parsed, dict):
            provenance["used_fallback"] = True
            provenance["fallback_reason"] = "llm_non_json"
            if run_id:
                _record_retry_result(run_id, success=False, reason="commander_non_json")
            return None, provenance
        validated, issues = _validate_commander_llm_proposal(parsed)
        if validated is None:
            provenance["used_fallback"] = True
            provenance["fallback_reason"] = "llm_invalid_json_schema"
            provenance["validation_issues"] = issues
            if run_id:
                _record_retry_result(run_id, success=False, reason="commander_invalid_json_schema")
            return None, provenance
        if isinstance(validated.get("_repair_actions"), list):
            provenance["repair_actions"] = [str(x) for x in validated.get("_repair_actions", []) if str(x).strip()][:12]
            validated = dict(validated)
            validated.pop("_repair_actions", None)
        if run_id:
            _record_retry_result(run_id, success=True, reason="commander_decision_proposal_ok")
        return validated, provenance
    except Exception as exc:
        provenance["used_fallback"] = True
        provenance["fallback_reason"] = f"llm_runtime_error:{str(exc).splitlines()[0][:160]}"
        if run_id:
            _record_retry_result(run_id, success=False, reason="commander_llm_runtime_error")
        return None, provenance


def _attach_commander_llm_reasoning(payload: dict[str, Any], backend_name: str) -> None:
    proposal, prov = _commander_llm_decision_proposal(payload, backend_name)
    final_dec = str(payload.get("normalized_decision", payload.get("decision", "unknown"))).upper()
    payload["llm_decision_provenance"] = prov
    payload["commander_model"] = prov.get("model")
    payload["llm_decision_proposal"] = proposal
    payload["llm_decision_alignment"] = {
        "final_decision": final_dec,
        "llm_proposed_decision": (proposal or {}).get("proposed_decision") if isinstance(proposal, dict) else None,
        "matches_final": bool(isinstance(proposal, dict) and str(proposal.get("proposed_decision", "")).upper() == final_dec),
        "final_decision_authority": "deterministic_gates_then_human_in_the_loop",
        "notes": "LLM proposal is advisory until commander decision path is fully migrated to llm-propose + validator-finalize.",
    }
    if isinstance(proposal, dict):
        payload["llm_decision_trace"] = {
            "visible_reasoning_summary": {
                "rationale": proposal.get("decision_rationale"),
                "causal_chain_summary": proposal.get("causal_chain_summary", []),
                "human_loop_checks": proposal.get("human_loop_checks", []),
                "what_would_change_my_mind": proposal.get("what_would_change_my_mind", []),
                "requested_data": proposal.get("requested_data", []),
                "confidence": proposal.get("confidence"),
            },
            "evidence_snapshot_used": _commander_llm_input(payload),
        }
    else:
        payload["llm_decision_trace"] = {
            "visible_reasoning_summary": None,
            "evidence_snapshot_used": _commander_llm_input(payload),
        }


_COMMANDER_DECISION_CONSERVATISM = {
    "STOP": 0,
    "HOLD_NEED_DATA": 1,
    "HOLD_RISK": 2,
    "RUN_AB": 3,
    "ROLLOUT_CANDIDATE": 4,
}


def _apply_commander_llm_decision_merge(payload: dict[str, Any]) -> None:
    final_before = str(payload.get("normalized_decision", payload.get("decision", "HOLD_NEED_DATA"))).upper()
    llm_prop = payload.get("llm_decision_proposal", {}) if isinstance(payload.get("llm_decision_proposal"), dict) else {}
    llm_dec = str(llm_prop.get("proposed_decision", "")).upper().strip() if llm_prop else ""

    source = "deterministic_only"
    final_after = final_before
    notes: list[str] = []
    if llm_dec in _COMMANDER_DECISION_CONSERVATISM and final_before in _COMMANDER_DECISION_CONSERVATISM:
        if llm_dec == final_before:
            source = "llm_matches_deterministic"
        elif _COMMANDER_DECISION_CONSERVATISM[llm_dec] < _COMMANDER_DECISION_CONSERVATISM[final_before]:
            final_after = llm_dec
            source = "llm_more_conservative_accepted"
            notes.append("Accepted LLM proposal because it is more conservative than deterministic decision.")
        else:
            source = "llm_more_aggressive_rejected_by_gates"
            notes.append("Rejected LLM proposal because deterministic gates are final authority for safety.")
    elif llm_dec:
        source = "llm_invalid_or_missing_decision"
        notes.append("LLM proposal present but decision field is invalid/unrecognized.")

    payload["decision_merge_provenance"] = {
        "deterministic_decision_before_merge": final_before,
        "llm_proposed_decision": (llm_dec or None),
        "merge_source": source,
        "final_decision_after_merge": final_after,
        "safety_authority": "deterministic_gates_then_human_in_the_loop",
        "notes": notes,
    }

    payload["decision"] = final_after
    payload["normalized_decision"] = final_after

    if final_after not in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
        payload["next_experiment"] = None

    blocked_by = payload.get("blocked_by", []) if isinstance(payload.get("blocked_by"), list) else []
    payload["top_priorities"] = _top_priorities(final_after, blocked_by, payload.get("next_experiment"))

    align = payload.get("llm_decision_alignment", {}) if isinstance(payload.get("llm_decision_alignment"), dict) else {}
    align.update(
        {
            "final_decision_before_merge": final_before,
            "final_decision": final_after,
            "matches_final": bool(llm_dec and llm_dec == final_after),
            "merge_source": source,
        }
    )
    payload["llm_decision_alignment"] = align


def _build_commander_visible_reasoning_trace(payload: dict[str, Any], enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {"claims": [], "gates_checked": [], "unknowns": []}

    evidence_map = payload.get("evidence_refs", {}) if isinstance(payload.get("evidence_refs"), dict) else {}
    global_refs = [str(v).strip() for v in evidence_map.values() if str(v).strip()][:10]
    final_decision = str(payload.get("normalized_decision", payload.get("decision", "unknown"))).upper()

    claims: list[dict[str, Any]] = [
        {
            "claim_id": f"commander:{payload.get('run_id', 'unknown')}:final_decision",
            "statement": f"Final decision for this run is {final_decision}.",
            "evidence_refs": global_refs[:5],
            "alternatives_considered": ["STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"],
            "falsifiability_test": "Re-run commander after resolving blockers and compare if final decision changes.",
            "decision_impact": "Directly determines execution ceiling (STOP/HOLD/RUN_AB/ROLLOUT_CANDIDATE).",
        }
    ]
    blocked_by = payload.get("blocked_by", []) if isinstance(payload.get("blocked_by"), list) else []
    for idx, blocker in enumerate(blocked_by[:20], start=1):
        b = str(blocker).strip()
        if not b:
            continue
        claims.append(
            {
                "claim_id": f"commander:{payload.get('run_id', 'unknown')}:blocker:{idx}",
                "statement": f"Blocker detected: {b}",
                "evidence_refs": global_refs[:3],
                "alternatives_considered": ["address_blocker_then_re_evaluate", "retain_conservative_decision"],
                "falsifiability_test": f"Resolve blocker '{b}' and re-run commander; claim is rejected if blocker disappears.",
                "decision_impact": "Supports conservative decision and prevents aggressive rollout while blocker is active.",
            }
        )

    methodology = payload.get("methodology_check", {}) if isinstance(payload.get("methodology_check"), dict) else {}
    gates_checked: list[str] = []
    for key in ("unit_alignment_ok", "goal_metric_alignment_ok", "stats_consistent"):
        value = methodology.get(key)
        status = "PASS" if value is True else ("FAIL" if value is False else "UNKNOWN")
        gates_checked.append(f"{key}:{status} (methodology_check.{key}:{value})")
    measurement_state = str(methodology.get("measurement_state", "")).upper()
    ab_status = str(methodology.get("ab_status", "")).upper()
    blind_spot = is_measurement_blocked(measurement_state) or is_ab_decision_invalid(ab_status)
    gates_checked.append(
        "measurement_blind_spot_ceiling:"
        + ("PASS" if not blind_spot else "FAIL")
        + f" (measurement_state:{measurement_state},ab_status:{ab_status})"
    )
    gates_checked.append("advisory_reasoning_mode:PASS (decision_authority:deterministic_gates_then_human_in_the_loop)")

    unknowns: list[str] = []
    data_requests = payload.get("data_requests", []) if isinstance(payload.get("data_requests"), list) else []
    for req in data_requests[:20]:
        if not isinstance(req, dict):
            continue
        why = str(req.get("why", "")).strip()
        if why:
            unknowns.append(why)
    cohort = payload.get("cohort_analysis", {}) if isinstance(payload.get("cohort_analysis"), dict) else {}
    if str(cohort.get("status", "")).upper() == "BLOCKED_BY_DATA":
        unknowns.append("Cohort heterogeneity remains unknown until blocked data requests are resolved.")
    unknowns = sorted({u for u in unknowns if u})[:20]
    return {"claims": claims, "gates_checked": gates_checked, "unknowns": unknowns}


def _attach_phase_flags_and_visible_trace(payload: dict[str, Any]) -> None:
    feature_flags = _active_feature_flags()
    llm_prov = payload.get("llm_provenance", {}) if isinstance(payload.get("llm_provenance"), dict) else {}
    llm_prov["feature_flags"] = feature_flags
    llm_decision_prov = payload.get("llm_decision_provenance", {})
    if isinstance(llm_decision_prov, dict):
        llm_prov["decision_layer"] = llm_decision_prov
    hist = payload.get("historical_context", {}) if isinstance(payload.get("historical_context"), dict) else {}
    if hist:
        llm_prov["historical_context"] = {
            "used": bool(hist.get("used")),
            "pack_ref": str(hist.get("pack_ref", "")).strip() or None,
            "retrieved_rows": int(hist.get("retrieved_rows", 0) or 0),
        }
    trace, trace_meta = build_visible_reasoning_trace_advisory(
        enabled=bool(feature_flags.get("ENABLE_VISIBLE_REASONING_TRACE", 0)),
        trace_builder=lambda: _build_commander_visible_reasoning_trace(payload, enabled=True),
        trace_prefix=f"commander:{payload.get('run_id', 'unknown')}",
        redact_text=_redact_text,
    )
    llm_prov["visible_reasoning_trace"] = trace_meta
    payload["llm_provenance"] = llm_prov
    payload["visible_reasoning_trace"] = trace


def _to_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Commander Priority: {payload['run_id']}")
    lines.append("")
    lines.append(f"- decision: `{payload['decision']}`")
    lines.append(f"- version: `{payload['version']}`")
    lines.append("")
    lines.append("## Top Priorities")
    for p in payload["top_priorities"]:
        lines.append(f"- {p['title']} (eta_days={p['eta_days']}): {p['rationale']}")
    lines.append("")
    lines.append("## Blocked By")
    if payload["blocked_by"]:
        for b in payload["blocked_by"]:
            lines.append(f"- {b}")
    else:
        lines.append("- none")
    lines.append("")
    prov = payload.get("llm_decision_provenance", {}) if isinstance(payload.get("llm_decision_provenance"), dict) else {}
    llm_prop = payload.get("llm_decision_proposal", {}) if isinstance(payload.get("llm_decision_proposal"), dict) else {}
    lines.append("## Commander LLM Decision Layer")
    lines.append(f"- model: `{payload.get('commander_model')}`")
    lines.append(f"- backend_requested: `{prov.get('backend_requested')}`")
    lines.append(f"- remote_allowed: `{prov.get('remote_allowed')}`")
    lines.append(f"- used_fallback: `{prov.get('used_fallback')}`")
    if prov.get("fallback_reason"):
        lines.append(f"- fallback_reason: `{prov.get('fallback_reason')}`")
    if llm_prop:
        lines.append(f"- proposed_decision: `{llm_prop.get('proposed_decision')}`")
        lines.append(f"- confidence: `{llm_prop.get('confidence')}`")
        lines.append(f"- rationale: {llm_prop.get('decision_rationale')}")
        ccs = llm_prop.get("causal_chain_summary", []) if isinstance(llm_prop.get("causal_chain_summary"), list) else []
        if ccs:
            lines.append("- causal_chain_summary:")
            for item in ccs[:4]:
                lines.append(f"  - {item}")
        hlc = llm_prop.get("human_loop_checks", []) if isinstance(llm_prop.get("human_loop_checks"), list) else []
        if hlc:
            lines.append("- human_loop_checks:")
            for item in hlc[:4]:
                lines.append(f"  - {item}")
        wcm = llm_prop.get("what_would_change_my_mind", []) if isinstance(llm_prop.get("what_would_change_my_mind"), list) else []
        if wcm:
            lines.append("- what_would_change_my_mind:")
            for item in wcm[:4]:
                lines.append(f"  - {item}")
    align = payload.get("llm_decision_alignment", {}) if isinstance(payload.get("llm_decision_alignment"), dict) else {}
    if align:
        lines.append(f"- llm_vs_final_match: `{align.get('matches_final')}` (llm=`{align.get('llm_proposed_decision')}`, final=`{align.get('final_decision')}`)")
    merge = payload.get("decision_merge_provenance", {}) if isinstance(payload.get("decision_merge_provenance"), dict) else {}
    if merge:
        lines.append(f"- decision_merge_source: `{merge.get('merge_source')}`")
        if merge.get("notes"):
            for n in (merge.get("notes") if isinstance(merge.get("notes"), list) else [])[:3]:
                lines.append(f"- merge_note: {n}")
    lines.append("")
    lines.append("## Weekly Report Bullets")
    for b in payload["weekly_report_bullets"]:
        lines.append(f"- {b}")
    return "\n".join(lines)


def _base_run_id(run_id: str) -> str:
    return re.sub(r"_s\\d+$", "", run_id)


def _goal_from_target_metric(target_metric: str) -> str:
    alias_map = domain_target_metric_alias_to_goal()
    key = str(target_metric or "").strip()
    if key in alias_map:
        return alias_map[key]
    return goal_from_metric(key)


def _goal_defaults() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for row in domain_goal_definitions():
        goal_id = str(row.get("goal_id", "")).strip().lower()
        primary_metric = str(row.get("default_metric") or row.get("primary_metric") or "").strip()
        alias = str(row.get("target_metric_alias", "")).strip()
        if goal_id and primary_metric:
            rows.append((goal_id, primary_metric, alias))
    if rows:
        return rows
    raise ConfigurationError("Missing Domain Template goals")


def _resolve_guardrail_threshold(metric: str, raw_threshold: Any, metrics: dict[str, Any]) -> float:
    if isinstance(raw_threshold, (int, float)):
        return float(raw_threshold)
    text = str(raw_threshold or "").strip().lower()
    if text == "baseline*0.99":
        baseline = float(metrics.get(metric) or 0.0)
        return max(0.0, baseline * 0.99) if baseline > 0 else 0.0
    return 0.0


def _build_guardrails(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    rows = domain_guardrails_for("commander_priority")
    out: list[dict[str, Any]] = []
    for row in rows:
        metric = str(row.get("metric", "")).strip()
        op = str(row.get("op", "")).strip()
        if not metric or not op:
            continue
        out.append(
            {
                "metric": metric,
                "op": op,
                "threshold": _resolve_guardrail_threshold(metric, row.get("threshold"), metrics),
            }
        )
    if out:
        return out
    raise ConfigurationError("Missing Domain Template guardrails")


def _stop_conditions_from_guardrails(guardrails: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for row in guardrails:
        if not isinstance(row, dict):
            continue
        metric = str(row.get("metric", "")).strip()
        op = str(row.get("op", "")).strip()
        if not metric or op not in {">=", ">", "<=", "<"}:
            continue
        suffix = "below_threshold" if op in {">", ">="} else "above_threshold"
        out.append(f"{metric}_{suffix}")
    return out[:6]


def _base_hold_payload(run_id: str, blocked_by: list[str]) -> dict[str, Any]:
    base_methodology = {
        "ab_status": "MISSING",
        "measurement_state": "BLOCKED_BY_DATA",
        "unit_alignment_ok": False,
        "goal_metric_alignment_ok": False,
        "stats_consistent": False,
        "alpha": 0.05,
        "ci_level": 0.95,
        "sample_sizes": {"control": 0, "treatment": 0},
        "decision_rule_result": "NOT_APPLICABLE",
        "errors": ["missing_inputs"],
    }
    base_data_requests = _build_data_requests(run_id=run_id, methodology_check=base_methodology, cohort_blocked=True)
    base_goals = []
    for gid, metric, _alias in _goal_defaults():
        base_goals.append(
            {
                "goal_id": gid,
                "target_status": "SECONDARY",
                "primary_metric": metric,
                "success_metric": metric,
                "expected_impact_range": None,
                "expected_impact_accepted": False,
                "expected_impact_changed": False,
                "corrected_expected_impact_range": None,
                "guardrails": _build_guardrails({}),
                "evidence_refs": [],
            }
        )
    return {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "decision": "HOLD_NEED_DATA",
        "normalized_decision": "HOLD_NEED_DATA",
        "generated_by": "scripts/run_commander_priority.py",
        "contract_version": "commander_priority.v1",
        "decision_contract_version": "decision_contract_v1",
        "schema_version": "commander_priority_output.v1",
        "blocked_by": sorted({x for x in blocked_by if x})[:20],
        "top_priorities": [
            {"title": "Restore missing/invalid inputs", "rationale": "Commander requires complete validated artifacts", "eta_days": 14},
            {"title": "Re-run upstream pipeline steps", "rationale": "Need fresh DQ/Captain/Doctor/Metrics evidence", "eta_days": 14},
            {"title": "Re-evaluate PM roadmap", "rationale": "Decision can proceed only after evidence is complete", "eta_days": 14},
        ],
        "goals": base_goals,
        "methodology_check": base_methodology,
        "cohort_analysis": {"status": "BLOCKED_BY_DATA", "cuts": [], "notes": ["missing inputs"]},
        "top_reasons": sorted({x for x in blocked_by if x})[:5],
        "data_requests": base_data_requests,
        "next_experiment": None,
        "next_actions": [{"type": "measurement_fix_plan", "steps": ["Restore missing inputs", "Re-run upstream artifacts", "Re-run commander"]}],
        "weekly_report_bullets": [
            "Decision for this cycle: HOLD.",
            "Commander received incomplete or invalid inputs.",
            "Re-run upstream steps to regenerate required artifacts.",
            "Do not start a new experiment until evidence is complete.",
            "Re-evaluate PM roadmap after artifacts are restored.",
        ],
        "inputs_summary": {
            "captain_verdict": None,
            "doctor_decision": "unknown",
            "dq_fail_count": 0,
            "dq_warn_count": 0,
        },
        "prompt_profile": {"name": "commander_decision_scientist_v2", "system_prompt_embedded": True},
        "react_config": {
            "enabled": False,
            "max_steps": 4,
            "tool_policy": "read_only_json_md_csv",
            "forbidden": ["db_write", "file_write_outside_artifacts", "migrations"],
            "steps": ["Read Evidence", "Check Gates", "Reason", "Decide"],
        },
        "fallback_tier": "none",
        "fallback_reason": None,
        "provisional_local_fallback": False,
        "needs_cloud_reconciliation": False,
        "hypothesis_review_mode": "shadow",
        "doctor_hypothesis_review": [],
        "hypothesis_review_summary": {
            "total_count": 0,
            "supported_count": 0,
            "weak_count": 0,
            "refuted_count": 0,
            "untestable_count": 0,
            "refuted_high_count": 0,
            "verification_quality_score": 1.0,
        },
        "review_blockers": [],
        "evidence_refs": {},
        "version": VERSION,
        "domain_template_path": domain_template_source(),
    }


def _extract_top_portfolio_hypothesis(doctor: dict[str, Any]) -> dict[str, Any]:
    portfolio = doctor.get("hypothesis_portfolio", [])
    if not isinstance(portfolio, list):
        return {}
    rows = [h for h in portfolio if isinstance(h, dict)]
    if not rows:
        return {}
    rows.sort(key=lambda h: (int(h.get("rank", 9999)) if str(h.get("rank", "")).isdigit() else 9999, -float(h.get("ice_score", 0.0) or 0.0)))
    return rows[0]


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _normalize_review_status(value: Any) -> str:
    status = str(value or "").strip().upper()
    return status if status in HYPOTHESIS_REVIEW_STATUSES else "UNTESTABLE"


def _load_doctor_hypothesis_review_contract() -> dict[str, Any]:
    global _DOCTOR_HYPOTHESIS_REVIEW_CONTRACT_CACHE
    if _DOCTOR_HYPOTHESIS_REVIEW_CONTRACT_CACHE is not None:
        return _DOCTOR_HYPOTHESIS_REVIEW_CONTRACT_CACHE
    payload = load_json_with_integrity(DOCTOR_HYPOTHESIS_REVIEW_CONTRACT_PATH)
    if not isinstance(payload, dict):
        raise ValueError("HYPOTHESIS_REVIEW_INVALID_SCHEMA:contract_not_object")
    _DOCTOR_HYPOTHESIS_REVIEW_CONTRACT_CACHE = payload
    return payload


def _normalize_evidence_refs_for_review(raw_refs: Any) -> list[str]:
    refs: list[str] = []
    if not isinstance(raw_refs, list):
        return refs
    for row in raw_refs:
        if isinstance(row, str):
            txt = row.strip()
            if txt:
                refs.append(txt)
            continue
        if isinstance(row, dict):
            source = str(row.get("source", "")).strip()
            metric = str(row.get("metric", "")).strip()
            value = row.get("value", row.get("fact", row.get("baseline")))
            compact = f"{source}:{metric}:{value}"
            compact = compact.strip(":")
            if compact:
                refs.append(compact)
    return refs[:8]


def _parse_expected_range_for_review(raw_range: Any) -> tuple[int, float | None]:
    txt = str(raw_range or "").strip()
    if not txt:
        return 0, None
    nums: list[float] = []
    for token in re.findall(r"[-+]?\d+(?:\.\d+)?", txt):
        try:
            nums.append(float(token))
        except Exception:
            continue
    if not nums:
        return 0, None
    positive = [x for x in nums if x > 0]
    negative = [x for x in nums if x < 0]
    if positive and not negative:
        sign = 1
    elif negative and not positive:
        sign = -1
    else:
        sign = 0
    min_abs = min(abs(x) for x in nums)
    return sign, min_abs


def _extract_observed_effect_pct(hypothesis: dict[str, Any], ab: dict[str, Any] | None, ab_v2: dict[str, Any] | None) -> float | None:
    for key in ("observed_effect_pct", "observed_delta_pct", "actual_uplift_pct", "effect_pct", "uplift_pct"):
        try:
            if hypothesis.get(key) is not None:
                return float(hypothesis.get(key))
        except Exception:
            continue
    if isinstance(hypothesis.get("observed_effect"), dict):
        for key in ("delta_pct", "uplift_pct", "effect_pct"):
            try:
                if hypothesis["observed_effect"].get(key) is not None:
                    return float(hypothesis["observed_effect"].get(key))
            except Exception:
                continue
    if isinstance(ab_v2, dict):
        pm = ab_v2.get("primary_metric", {}) if isinstance(ab_v2.get("primary_metric"), dict) else {}
        for key in ("delta_pct", "uplift_pct", "effect_pct", "point_estimate"):
            try:
                if pm.get(key) is not None:
                    return float(pm.get(key))
            except Exception:
                continue
    if isinstance(ab, dict):
        summary = ab.get("summary", {}) if isinstance(ab.get("summary"), dict) else {}
        for key in ("primary_metric_uplift", "primary_metric_uplift_pct", "delta_pct"):
            try:
                if summary.get(key) is not None:
                    return float(summary.get(key))
            except Exception:
                continue
    return None


def _infer_impact_class(hypothesis: dict[str, Any], expected_min_abs_pct: float | None) -> str:
    explicit = str(hypothesis.get("impact_class", "")).strip().lower()
    if explicit in {"low", "medium", "high"}:
        return explicit
    if isinstance(hypothesis.get("risk_factors"), list):
        risk_blob = " ".join(str(x).strip().lower() for x in hypothesis.get("risk_factors", []) if str(x).strip())
        if "high" in risk_blob:
            return "high"
    if expected_min_abs_pct is None:
        return "unknown"
    if expected_min_abs_pct >= 10.0:
        return "high"
    if expected_min_abs_pct >= 4.0:
        return "medium"
    return "low"


def _has_guardrail_signal(hypothesis: dict[str, Any]) -> bool:
    guardrails = hypothesis.get("guardrails")
    if isinstance(guardrails, dict):
        if any(str(v).strip() for v in guardrails.values()):
            return True
    elif isinstance(guardrails, list):
        if any(str(x).strip() for x in guardrails):
            return True
    risk_factors = hypothesis.get("risk_factors", []) if isinstance(hypothesis.get("risk_factors"), list) else []
    risk_blob = " ".join(str(x).strip().lower() for x in risk_factors if str(x).strip())
    if any(k in risk_blob for k in ("guardrail", "measurement", "srm", "availability", "margin")):
        return True
    refs = _normalize_evidence_refs_for_review(hypothesis.get("evidence_refs"))
    refs_blob = " ".join(refs).lower()
    return any(k in refs_blob for k in ("guardrail", "measurement", "srm", "availability", "margin"))


def _build_hypothesis_review_summary(review_rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(review_rows)
    supported = len([r for r in review_rows if _normalize_review_status(r.get("final_verdict")) == "SUPPORTED"])
    weak = len([r for r in review_rows if _normalize_review_status(r.get("final_verdict")) == "WEAK"])
    refuted = len([r for r in review_rows if _normalize_review_status(r.get("final_verdict")) == "REFUTED"])
    untestable = len([r for r in review_rows if _normalize_review_status(r.get("final_verdict")) == "UNTESTABLE"])
    refuted_high = len(
        [
            r
            for r in review_rows
            if _normalize_review_status(r.get("final_verdict")) == "REFUTED"
            and str(r.get("impact_class", "")).strip().lower() == "high"
        ]
    )
    denom = float(total if total > 0 else 1)
    refuted_high_rate = refuted_high / denom
    untestable_rate = untestable / denom
    weak_rate = weak / denom
    score = 1.0 - (0.7 * refuted_high_rate + 0.5 * untestable_rate + 0.2 * weak_rate)
    return {
        "total_count": total,
        "supported_count": supported,
        "weak_count": weak,
        "refuted_count": refuted,
        "untestable_count": untestable,
        "refuted_high_count": refuted_high,
        "refuted_high_rate": round(refuted_high_rate, 4),
        "untestable_rate": round(untestable_rate, 4),
        "weak_rate": round(weak_rate, 4),
        "verification_quality_score": round(_clamp01(score), 4),
    }


def _verify_doctor_hypotheses(
    *,
    run_id: str,
    doctor: dict[str, Any],
    ab: dict[str, Any] | None,
    ab_v2: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    portfolio = doctor.get("hypothesis_portfolio", [])
    if not isinstance(portfolio, list):
        portfolio = []
    review_rows: list[dict[str, Any]] = []
    review_blockers: list[str] = []

    for idx, row in enumerate([x for x in portfolio if isinstance(x, dict)], start=1):
        hypothesis_id = str(row.get("hypothesis_id", "")).strip() or f"hypothesis_{idx:02d}"
        target_metric = str(row.get("target_metric", "")).strip()
        expected_range = str(row.get("expected_uplift_range", "")).strip()
        refs = _normalize_evidence_refs_for_review(row.get("evidence_refs"))
        sign_expected, expected_min_abs = _parse_expected_range_for_review(expected_range)
        observed_effect = _extract_observed_effect_pct(row, ab, ab_v2)
        impact_class = _infer_impact_class(row, expected_min_abs)
        has_falsifiability = any(
            str(row.get(k, "")).strip()
            for k in ("falsifiability_test", "falsifiability", "falsifiability_condition")
        )
        guardrail_signal = _has_guardrail_signal(row)

        verdict = "SUPPORTED"
        reason = "deterministic_supported"
        conflict_type = ""
        if not refs:
            verdict = "UNTESTABLE"
            reason = "missing_or_invalid_evidence_refs"
        elif impact_class == "high" and not guardrail_signal:
            verdict = "UNTESTABLE"
            reason = "high_risk_without_guardrail_signal"
        else:
            observed_sign = 0
            if observed_effect is not None:
                if observed_effect > 0:
                    observed_sign = 1
                elif observed_effect < 0:
                    observed_sign = -1
            sign_conflict = sign_expected != 0 and observed_sign != 0 and sign_expected != observed_sign
            magnitude_conflict = (
                expected_min_abs is not None
                and observed_effect is not None
                and abs(observed_effect) < (expected_min_abs * 0.25)
            )
            if sign_conflict or magnitude_conflict:
                verdict = "REFUTED"
                conflict_type = "sign_conflict" if sign_conflict else "magnitude_conflict"
                reason = f"deterministic_{conflict_type}"
            elif not has_falsifiability:
                verdict = "WEAK"
                reason = "missing_falsifiability"

        if verdict in {"UNTESTABLE", "REFUTED"}:
            review_blockers.append(f"{hypothesis_id}:{reason}")

        review_rows.append(
            {
                "hypothesis_id": hypothesis_id,
                "target_metric": target_metric,
                "impact_class": impact_class,
                "deterministic_verdict": verdict,
                "final_verdict": verdict,
                "evidence_refs": refs,
                "rationale": (
                    f"Deterministic review for {hypothesis_id}: {reason}."
                    if reason
                    else f"Deterministic review for {hypothesis_id} completed."
                ),
                "mitigation": (
                    "Add measurable evidence refs and explicit falsifiability test before next decision cycle."
                    if verdict in {"UNTESTABLE", "WEAK"}
                    else "Address sign/magnitude conflict with corrected hypothesis before rollout."
                ),
                "expected_uplift_range": expected_range,
                "observed_effect_pct": observed_effect,
                "conflict_type": conflict_type or None,
            }
        )

    summary = _build_hypothesis_review_summary(review_rows)
    return review_rows, summary, sorted(set(review_blockers))[:20]


def _refine_hypothesis_review_rationale(
    *,
    run_id: str,
    review_rows: list[dict[str, Any]],
    backend_name: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    remote_allowed = os.getenv("LLM_ALLOW_REMOTE", "0") == "1"
    if not review_rows or not remote_allowed:
        return review_rows, {
            "enabled": False,
            "remote_allowed": remote_allowed,
            "used_fallback": False,
            "reason": "disabled_or_no_rows",
        }
    prompt = (
        "Return JSON object with key refinements[]. "
        "Each item: hypothesis_id, rationale, mitigation. "
        "Do not change verdicts, only improve text clarity.\n\n"
        + json.dumps(
            [
                {
                    "hypothesis_id": r.get("hypothesis_id"),
                    "final_verdict": r.get("final_verdict"),
                    "impact_class": r.get("impact_class"),
                    "rationale": r.get("rationale"),
                    "mitigation": r.get("mitigation"),
                }
                for r in review_rows
            ],
            ensure_ascii=False,
        )
    )
    provenance: dict[str, Any] = {
        "enabled": True,
        "remote_allowed": remote_allowed,
        "used_fallback": False,
        "fallback_reason": None,
    }
    try:
        groq_candidates = [COMMANDER_GROQ_PRIMARY_MODEL, COMMANDER_GROQ_FALLBACK_MODEL]
        tiers = build_runtime_failover_tiers(
            backend_requested=backend_name,
            groq_models=[str(x).strip() for x in groq_candidates if str(x).strip()],
            include_ollama=True,
        )
        raw, meta = generate_with_runtime_failover(
            run_id=run_id or "unknown_run",
            agent_name="commander",
            call_name="doctor_hypothesis_review_refinement",
            prompt=prompt,
            system_prompt="You are an evidence-focused reviewer. Refine only rationale and mitigation text.",
            tiers=tiers,
            deterministic_generator=lambda: json.dumps({"refinements": []}, ensure_ascii=False),
        )
        provenance["model"] = str(meta.get("model", "")).strip() or None
        provenance["used_fallback"] = bool(meta.get("used_fallback", False))
        provenance["fallback_reason"] = str(meta.get("fallback_reason", "")).strip() or None
        parsed = parse_json_object_loose(raw)
        ref_rows = parsed.get("refinements", []) if isinstance(parsed, dict) and isinstance(parsed.get("refinements"), list) else []
        by_id: dict[str, dict[str, Any]] = {}
        for row in ref_rows:
            if not isinstance(row, dict):
                continue
            hyp_id = str(row.get("hypothesis_id", "")).strip()
            if hyp_id:
                by_id[hyp_id] = row
        out_rows: list[dict[str, Any]] = []
        for row in review_rows:
            updated = dict(row)
            hyp_id = str(row.get("hypothesis_id", "")).strip()
            candidate = by_id.get(hyp_id, {})
            if isinstance(candidate, dict):
                rationale = str(candidate.get("rationale", "")).strip()
                mitigation = str(candidate.get("mitigation", "")).strip()
                if rationale:
                    updated["rationale"] = rationale[:1200]
                if mitigation:
                    updated["mitigation"] = mitigation[:800]
            updated["final_verdict"] = _normalize_review_status(updated.get("deterministic_verdict"))
            out_rows.append(updated)
        return out_rows, provenance
    except Exception as exc:
        provenance["used_fallback"] = True
        provenance["fallback_reason"] = f"refinement_error:{exc}"
        return review_rows, provenance


def _enforce_hypothesis_review_ceiling(payload: dict[str, Any], *, enforce: bool) -> None:
    if not enforce:
        return
    summary = payload.get("hypothesis_review_summary", {}) if isinstance(payload.get("hypothesis_review_summary"), dict) else {}
    refuted_high_count = int(summary.get("refuted_high_count", 0) or 0)
    if refuted_high_count <= 0:
        return
    decision = str(payload.get("normalized_decision", payload.get("decision", ""))).upper().strip()
    if decision in AGGRESSIVE_DECISIONS:
        payload["decision"] = "HOLD_NEED_DATA"
        payload["normalized_decision"] = "HOLD_NEED_DATA"
        blocked_by = payload.get("blocked_by", []) if isinstance(payload.get("blocked_by"), list) else []
        blocked_by.append("hypothesis_refuted_high")
        payload["blocked_by"] = sorted({str(x) for x in blocked_by if str(x).strip()})[:20]
        payload["top_reasons"] = payload["blocked_by"][:5]


def _validate_hypothesis_review_payload(payload: dict[str, Any]) -> None:
    try:
        contract = _load_doctor_hypothesis_review_contract()
    except Exception as exc:
        raise ValueError(f"HYPOTHESIS_REVIEW_INVALID_SCHEMA:contract_load_failed:{exc}")

    required_top = contract.get("required", []) if isinstance(contract.get("required"), list) else []
    for key in required_top:
        if key not in payload:
            raise ValueError(f"HYPOTHESIS_REVIEW_INVALID_SCHEMA:missing_top_required:{key}")

    rows = payload.get("doctor_hypothesis_review")
    summary = payload.get("hypothesis_review_summary")
    if not isinstance(rows, list) or not isinstance(summary, dict):
        raise ValueError("HYPOTHESIS_REVIEW_INVALID_SCHEMA:missing_review_blocks")

    props = contract.get("properties", {}) if isinstance(contract.get("properties"), dict) else {}
    rows_schema = (
        ((props.get("doctor_hypothesis_review") or {}).get("items", {}))
        if isinstance(props.get("doctor_hypothesis_review"), dict)
        else {}
    )
    row_required = rows_schema.get("required", []) if isinstance(rows_schema.get("required"), list) else []
    row_props = rows_schema.get("properties", {}) if isinstance(rows_schema.get("properties"), dict) else {}
    det_allowed = set(
        row_props.get("deterministic_verdict", {}).get("enum", HYPOTHESIS_REVIEW_STATUSES)
        if isinstance(row_props.get("deterministic_verdict"), dict)
        else HYPOTHESIS_REVIEW_STATUSES
    )
    final_allowed = set(
        row_props.get("final_verdict", {}).get("enum", HYPOTHESIS_REVIEW_STATUSES)
        if isinstance(row_props.get("final_verdict"), dict)
        else HYPOTHESIS_REVIEW_STATUSES
    )
    summary_schema = props.get("hypothesis_review_summary", {}) if isinstance(props.get("hypothesis_review_summary"), dict) else {}
    summary_required = summary_schema.get("required", []) if isinstance(summary_schema.get("required"), list) else []

    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"HYPOTHESIS_REVIEW_INVALID_SCHEMA:row_not_object:{idx}")
        for key in row_required:
            if key not in row:
                raise ValueError(f"HYPOTHESIS_REVIEW_INVALID_SCHEMA:missing_row_required:{idx}:{key}")
        det_raw = str(row.get("deterministic_verdict", "")).strip().upper()
        final_raw = str(row.get("final_verdict", "")).strip().upper()
        if det_raw not in det_allowed:
            raise ValueError(f"HYPOTHESIS_REVIEW_INVALID_SCHEMA:invalid_deterministic_verdict:{idx}:{det_raw or 'empty'}")
        if final_raw not in final_allowed:
            raise ValueError(f"HYPOTHESIS_REVIEW_INVALID_SCHEMA:invalid_final_verdict:{idx}:{final_raw or 'empty'}")
        det = _normalize_review_status(det_raw)
        final = _normalize_review_status(final_raw)
        if det == "REFUTED" and final == "SUPPORTED":
            raise ValueError("HYPOTHESIS_REVIEW_POLICY_VIOLATION:llm_upgraded_refuted_to_supported")
        refs = row.get("evidence_refs", [])
        if not isinstance(refs, list):
            raise ValueError(f"HYPOTHESIS_REVIEW_INVALID_SCHEMA:evidence_refs_not_list:{idx}")

    for key in summary_required:
        if key not in summary:
            raise ValueError(f"HYPOTHESIS_REVIEW_INVALID_SCHEMA:missing_summary_required:{key}")

    total = int(summary.get("total_count", 0) or 0)
    if total != len(rows):
        raise ValueError("HYPOTHESIS_REVIEW_INVALID_SCHEMA:summary_total_mismatch")


def _compute_goal_blocks(
    *,
    doctor: dict[str, Any],
    metrics_snapshot: dict[str, Any],
    ab: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    metrics = metrics_snapshot.get("metrics", {}) if isinstance(metrics_snapshot.get("metrics"), dict) else {}
    top_h = _extract_top_portfolio_hypothesis(doctor)
    target_metric = str(top_h.get("target_metric", "")).strip()
    target_goal = _goal_from_target_metric(target_metric)
    ab_summary = ab.get("summary", {}) if isinstance(ab, dict) and isinstance(ab.get("summary"), dict) else {}
    ab_primary_metric = str(ab_summary.get("primary_metric", "")).strip()
    expected_range = str(top_h.get("expected_uplift_range", "")).strip() or None
    base_guardrails = _build_guardrails(metrics)
    goal_defs = _goal_defaults()
    primary_goal_id = goal_defs[0][0] if goal_defs else ""
    secondary_goal_id = goal_defs[1][0] if len(goal_defs) > 1 else ""
    goal_direction = domain_goal_expected_direction()
    out: list[dict[str, Any]] = []
    for goal_id, default_metric, _alias in goal_defs:
        primary_metric = default_metric if goal_id != goal_from_metric(ab_primary_metric) else (ab_primary_metric or default_metric)
        target_status = "PRIMARY" if goal_id == target_goal else ("GUARDRAIL" if goal_id == secondary_goal_id and target_goal == primary_goal_id else "SECONDARY")
        direction = str(goal_direction.get(goal_id, "")).strip().lower()
        out.append(
            {
                "goal_id": goal_id,
                "target_status": target_status,
                "primary_metric": primary_metric,
                "success_metric": primary_metric,
                "expected_impact_range": expected_range if goal_id == target_goal else None,
                "expected_impact_accepted": True if goal_id == target_goal else False,
                "expected_impact_changed": False,
                "corrected_expected_impact_range": None,
                "guardrails": base_guardrails,
                "decision_impact_risk": (
                    "Optimization can harm availability/economics if operational constraints are ignored."
                    if direction == "decrease"
                    else "Growth can degrade margin or service quality if guardrails are not enforced."
                ),
                "evidence_refs": [
                    {"source": "metrics_snapshot", "metric": primary_metric, "value": metrics.get(primary_metric)},
                    {"source": "doctor", "field": "hypothesis_portfolio", "value": top_h.get("hypothesis_id")},
                ],
            }
        )
    return out


def _compute_methodology_check(
    *,
    doctor: dict[str, Any],
    evaluator: dict[str, Any],
    metrics_snapshot: dict[str, Any],
    ab: dict[str, Any] | None,
    ab_v2: dict[str, Any] | None,
) -> dict[str, Any]:
    run_cfg = metrics_snapshot.get("run_config", {}) if isinstance(metrics_snapshot.get("run_config"), dict) else {}
    top_h = _extract_top_portfolio_hypothesis(doctor)
    hyp_goal = goal_from_metric(str(top_h.get("target_metric", "")).strip())
    ab_summary = ab.get("summary", {}) if isinstance(ab, dict) and isinstance(ab.get("summary"), dict) else {}
    ab_primary_metric = str(((ab_v2 or {}).get("primary_metric", {}) or {}).get("name") if isinstance((ab_v2 or {}).get("primary_metric"), dict) else ab_summary.get("primary_metric", "")).strip()
    ab_goal = goal_from_metric(ab_primary_metric)
    ab_status = str((ab_v2 or {}).get("status") if isinstance(ab_v2, dict) and (ab_v2 or {}).get("status") else evaluator.get("ab_status", "")).upper()
    measurement_state = str(doctor.get("measurement_state", evaluator.get("measurement_state", "BLOCKED_BY_DATA"))).upper()
    sample_sizes = {
        "control": int(float(ab_summary.get("n_orders_control", 0) or 0)),
        "treatment": int(float(ab_summary.get("n_orders_treatment", 0) or 0)),
    }
    alpha = 0.05
    ci_level = 0.95
    p_value = ((ab_v2 or {}).get("primary_metric", {}) or {}).get("p_value") if isinstance((ab_v2 or {}).get("primary_metric"), dict) else ab_summary.get("primary_metric_p_value")
    ci95 = ((ab_v2 or {}).get("primary_metric", {}) or {}).get("ci95") if isinstance((ab_v2 or {}).get("primary_metric"), dict) else ab_summary.get("primary_metric_uplift_ci95")
    stats_consistent = True
    decision_rule_result = "NOT_APPLICABLE"
    errors: list[str] = []
    p_num = None
    ci_contains_zero = None
    try:
        if p_value is not None:
            p_num = float(p_value)
    except Exception:
        p_num = None
    try:
        if isinstance(ci95, list) and len(ci95) == 2:
            ci_contains_zero = float(ci95[0]) <= 0 <= float(ci95[1])
    except Exception:
        ci_contains_zero = None
    if p_num is not None and ci_contains_zero is not None:
        if p_num <= alpha and ci_contains_zero is False:
            decision_rule_result = "REJECT_H0"
        elif p_num > alpha:
            decision_rule_result = "FAIL_TO_REJECT_H0"
        else:
            decision_rule_result = "INCONCLUSIVE"
            stats_consistent = False
            errors.append("p_value_ci_contradiction")
    if ab_status in AB_METHOD_VALIDITY_ERROR_STATUSES:
        decision_rule_result = "INCONCLUSIVE"
    unit_alignment_ok = str(run_cfg.get("experiment_unit", "")).lower() in {"", str((ab or {}).get("unit_type", "")).lower()}
    goal_metric_alignment_ok = bool(hyp_goal != "unknown" and ab_goal != "unknown" and hyp_goal == ab_goal)
    if not goal_metric_alignment_ok:
        errors.append("goal_metric_misalignment")
    if not unit_alignment_ok:
        errors.append("unit_alignment")
    if is_measurement_blocked(measurement_state):
        errors.append("measurement_blind_spot")
    mde_val = ab_summary.get("mde_estimate")
    return {
        "ab_status": ab_status,
        "measurement_state": measurement_state,
        "unit_alignment_ok": unit_alignment_ok,
        "goal_metric_alignment_ok": goal_metric_alignment_ok,
        "stats_consistent": stats_consistent,
        "alpha": alpha,
        "ci_level": ci_level,
        "sample_sizes": sample_sizes,
        "sample_size_imbalance": (sample_sizes["control"] != sample_sizes["treatment"]),
        "underpowered": bool(str(ab_status).upper() == "UNDERPOWERED"),
        "mde": mde_val,
        "decision_rule_result": decision_rule_result,
        "errors": errors,
        "assignment_method": "hash+salt",
        "experiment_unit": str(run_cfg.get("experiment_unit", (ab or {}).get("unit_type", "unknown"))),
        "method_by_metric_policy": {
            "continuous": "Welch t-test / bootstrap",
            "proportions": "z-test proportions / chi-square",
            "ratios": "bootstrap or delta method",
        },
    }


def _build_commander_measurement_fix_plan(doctor: dict[str, Any], methodology_check: dict[str, Any]) -> list[str]:
    existing = doctor.get("measurement_fix_plan", {}) if isinstance(doctor.get("measurement_fix_plan"), dict) else {}
    steps = existing.get("minimal_steps", []) if isinstance(existing.get("minimal_steps"), list) else []
    out = [str(x) for x in steps if str(x).strip()]
    if not out:
        out = [
            "Restore valid assignment/join path for the experiment unit.",
            "Rebuild AB report with aligned primary metric and consistent p-value/CI method.",
            "Re-run evaluator and commander after methodology checks pass.",
        ]
    return out[:3]


def _build_mitigation_proposals(
    *,
    run_id: str,
    decision: str,
    blocked_by: list[str],
    methodology_check: dict[str, Any],
) -> dict[str, Any]:
    dec = str(decision or "").upper()
    if dec not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"}:
        return {"mitigation_proposals": [], "insufficient_evidence": None}

    primary_blocker = (blocked_by[0] if blocked_by else "insufficient_evidence").strip() or "insufficient_evidence"
    evidence_refs = [
        f"artifact:data/agent_reports/{run_id}_doctor_variance.json#",
        f"artifact:data/agent_reports/{run_id}_experiment_evaluator.json#",
        f"artifact:data/metrics_snapshots/{run_id}.json#",
    ]
    required_data = [
        "assignment_integrity_report",
        "ab_methodology_alignment_report",
        "guardrail_history_for_primary_metric",
    ]
    proposals = [
        {
            "mitigation_id": "mitigation_assignment_integrity",
            "applicability": f"applies_when:{primary_blocker}",
            "risk_tradeoff": "slower iteration speed in exchange for causal validity",
            "confidence": 0.82,
            "evidence_refs": evidence_refs,
            "required_data": required_data,
        },
        {
            "mitigation_id": "mitigation_measurement_repair",
            "applicability": f"methodology_state:{methodology_check.get('decision_rule_result', 'INCONCLUSIVE')}",
            "risk_tradeoff": "extra data collection cost in exchange for decision safety",
            "confidence": 0.78,
            "evidence_refs": evidence_refs,
            "required_data": required_data,
        },
    ]
    insufficient_evidence = {
        "reason": primary_blocker,
        "required_data": required_data,
        "next_validation_plan": [
            "collect missing assignment + SRM evidence",
            "recompute evaluator with aligned primary metric",
            "rerun commander after quality gates PASS",
        ],
    }
    return {"mitigation_proposals": proposals, "insufficient_evidence": insufficient_evidence}


def _validate_mitigation_policy(payload: dict[str, Any]) -> None:
    decision = str(payload.get("normalized_decision", payload.get("decision", ""))).upper().strip()
    if decision not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK"}:
        return

    proposals = payload.get("mitigation_proposals", [])
    insufficient = payload.get("insufficient_evidence", {})
    if not isinstance(proposals, list):
        proposals = []

    valid = 0
    for row in proposals:
        if not isinstance(row, dict):
            continue
        if not str(row.get("applicability", "")).strip():
            continue
        if not str(row.get("risk_tradeoff", "")).strip():
            continue
        try:
            conf = float(row.get("confidence"))
        except Exception:
            continue
        if conf <= 0.0 or conf > 1.0:
            continue
        ev = row.get("evidence_refs", [])
        req = row.get("required_data", [])
        if not isinstance(ev, list) or not ev:
            continue
        if not isinstance(req, list) or not req:
            continue
        valid += 1
    if valid >= 2:
        return

    if not isinstance(insufficient, dict):
        raise ValueError("MITIGATION_PROPOSALS_MISSING:invalid_insufficient_evidence_block")
    req = insufficient.get("required_data", [])
    nvp = insufficient.get("next_validation_plan", [])
    if not isinstance(req, list) or len(req) == 0:
        raise ValueError("MITIGATION_PROPOSALS_MISSING:required_data_empty")
    if not isinstance(nvp, list) or len(nvp) == 0:
        raise ValueError("MITIGATION_PROPOSALS_MISSING:next_validation_plan_empty")


def _validate_commander_policy_contract(payload: dict[str, Any]) -> None:
    if payload.get("normalized_decision") not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}:
        raise ValueError("commander contract: invalid normalized_decision")
    _validate_hypothesis_review_payload(payload)
    methodology = payload.get("methodology_check", {})
    if not isinstance(methodology, dict):
        raise ValueError("commander contract: methodology_check missing")
    ab_status = str(methodology.get("ab_status", "")).upper()
    measurement_state = str(methodology.get("measurement_state", "")).upper()
    decision = str(payload.get("normalized_decision", "")).upper()
    if is_ab_decision_invalid(ab_status) or is_measurement_blocked(measurement_state):
        if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
            raise ValueError("commander contract: decision ceiling violated under measurement blind spot")
    review_summary = payload.get("hypothesis_review_summary", {}) if isinstance(payload.get("hypothesis_review_summary"), dict) else {}
    if int(review_summary.get("refuted_high_count", 0) or 0) > 0 and decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
        raise ValueError("HYPOTHESIS_REVIEW_POLICY_VIOLATION:refuted_high_requires_hold_need_data")
    if methodology.get("goal_metric_alignment_ok") is False and decision != "STOP":
        raise ValueError("commander contract: goal misalignment must force STOP")
    goals = payload.get("goals", [])
    expected_goal_count = len(_goal_defaults())
    if not isinstance(goals, list) or len(goals) != expected_goal_count:
        raise ValueError(f"commander contract: goals must contain exactly {expected_goal_count} blocks")
    required_guardrail_metrics = {
        str(x.get("metric", "")).strip()
        for x in _build_guardrails({})
        if isinstance(x, dict) and str(x.get("metric", "")).strip()
    }
    for idx, g in enumerate(goals):
        if not isinstance(g, dict):
            raise ValueError(f"commander contract: goals[{idx}] invalid")
        guardrails = g.get("guardrails")
        if not isinstance(guardrails, list):
            raise ValueError(f"commander contract: goals[{idx}].guardrails missing")
        metrics = {str(x.get("metric", "")).strip() for x in guardrails if isinstance(x, dict) and str(x.get("metric", "")).strip()}
        missing = sorted(m for m in required_guardrail_metrics if m not in metrics)
        if missing:
            raise ValueError(f"commander contract: goals[{idx}] missing template guardrails: {','.join(missing)}")
    cohort = payload.get("cohort_analysis", {})
    if isinstance(cohort, dict) and str(cohort.get("status", "")).upper() == "BLOCKED_BY_DATA":
        dr = payload.get("data_requests", [])
        if not isinstance(dr, list) or len(dr) < 3:
            raise ValueError("commander contract: data_requests (>=3) required when cohort_analysis is BLOCKED_BY_DATA")


def _build_data_requests(
    *,
    run_id: str,
    methodology_check: dict[str, Any],
    cohort_blocked: bool,
) -> list[dict[str, Any]]:
    reqs: list[dict[str, Any]] = []
    goal_defs = _goal_defaults()
    primary_goal_metric = goal_defs[0][1] if goal_defs else "primary_metric"
    primary_goal_alias = goal_defs[0][2] if goal_defs else "target_metric"
    guardrail_metrics = [str(g.get("metric", "")).strip() for g in _build_guardrails({}) if isinstance(g, dict) and str(g.get("metric", "")).strip()]
    if cohort_blocked:
        reqs.extend(
            [
                {
                    "request_id": "cohort_spend_bucket",
                    "priority": "P0",
                    "table_or_artifact": "step1_orders / metrics_snapshot extension",
                    "fields": ["customer_id", "order_id", "order_value", "order_date"],
                    "aggregation": "bucket customers into low/med/high spend and compute share of users, orders, and reference value by arm",
                    "why": "Need cohort heterogeneity check before trusting average effect.",
                },
                {
                    "request_id": "cohort_frequency_bucket",
                    "priority": "P0",
                    "table_or_artifact": "step1_orders / customer_daily",
                    "fields": ["customer_id", "orders_14d", "arm"],
                    "aggregation": "bucket by order frequency and compare direction consistency vs overall uplift",
                    "why": "Detect effect concentration or reversal hidden in aggregate averages.",
                },
                {
                    "request_id": "target_metric_vs_guardrail_breakdown",
                    "priority": "P0",
                    "table_or_artifact": "domain-specific category rollup (missing now)",
                    "fields": ["category_id", primary_goal_metric, *guardrail_metrics[:2]],
                    "aggregation": "category-level before/after and control/treatment tradeoff table for target vs guardrails",
                    "why": (
                        "Need anti-Goodhart check: apparent improvement in "
                        f"{primary_goal_alias} may come from hidden trade-offs."
                    ),
                },
            ]
        )
    if methodology_check.get("sample_size_imbalance") or methodology_check.get("underpowered"):
        reqs.append(
            {
                "request_id": "srm_mde_recompute",
                "priority": "P0",
                "table_or_artifact": "ab_report + assignment log summary",
                "fields": ["assignment_counts_by_arm", "n_orders_control", "n_orders_treatment", "variance_estimates"],
                "aggregation": "recompute SRM test and MDE using actual arm sizes and variance",
                "why": "Need defensible sample-size and power interpretation before approving next experiment.",
            }
        )
    if methodology_check.get("goal_metric_alignment_ok") is False:
        reqs.append(
            {
                "request_id": "goal_metric_alignment_fix",
                "priority": "P0",
                "table_or_artifact": "doctor_portfolio + ab_config",
                "fields": ["hypothesis.target_metric", "ab.primary_metric", "experiment_id"],
                "aggregation": "one-row alignment check artifact before evaluator/commander",
                "why": "Prevent invalid-method decisions due to goal/metric mismatch.",
            }
        )
    # Ensure at least 3 concrete requests in blocked scenarios.
    return reqs[:6]


def _render_commander_60s_memo(run_id: str, payload: dict[str, Any]) -> str:
    goals = payload.get("goals", []) if isinstance(payload.get("goals"), list) else []
    methodology = payload.get("methodology_check", {}) if isinstance(payload.get("methodology_check"), dict) else {}
    data_requests = payload.get("data_requests", []) if isinstance(payload.get("data_requests"), list) else []
    next_actions = payload.get("next_actions", []) if isinstance(payload.get("next_actions"), list) else []
    lines = [
        f"# COMMANDER_60S_MEMO — {run_id}",
        "",
        f"- Decision: `{payload.get('normalized_decision')}`",
        f"- Why now: `{'; '.join(payload.get('top_reasons', [])[:2]) if isinstance(payload.get('top_reasons'), list) else 'missing'}`",
        "",
        "## 3 Goal Blocks (Executive View)",
    ]
    for g in goals[:3]:
        if not isinstance(g, dict):
            continue
        lines.append(
            f"- {g.get('goal_id')}: status=`{g.get('target_status')}`, metric=`{g.get('primary_metric')}`, expected=`{g.get('expected_impact_range')}`, accepted=`{g.get('expected_impact_accepted')}`, changed=`{g.get('expected_impact_changed')}`"
        )
    lines.extend(
        [
            "",
            "## Statistical Decision + Why",
            f"- ab_status=`{methodology.get('ab_status')}`, measurement_state=`{methodology.get('measurement_state')}`",
            f"- stats_consistent=`{methodology.get('stats_consistent')}`, decision_rule_result=`{methodology.get('decision_rule_result')}`",
            f"- alignment: unit_ok=`{methodology.get('unit_alignment_ok')}`, goal_metric_ok=`{methodology.get('goal_metric_alignment_ok')}`",
            "",
            "## Trade-offs Across Goals",
            f"- Blocked by: `{payload.get('blocked_by', [])[:5]}`",
            "",
            "## Data Requests (if blocked)",
        ]
    )
    if data_requests:
        for r in data_requests[:5]:
            if not isinstance(r, dict):
                continue
            lines.append(
                f"- {r.get('request_id')}: {r.get('aggregation')} (fields={r.get('fields')})"
            )
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Next Action (single)")
    if next_actions:
        first = next_actions[0]
        lines.append(f"- `{first}`")
    else:
        lines.append("- `none`")
    return "\n".join(lines) + "\n"


def _stable_proposal_id(agent: str, proposal_type: str, title: str, key_fields: dict[str, Any]) -> str:
    raw = json.dumps(
        {
            "agent": agent,
            "proposal_type": proposal_type,
            "title": title,
            "key_fields": key_fields,
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _proposal_row(
    *,
    agent: str,
    proposal_type: str,
    linked_goal: str,
    title: str,
    decision: str,
    reason_code: str,
    source: str,
    key_fields: dict[str, Any],
) -> dict[str, Any]:
    return {
        "proposal_id": _stable_proposal_id(agent, proposal_type, title, key_fields),
        "proposal_type": proposal_type,
        "agent": agent,
        "linked_goal": linked_goal,
        "decision": decision,
        "reason_code": reason_code,
        "source": source,
        "title": title,
        "key_fields": key_fields,
    }


def _collect_doctor_proposals(doctor: dict[str, Any], commander_decision: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    goal_ids = [g[0] for g in _goal_defaults()]
    default_goal = goal_ids[1] if len(goal_ids) > 1 else goal_ids[0]
    ab_plan = doctor.get("ab_plan", [])
    if not isinstance(ab_plan, list):
        ab_plan = []
    for exp in ab_plan:
        if not isinstance(exp, dict):
            continue
        name = str(exp.get("name", "experiment")).strip() or "experiment"
        goal_raw = str(exp.get("goal", "")).strip().lower()
        linked_goal = default_goal
        for gid in goal_ids:
            if gid and gid in goal_raw:
                linked_goal = gid
                break
        decision = "APPROVE" if commander_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} else "REJECT"
        reason = "good_value" if decision == "APPROVE" else "guardrail_risk"
        hypotheses = exp.get("hypotheses", [])
        if isinstance(hypotheses, list) and hypotheses and isinstance(hypotheses[0], dict):
            h0 = hypotheses[0]
            if not str(h0.get("hypothesis_statement", "")).strip():
                reason = "missing_evidence"
                decision = "REJECT"
            if not str(h0.get("analysis_method", "")).strip():
                reason = "bad_methodology"
                decision = "REJECT"
        out.append(
            _proposal_row(
                agent="doctor",
                proposal_type="hypothesis",
                linked_goal=linked_goal,
                title=name,
                decision=decision,
                reason_code=reason,
                source="commander",
                key_fields={
                    "lever_type": str(exp.get("lever_type", "")),
                    "unit": str(exp.get("unit", "")),
                    "scope": _coerce_scope(exp.get("scope", ["all"])),
                    "methodology": str(exp.get("methodology", "")),
                },
            )
        )
    return out


def _collect_captain_proposals(captain: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    default_goal = _goal_defaults()[0][0]
    issues = ((captain.get("result") or {}).get("issues", []) if isinstance(captain.get("result"), dict) else [])
    if not isinstance(issues, list):
        issues = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        name = str(issue.get("check_name", "captain_issue")).strip() or "captain_issue"
        sev = str(issue.get("severity", "WARN")).upper()
        out.append(
            _proposal_row(
                agent="captain",
                proposal_type="realism_gap",
                linked_goal=default_goal,
                title=name,
                decision="APPROVE" if sev in {"WARN", "HARD_FAIL"} else "REJECT",
                reason_code="good_value" if sev in {"WARN", "HARD_FAIL"} else "duplicate",
                source="commander",
                key_fields={"severity": sev, "message": str(issue.get("message", ""))[:160]},
            )
        )
    return out


def _collect_narrative_proposals(run_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    goal_ids = [g[0] for g in _goal_defaults()]
    default_goal = goal_ids[1] if len(goal_ids) > 1 else goal_ids[0]
    path = Path(f"reports/L1_ops/{run_id}/causal_claims.json")
    doc, _err = _try_load_json(path)
    if not isinstance(doc, dict):
        return out
    metric_claims = doc.get("metric_claims", {})
    if not isinstance(metric_claims, dict):
        return out
    for mk, claim in metric_claims.items():
        if not isinstance(claim, dict):
            continue
        short = str(claim.get("explanation_short", "")).strip()
        refs = claim.get("evidence_refs", [])
        if not short:
            continue
        decision = "APPROVE" if isinstance(refs, list) and len(refs) > 0 else "REJECT"
        reason = "good_value" if decision == "APPROVE" else "missing_evidence"
        out.append(
            _proposal_row(
                agent="narrative_analyst",
                proposal_type="explanation",
                linked_goal=default_goal,
                title=mk,
                decision=decision,
                reason_code=reason,
                source="commander",
                key_fields={"metric": mk, "has_refs": isinstance(refs, list) and len(refs) > 0},
            )
        )
    return out


def _merge_human_overrides(run_id: str, approvals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    path = Path(f"data/governance/approvals_overrides_{run_id}.json")
    doc, _err = _try_load_json(path)
    if not isinstance(doc, dict):
        return approvals
    extra = doc.get("approvals", [])
    if not isinstance(extra, list):
        return approvals
    merged = {str(a.get("proposal_id", "")): a for a in approvals if isinstance(a, dict)}
    for row in extra:
        if not isinstance(row, dict):
            continue
        if str(row.get("source", "")).strip().lower() != "human":
            continue
        pid = str(row.get("proposal_id", "")).strip()
        if not pid:
            agent = str(row.get("agent", "human")).strip() or "human"
            ptype = str(row.get("proposal_type", "improvement")).strip() or "improvement"
            title = str(row.get("title", "override")).strip() or "override"
            key_fields = row.get("key_fields", {}) if isinstance(row.get("key_fields"), dict) else {}
            pid = _stable_proposal_id(agent, ptype, title, key_fields)
            row["proposal_id"] = pid
        merged[pid] = row
    return list(merged.values())


def _write_approvals_registry(
    run_id: str,
    *,
    doctor: dict[str, Any],
    captain: dict[str, Any],
    commander_decision: str,
) -> Path:
    out = Path(f"data/governance/approvals_{run_id}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    approvals: list[dict[str, Any]] = []
    approvals.extend(_collect_doctor_proposals(doctor, commander_decision))
    approvals.extend(_collect_captain_proposals(captain))
    approvals.extend(_collect_narrative_proposals(run_id))
    approvals = _merge_human_overrides(run_id, approvals)
    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "approvals": approvals,
    }
    out.write_text(json.dumps(_redact_obj(payload), ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Commander Priority v1 (PM decision + roadmap)")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--backend", choices=["groq", "ollama", "auto"], default="auto")
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--domain-template", default="", help="Optional path to domain template JSON")
    parser.add_argument("--enable-react-commander", type=int, default=0, choices=[0, 1])
    parser.add_argument("--react-max-steps", type=int, default=4)
    parser.add_argument("--enable-hypothesis-review-v1", type=int, default=0, choices=[0, 1])
    args = parser.parse_args()
    set_domain_template_override(args.domain_template)
    hypothesis_review_enforce = int(args.enable_hypothesis_review_v1) == 1
    hypothesis_review_mode = "enforce" if hypothesis_review_enforce else "shadow"

    run_id = args.run_id
    log_path = Path(f"data/logs/commander_priority_{run_id}.log")
    out_json = Path(f"data/agent_reports/{run_id}_commander_priority.json")
    out_md = Path(f"data/agent_reports/{run_id}_commander_priority.md")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    retry_policy, retry_status = _retry_budget_status(run_id)
    if retry_policy is not None and not bool(retry_status.get("allowed", False)):
        reason = str(retry_status.get("reason", "retry_policy_blocked"))
        write_retry_guard_report(
            run_id,
            status="FAIL",
            reason=f"{reason}:run_commander_priority_precheck",
            retry_policy=retry_policy,
            state=(retry_status.get("state") if isinstance(retry_status.get("state"), dict) else {}),
        )
        payload = _base_hold_payload(run_id, [f"retry_budget_or_circuit_blocked:{reason}"])
        payload["hypothesis_review_mode"] = hypothesis_review_mode
        payload["fallback_tier"] = "local_fallback"
        payload["fallback_reason"] = f"retry_policy_blocked:{reason}"
        payload["provisional_local_fallback"] = True
        payload["needs_cloud_reconciliation"] = True
        payload.update(
            _build_mitigation_proposals(
                run_id=run_id,
                decision=str(payload.get("normalized_decision", payload.get("decision", ""))),
                blocked_by=(payload.get("blocked_by", []) if isinstance(payload.get("blocked_by"), list) else []),
                methodology_check={},
            )
        )
        _attach_phase_flags_and_visible_trace(payload)
        payload["fallback_tier"] = "local_fallback"
        payload["fallback_reason"] = "unexpected_runtime_error"
        payload["provisional_local_fallback"] = True
        payload["needs_cloud_reconciliation"] = True
        safe_payload = _redact_obj(payload)
        out_json.write_text(json.dumps(safe_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(out_json)
        out_md.write_text(_redact_text(_to_markdown(safe_payload)), encoding="utf-8")
        memo_path = Path(f"reports/L1_ops/{run_id}/COMMANDER_60S_MEMO.md")
        memo_path.parent.mkdir(parents=True, exist_ok=True)
        memo_path.write_text(_redact_text(_render_commander_60s_memo(run_id, safe_payload)), encoding="utf-8")
        _write_approvals_registry(run_id, doctor={}, captain={}, commander_decision="HOLD_NEED_DATA")
        print(f"ok: commander priority report written for run_id={run_id} (retry-guard hold)")
        return

    payload: dict[str, Any]
    try:
        decision_contract = load_decision_contract()
        dq, dq_err = _try_load_json(Path(f"data/dq_reports/{run_id}.json"))
        captain, cap_err = _try_load_json(Path(f"data/llm_reports/{run_id}_captain.json"))
        metrics, met_err = _try_load_json(Path(f"data/metrics_snapshots/{run_id}.json"))
        doctor, doc_err = _try_load_json(Path(f"data/agent_reports/{run_id}_doctor_variance.json"))
        evaluator, eval_err = _try_load_json(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"))
        synthetic_bias, _ = _try_load_json(Path(f"data/realism_reports/{run_id}_synthetic_bias.json"))
        narrative_validation, _ = _try_load_json(Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json"))
        doctor_context, _ = _try_load_json(Path(f"data/agent_context/{run_id}_doctor_context.json"))
        historical_context_pack_path = Path(f"data/agent_context/{run_id}_historical_context_pack.json")
        historical_context_pack = {}
        historical_context_err = ""
        historical_context_pack_sha256 = ""
        try:
            historical_context_pack = load_json_with_integrity(historical_context_pack_path)
            sidecar = sha256_sidecar_path(historical_context_pack_path)
            if sidecar.exists():
                historical_context_pack_sha256 = sidecar.read_text(encoding="utf-8").strip().lower()
        except Exception as exc:
            historical_context_pack = {}
            historical_context_err = str(exc)
        exp_id = str(args.experiment_id or "").strip()
        if not exp_id and isinstance(metrics, dict):
            run_cfg = metrics.get("run_config", {})
            if isinstance(run_cfg, dict):
                exp_id = str(run_cfg.get("experiment_id", "") or "").strip()
        ab, ab_err = _try_load_json(Path(f"data/ab_reports/{run_id}_{exp_id}_ab.json")) if exp_id else (None, None)
        ab_v2, _ = _try_load_json(Path(f"data/ab_reports/{run_id}_{exp_id}_ab_v2.json")) if exp_id else (None, None)
        active_exp, _ = _try_load_json(Path("data/agent_reports/active_experiments.json"))
        blocked = [x for x in [dq_err, cap_err, met_err, doc_err, eval_err] if x]
        if historical_context_err:
            blocked.append(f"historical_context_missing_or_invalid:{historical_context_err}")
        if exp_id and ab_err:
            blocked.append(ab_err)

        hist_rows = (
            historical_context_pack.get("rows", [])
            if isinstance(historical_context_pack, dict) and isinstance(historical_context_pack.get("rows"), list)
            else []
        )
        hist_ready = (
            isinstance(historical_context_pack, dict)
            and str(historical_context_pack.get("status", "")).upper() == "PASS"
            and len(hist_rows) > 0
        )
        doctor_hypothesis_review: list[dict[str, Any]] = []
        hypothesis_review_summary: dict[str, Any] = _build_hypothesis_review_summary([])
        review_blockers: list[str] = []
        hypothesis_review_llm_provenance: dict[str, Any] = {
            "enabled": False,
            "remote_allowed": False,
            "used_fallback": False,
            "reason": "doctor_payload_missing",
        }
        if isinstance(doctor, dict):
            doctor_hypothesis_review, hypothesis_review_summary, review_blockers = _verify_doctor_hypotheses(
                run_id=run_id,
                doctor=doctor,
                ab=ab if isinstance(ab, dict) else None,
                ab_v2=ab_v2 if isinstance(ab_v2, dict) else None,
            )
            doctor_hypothesis_review, hypothesis_review_llm_provenance = _refine_hypothesis_review_rationale(
                run_id=run_id,
                review_rows=doctor_hypothesis_review,
                backend_name=args.backend,
            )
            hypothesis_review_summary = _build_hypothesis_review_summary(doctor_hypothesis_review)
        if dq is None or captain is None or metrics is None or doctor is None or evaluator is None or not hist_ready:
            payload = _base_hold_payload(run_id, blocked)
            payload["hypothesis_review_mode"] = hypothesis_review_mode
            payload["doctor_hypothesis_review"] = doctor_hypothesis_review
            payload["hypothesis_review_summary"] = hypothesis_review_summary
            payload["review_blockers"] = review_blockers
            payload["hypothesis_review_llm_provenance"] = hypothesis_review_llm_provenance
        else:
            dq_rows = dq.get("rows", [])
            if not isinstance(dq_rows, list):
                dq_rows = []
            dq_fail_count, dq_warn_count = _count_dq(dq_rows)
            captain_verdict = captain.get("result", {}).get("verdict")
            mapped_decision, evaluator_decision_summary = _map_evaluator_decision(
                evaluator.get("decision")
            )
            _, doctor_decision_summary = _map_doctor_decision(
                doctor.get("normalized_decision", doctor.get("decision"))
            )
            pre_blocked: list[str] = []
            if evaluator_decision_summary == "unknown":
                pre_blocked.append("evaluator_decision_unrecognized")
            hyp_ok, hyp_issue = _doctor_hypothesis_valid(doctor)
            if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and not hyp_ok:
                mapped_decision = "HOLD_NEED_DATA"
                if hyp_issue:
                    pre_blocked.append(hyp_issue)
            assignment_status = str(doctor.get("assignment_status", "missing")).strip().lower()
            assignment_ready = assignment_status in {"present", "ready"}
            evaluator_ab_status = str(evaluator.get("ab_status", "")).upper()
            measurement_state = str(
                doctor.get("measurement_state", evaluator.get("measurement_state", "BLOCKED_BY_DATA"))
            ).upper()
            anti_goodhart_triggered, anti_goodhart_err = _anti_goodhart_from_sot(run_id)
            if anti_goodhart_err:
                mapped_decision = "HOLD_NEED_DATA"
                pre_blocked.append(anti_goodhart_err)
            if (
                hypothesis_review_enforce
                and int(hypothesis_review_summary.get("refuted_high_count", 0) or 0) > 0
                and mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}
            ):
                mapped_decision = "HOLD_NEED_DATA"
                pre_blocked.append("hypothesis_refuted_high")
            top_h = _extract_top_portfolio_hypothesis(doctor)
            top_target_goal = _goal_from_target_metric(str(top_h.get("target_metric", "")).strip())
            ab_primary_metric = str((((ab_v2 or {}).get("primary_metric", {}) if isinstance(ab_v2, dict) else {}) or {}).get("name") if isinstance((((ab_v2 or {}).get("primary_metric", {}) if isinstance(ab_v2, dict) else {})), dict) else "")
            if not ab_primary_metric and isinstance(ab, dict):
                ab_primary_metric = str(((ab.get("summary") or {}).get("primary_metric", "")) if isinstance(ab.get("summary"), dict) else "")
            ab_primary_goal = goal_from_metric(ab_primary_metric)
            goal_metric_alignment_ok = bool(top_target_goal != "unknown" and ab_primary_goal != "unknown" and top_target_goal == ab_primary_goal)
            if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and not assignment_ready:
                mapped_decision = "HOLD_NEED_DATA"
                pre_blocked.append("missing_assignment_log")
            if evaluator_ab_status == "METHODOLOGY_MISMATCH":
                mapped_decision = "STOP"
                pre_blocked.append("measurement_blind_spot")
            if evaluator_ab_status == "INVALID_METHODS":
                if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                    mapped_decision = "HOLD_NEED_DATA"
                pre_blocked.append("invalid_methods")
            if is_measurement_blocked(measurement_state):
                # Hard governance gate: never allow rollout/run-ab when measurement is not observable.
                if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                    mapped_decision = "HOLD_NEED_DATA"
                pre_blocked.append(f"measurement_state_{measurement_state.lower()}")
            if not goal_metric_alignment_ok and (top_target_goal != "unknown" or ab_primary_goal != "unknown"):
                mapped_decision = "STOP"
                pre_blocked.append("goal_metric_misalignment")
            if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and evaluator_ab_status == "ASSIGNMENT_RECOVERED":
                mapped_decision = "HOLD_RISK"
                pre_blocked.append("assignment_recovered_post_hoc")
            if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and anti_goodhart_triggered:
                mapped_decision = "HOLD_RISK"
                pre_blocked.append("goodhart_guardrail_violation")
            if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and not exp_id:
                mapped_decision = "HOLD_NEED_DATA"
                pre_blocked.append("missing_experiment_id")
            next_exp = _build_next_experiment(
                doctor=doctor,
                decision=mapped_decision,
                start_date=datetime.now(timezone.utc).date(),
            )
            act_list = active_exp if isinstance(active_exp, list) else []
            next_exp, interference_blocked = _apply_interference(next_exp, act_list)
            pre_blocked.extend(interference_blocked)
            if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and "interference_high" in interference_blocked:
                mapped_decision = "HOLD_RISK"
            ensemble_path = Path(f"data/ensemble_reports/{_base_run_id(run_id)}_ensemble.json")
            if ensemble_path.exists():
                ens, ens_err = _try_load_json(ensemble_path)
                if ens_err:
                    pre_blocked.append("ensemble_summary_unreadable")
                elif isinstance(ens, dict) and bool(ens.get("stability_pass", True)) is False and mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                    mapped_decision = "HOLD_RISK"
                    pre_blocked.append("ensemble_stability_fail")
            else:
                pre_blocked.append("ensemble_summary_missing")
            methodology_check = _compute_methodology_check(
                doctor=doctor,
                evaluator=evaluator,
                metrics_snapshot=metrics,
                ab=ab if isinstance(ab, dict) else None,
                ab_v2=ab_v2 if isinstance(ab_v2, dict) else None,
            )
            if methodology_check.get("decision_rule_result") == "INCONCLUSIVE" and mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                mapped_decision = "HOLD_RISK"
                pre_blocked.append("stats_inconclusive")
            if methodology_check.get("sample_size_imbalance") or methodology_check.get("underpowered"):
                if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                    mapped_decision = "HOLD_RISK"
                if methodology_check.get("underpowered"):
                    pre_blocked.append("underpowered_need_longer_window_or_higher_treat_pct")
                if methodology_check.get("sample_size_imbalance"):
                    pre_blocked.append("sample_size_imbalance")
            blocked_by = _collect_blocked_by(doctor, captain, pre_blocked)
            goals = _compute_goal_blocks(
                doctor=doctor,
                metrics_snapshot=metrics,
                ab=ab if isinstance(ab, dict) else None,
            )
            # Expected impact reconfirmation through MDE / baseline volatility (deterministic proxy).
            mde = methodology_check.get("mde")
            try:
                mde_f = float(mde) if mde is not None else None
            except Exception:
                mde_f = None
            if goals:
                g0 = goals[0]
                exp_rng = str(g0.get("expected_impact_range") or "")
                changed = False
                correction_reason = None
                if mde_f is not None and mde_f > 0 and exp_rng:
                    # Conservative rule: if expected min effect magnitude < MDE, mark not accepted and propose corrected range.
                    nums = re.findall(r"[-+]?\\d+(?:\\.\\d+)?", exp_rng.replace("%", ""))
                    if nums:
                        vals = [abs(float(x)) for x in nums[:2]]
                        if vals and min(vals) < (mde_f * 100):
                            g0["expected_impact_accepted"] = False
                            g0["expected_impact_changed"] = True
                            g0["corrected_expected_impact_range"] = f">= {round(mde_f * 100, 2)}% detectable effect"
                            correction_reason = "baseline_volatility_mde_gate"
                            changed = True
                            if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                                mapped_decision = "HOLD_RISK"
                                pre_blocked.append("expected_impact_below_mde")
                if not changed:
                    g0["expected_impact_accepted"] = bool(exp_rng)
                if correction_reason:
                    g0["correction_reason"] = correction_reason
            cohort_analysis = _load_cohort_analysis_for_commander(
                run_id=run_id,
                doctor_context=(doctor_context if isinstance(doctor_context, dict) else None),
            )
            if (
                str(cohort_analysis.get("status", "")).upper() == "BLOCKED_BY_DATA"
                and isinstance(doctor_context, dict)
                and isinstance(doctor_context.get("goal_blocks"), dict)
            ):
                cohort_analysis.setdefault("notes", [])
                if isinstance(cohort_analysis.get("notes"), list):
                    cohort_analysis["notes"].append("doctor_context present, but cohort pack is missing/blocked.")
            if mapped_decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and cohort_analysis["status"] == "BLOCKED_BY_DATA":
                pre_blocked.append("cohort_analysis_blocked_by_data")
            data_requests = _build_data_requests(
                run_id=run_id,
                methodology_check=methodology_check,
                cohort_blocked=(cohort_analysis["status"] == "BLOCKED_BY_DATA"),
            )
            payload = {
                "run_id": run_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "decision": mapped_decision,
                "normalized_decision": mapped_decision,
                "generated_by": "scripts/run_commander_priority.py",
                "contract_version": "commander_priority.v1",
                "decision_contract_version": str(decision_contract.get("version", "decision_contract_v1")),
                "schema_version": "commander_priority_output.v1",
                "hypothesis_review_mode": hypothesis_review_mode,
                "doctor_hypothesis_review": doctor_hypothesis_review,
                "hypothesis_review_summary": hypothesis_review_summary,
                "review_blockers": review_blockers,
                "hypothesis_review_llm_provenance": hypothesis_review_llm_provenance,
                "blocked_by": blocked_by,
                "top_priorities": _top_priorities(mapped_decision, blocked_by, next_exp),
                "next_experiment": next_exp,
                "weekly_report_bullets": [],
                "inputs_summary": {
                    "captain_verdict": captain_verdict if captain_verdict in {"PASS", "WARN", "FAIL"} else None,
                    "doctor_decision": doctor_decision_summary,
                    "evaluator_decision": evaluator_decision_summary,
                    "measurement_state": measurement_state,
                    "dq_fail_count": dq_fail_count,
                    "dq_warn_count": dq_warn_count,
                },
                "goals": goals,
                "methodology_check": methodology_check,
                "cohort_analysis": cohort_analysis,
                "top_reasons": blocked_by[:5],
                "data_requests": data_requests,
                "historical_context": {
                    "used": True,
                    "pack_ref": str(historical_context_pack_path),
                    "retrieved_rows": len(hist_rows),
                },
                "trace_refs": [
                    f"artifact:{historical_context_pack_path}#",
                    f"artifact:data/agent_reports/{run_id}_doctor_variance.json#",
                ],
                "artifact_hash_refs": (
                    [
                        {
                            "artifact_ref": str(historical_context_pack_path),
                            "sha256": historical_context_pack_sha256,
                        }
                    ]
                    if historical_context_pack_sha256
                    else []
                ),
                "anti_goodhart_triggered": anti_goodhart_triggered,
                "version": VERSION,
                "domain_template_path": domain_template_source(),
                "prompt_profile": {
                    "name": "commander_decision_scientist_v2",
                    "system_prompt_embedded": True,
                },
                "react_config": {
                    "enabled": int(args.enable_react_commander) == 1,
                    "max_steps": int(args.react_max_steps),
                    "tool_policy": "read_only_json_md_csv",
                    "forbidden": ["db_write", "file_write_outside_artifacts", "migrations"],
                    "steps": ["Read Evidence", "Check Gates", "Reason", "Decide"],
                },
                "evidence_refs": {
                    "doctor": f"data/agent_reports/{run_id}_doctor_variance.json",
                    "evaluator": f"data/agent_reports/{run_id}_experiment_evaluator.json",
                    "metrics_snapshot": f"data/metrics_snapshots/{run_id}.json",
                    "ab_report": (f"data/ab_reports/{run_id}_{exp_id}_ab.json" if exp_id else None),
                    "ab_report_v2": (f"data/ab_reports/{run_id}_{exp_id}_ab_v2.json" if exp_id else None),
                    "anti_goodhart_verdict": f"data/agent_quality/{run_id}_anti_goodhart_verdict.json",
                    "dq_report": f"data/dq_reports/{run_id}.json",
                    "synthetic_bias": f"data/realism_reports/{run_id}_synthetic_bias.json",
                    "narrative_validation": f"reports/L1_ops/{run_id}/causal_claims_validation.json" if isinstance(narrative_validation, dict) else None,
                    "doctor_context": f"data/agent_context/{run_id}_doctor_context.json" if isinstance(doctor_context, dict) else None,
                    "historical_context_pack": f"artifact:{historical_context_pack_path}#",
                    "cohort_evidence_pack": f"reports/L1_ops/{run_id}/cohort_evidence_pack.json",
                },
            }
            _attach_commander_llm_reasoning(payload, args.backend)
            _apply_commander_llm_decision_merge(payload)
            _enforce_hypothesis_review_ceiling(payload, enforce=hypothesis_review_enforce)
            payload["weekly_report_bullets"] = _llm_bullets(payload, args.backend)
            # Decision-cap next actions refinement.
            if payload["normalized_decision"] == "HOLD_NEED_DATA":
                payload["next_actions"] = [
                    {"type": "measurement_fix_plan", "steps": _build_commander_measurement_fix_plan(doctor, methodology_check)},
                ]
            elif payload["normalized_decision"] == "STOP":
                payload["next_actions"] = [
                    {"type": "safer_alternative", "title": "Run an aligned experiment from domain template or fix observability before next hypothesis test."}
                ]
            elif payload["normalized_decision"] == "RUN_AB" and isinstance(payload.get("next_experiment"), dict):
                ne = payload["next_experiment"]
                payload["next_actions"] = [
                    {
                        "type": "run_ab",
                        "experiment_id": ne.get("name"),
                        "unit": ne.get("unit"),
                        "treat_pct": 50,
                        "duration_days": 14,
                        "primary_metric": (goals[0].get("primary_metric") if goals else None),
                        "guardrails": goals[0].get("guardrails") if goals else [],
                        "stop_conditions": _stop_conditions_from_guardrails(goals[0].get("guardrails", []) if goals else []),
                }
            ]
            else:
                payload.setdefault("next_actions", [])
            payload["blocked_by"] = _collect_blocked_by(doctor, captain, pre_blocked)
            payload["top_reasons"] = payload["blocked_by"][:5]
            payload["domain_template_path"] = domain_template_source()

        payload.update(
            _build_mitigation_proposals(
                run_id=run_id,
                decision=str(payload.get("normalized_decision", payload.get("decision", ""))),
                blocked_by=(payload.get("blocked_by", []) if isinstance(payload.get("blocked_by"), list) else []),
                methodology_check=(payload.get("methodology_check", {}) if isinstance(payload.get("methodology_check"), dict) else {}),
            )
        )

        if "llm_decision_provenance" not in payload:
            _attach_commander_llm_reasoning(payload, args.backend)
            _apply_commander_llm_decision_merge(payload)
        _enforce_hypothesis_review_ceiling(payload, enforce=hypothesis_review_enforce)
        payload["domain_template_path"] = domain_template_source()
        _attach_phase_flags_and_visible_trace(payload)
        llm_decision_prov = (
            payload.get("llm_decision_provenance", {})
            if isinstance(payload.get("llm_decision_provenance"), dict)
            else {}
        )
        provisional_local_fallback = bool(
            bool(llm_decision_prov.get("needs_cloud_reconciliation", False))
        )
        payload["fallback_tier"] = str(llm_decision_prov.get("fallback_tier", "none") or "none")
        payload["fallback_reason"] = (
            str(llm_decision_prov.get("fallback_reason", "")).strip() or payload.get("fallback_reason")
        )
        payload["provisional_local_fallback"] = provisional_local_fallback
        payload["needs_cloud_reconciliation"] = provisional_local_fallback
        validate_decision(str(payload.get("decision", "")), decision_contract, "decision")
        validate_decision(str(payload.get("normalized_decision", "")), decision_contract, "normalized_decision")
        validate_required_fields(payload, decision_contract, "commander")
        _validate_mitigation_policy(payload)
        _validate_commander_policy_contract(payload)
        safe_payload = _redact_obj(payload)
        out_json.write_text(json.dumps(safe_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(out_json)
        out_md.write_text(_redact_text(_to_markdown(safe_payload)), encoding="utf-8")
        memo_path = Path(f"reports/L1_ops/{run_id}/COMMANDER_60S_MEMO.md")
        memo_path.parent.mkdir(parents=True, exist_ok=True)
        memo_path.write_text(_redact_text(_render_commander_60s_memo(run_id, safe_payload)), encoding="utf-8")
        _write_approvals_registry(
            run_id,
            doctor=doctor if isinstance(doctor, dict) else {},
            captain=captain if isinstance(captain, dict) else {},
            commander_decision=str(payload.get("decision", "HOLD_NEED_DATA")),
        )
        print(f"ok: commander priority report written for run_id={run_id}")
    except ConfigurationError as exc:
        raise SystemExit(f"ConfigurationError: {exc}")
    except Exception as exc:
        with log_path.open("w", encoding="utf-8") as f:
            f.write(_redact_text(f"{exc}\n{traceback.format_exc()}"))
        # fail-safe: never break pipeline because of PM layer
        payload = _base_hold_payload(run_id, ["invalid_input:unexpected_error"])
        payload["hypothesis_review_mode"] = hypothesis_review_mode
        payload.update(
            _build_mitigation_proposals(
                run_id=run_id,
                decision=str(payload.get("normalized_decision", payload.get("decision", ""))),
                blocked_by=(payload.get("blocked_by", []) if isinstance(payload.get("blocked_by"), list) else []),
                methodology_check={},
            )
        )
        _attach_phase_flags_and_visible_trace(payload)
        safe_payload = _redact_obj(payload)
        out_json.write_text(json.dumps(safe_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(out_json)
        out_md.write_text(_redact_text(_to_markdown(safe_payload)), encoding="utf-8")
        memo_path = Path(f"reports/L1_ops/{run_id}/COMMANDER_60S_MEMO.md")
        memo_path.parent.mkdir(parents=True, exist_ok=True)
        memo_path.write_text(_redact_text(_render_commander_60s_memo(run_id, safe_payload)), encoding="utf-8")
        _write_approvals_registry(run_id, doctor={}, captain={}, commander_decision="HOLD_NEED_DATA")
        print(f"ok: commander priority report written for run_id={run_id} (fail-safe)")


if __name__ == "__main__":
    main()
