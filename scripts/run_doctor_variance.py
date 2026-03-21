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
import math

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.llm_contract_utils import coerce_string, coerce_string_list, parse_json_object_loose
from src.model_policy import DOCTOR_GROQ_FALLBACK_MODEL, DOCTOR_GROQ_PRIMARY_MODEL
from src.decision_contract import load_decision_contract, validate_decision, validate_required_fields
from src.domain_template import (
    ConfigurationError,
    domain_guardrails_for,
    domain_goal_definitions,
    load_domain_template,
    domain_goal_default_metrics,
    domain_goal_expected_direction,
    domain_goal_metric_sets,
    domain_signal_metric_to_target_metric,
    domain_target_metric_alias_to_goal,
    domain_target_metric_aliases,
    domain_target_metric_to_primary_metric,
    domain_template_source,
    domain_thresholds_for,
    set_domain_template_override,
)
from src.reasoning_feature_flags import load_reasoning_feature_flags
from src.semantic_scoring import hypothesis_format_ok
from src.status_taxonomy import goal_from_metric
from src.architecture_v3 import load_json_optional_with_integrity, paired_experiment_context_path, stat_evidence_bundle_path
from src.security_utils import sha256_sidecar_path, write_sha256_sidecar
from src.visible_reasoning_trace import build_visible_reasoning_trace_advisory
from src.runtime_failover import build_runtime_failover_tiers, generate_with_runtime_failover
from src.stat_engine import compute_stat_evidence

DOCTOR_VARIANCE_GROQ_MODEL = DOCTOR_GROQ_FALLBACK_MODEL
DOCTOR_VARIANCE_DEEPSEEK_MODEL = DOCTOR_GROQ_PRIMARY_MODEL
ENABLE_VISIBLE_REASONING_TRACE = 0
CAPTAIN_ALLOW_NOVEL_ISSUES = 0
DOCTOR_DYNAMIC_HYPOTHESES = 0
REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]
CANONICAL_STANDARD_PATH = Path("human_reports/L1/v13_ab_final_003/канонический_стандарт.md")
GOLDEN_AB_REPORT_PATH = Path("human_reports/L1/v13_ab_final_003/AB_stat_report_standart.md")
GOLDEN_DECISION_CARD_PATH = Path("reports/L1_ops/v13_agent_prod_013/Decision Card_standard.md")
_DOMAIN_REFERENCE_CHAR_LIMIT = 2600
_DOMAIN_REFERENCE_CACHE: dict[str, Any] | None = None
DOCTOR_SYSTEM_PROMPT_V2 = """SYSTEM: You are Doctor Variance, a Principal Retail Experiment Scientist.
Your job is to produce measurable business value while obeying strict measurement and causality rules.

NON-NEGOTIABLE:
1) Never invent facts; use only provided artifacts/fields.
2) Lock primary metric to experiment north_star_metric / AB primary_metric.
   - Never substitute primary metric with supporting or guardrail metrics.
   - CRITICAL GOAL ALIGNMENT RULE: hypothesis_portfolio for the current AB contour must stay aligned with ab_primary_goal.
     Cross-goal ideas are allowed only as `next experiment` references, not as current-goal replacements.
3) If ab_status in {MISSING_ASSIGNMENT, METHODOLOGY_MISMATCH, INVALID_METHODS, ASSIGNMENT_RECOVERED}
   OR measurement_state in {UNOBSERVABLE, BLOCKED_BY_DATA}:
   - Do NOT claim uplift, do NOT recommend RUN_AB or ROLLOUT.
   - Output MUST include measurement_fix_plan with concrete redo steps.
4) Respect canonical AB causality:
   - If randomization unit and analysis unit are inconsistent, flag causal risk.
   - If SRM is not PASS, treat inference as risk and request assignment/sampling fix.
   - Guardrail breaches can veto rollout even when primary looks positive.
5) Every claim must cite numeric evidence_refs (metric names + values).
6) Output JSON only, schema-valid.

TASK:
Given decision_card + metrics_snapshot + ab_report (if valid) + dq + synthetic_bias + commander/evaluator:
A) Build >=3 hypothesis_portfolio items across configured goals from domain_template.
B) For each hypothesis include: action, mechanism, target_metric, expected_uplift_range, guardrails from domain_template,
   falsifiability, and design contract fields (pre_period_weeks, wash_in_days, attribution_window_rule, test_side).
C) LIVE EXPERIMENT EVIDENCE (Layers 1+2) is mandatory for paired COMPLETE runs:
   - layer1_verdict from stat_evidence_bundle_v1 (primary metric inference)
   - layer2_guardrail_verdicts from stat_evidence_bundle_v1 (guardrail veto surface)
   - if Layers 1+2 are missing/underpowered/inconclusive, keep conservative ceiling (no aggressive decision).
D) If AB is valid and aligned, interpret with strict hypothesis testing:
   - H0: treatment == control
   - alpha=0.05 unless specified
   - p<=alpha and CI excludes 0 => Reject H0
   - p>alpha => Fail to Reject H0
   - p/CI inconsistency => INCONCLUSIVE with method explanation
E) If AB is invalid/misaligned, return measurement_fix_plan with missing items, 3 minimal steps, expected measurable outcome.

ALLOWED METHODS:
- Continuous: Welch t-test (bootstrap if heavy skew)
- Proportions/counts: two-proportion / chi-square / bootstrap
- Ratio metrics: bootstrap or delta method

STYLE:
- Be concise and falsifiable.
- Explicitly state trade-offs and causal limitations.
"""


def _doctor_model_override_for_backend(backend_name: str, model_override: str | None = None) -> str | None:
    if backend_name in {"groq", "auto"}:
        return model_override or DOCTOR_VARIANCE_GROQ_MODEL
    return None
DOCTOR_METHOD_SELECTION_SYSTEM_PROMPT = """SYSTEM: You are Domain_Analyst for A/B methodology (Doctor Variance method layer).
Pick a statistical methodology for one experiment with strict canonical alignment.

Rules:
- Output JSON only (no markdown).
- Primary metric must match provided primary_metric exactly.
- Use canonical context + golden examples as structural anchors, not as data sources.
- Validate causal consistency: randomization unit, analysis unit, SRM status, measurement_state, ab_status.
- If preconditions are weak, choose conservative method and state caveats.
- Do not invent unavailable fields.
"""
OUTPUT_CONTRACT_VERSION = "doctor_variance.v1"
METRICS_CONTRACT_VERSION = "metrics_contract_v1"

BASE_DEFAULT_THRESHOLDS: dict[str, Any] = {
    "mvp_mode_one_experiment": True,
}

BASE_READY_NOW_METRICS: set[str] = set()
BASE_REQUIRED_READY_NOW: set[str] = set()
BASE_BLOCKED_PHASE2_METRICS: list[str] = []
DEFAULT_THRESHOLDS: dict[str, Any] = dict(BASE_DEFAULT_THRESHOLDS)
READY_NOW_METRICS = set(BASE_READY_NOW_METRICS)
REQUIRED_READY_NOW = set(BASE_REQUIRED_READY_NOW)
BLOCKED_PHASE2_METRICS = list(BASE_BLOCKED_PHASE2_METRICS)
GOAL_DEFAULT_PRIMARY_MAP: dict[str, str] = {}
TARGET_METRIC_PRIMARY_MAP: dict[str, str] = {}
METRIC_TO_GOAL: dict[str, str] = {}
ALLOWED_TARGET_METRICS = set(TARGET_METRIC_PRIMARY_MAP.keys())
GOAL_ORDER: list[str] = []
DOCTOR_GUARDRAILS: list[dict[str, Any]] = []
DOCTOR_CAPTAIN_ISSUE_POLICIES: dict[str, dict[str, Any]] = {}
DOCTOR_RUN_CONFIG_RULES: list[dict[str, Any]] = []

CONFIDENCE_TO_NUM = {"low": 0.6, "med": 0.8, "high": 1.0}
AB_MIN_UNITS_PER_ARM = 200
AB_MIN_ORDERS_PER_ARM = 500


def _apply_domain_template(domain_template_path: str = "") -> dict[str, Any]:
    global DEFAULT_THRESHOLDS
    global READY_NOW_METRICS
    global REQUIRED_READY_NOW
    global BLOCKED_PHASE2_METRICS
    global GOAL_DEFAULT_PRIMARY_MAP
    global TARGET_METRIC_PRIMARY_MAP
    global METRIC_TO_GOAL
    global ALLOWED_TARGET_METRICS
    global GOAL_ORDER
    global DOCTOR_GUARDRAILS
    global DOCTOR_CAPTAIN_ISSUE_POLICIES
    global DOCTOR_RUN_CONFIG_RULES

    cfg = load_domain_template(domain_template_path)
    doctor_cfg = cfg.get("doctor", {}) if isinstance(cfg.get("doctor"), dict) else {}
    template_thresholds = {}
    if isinstance(cfg.get("thresholds"), dict):
        template_thresholds = cfg.get("thresholds", {}).get("doctor_variance", {})
    if not isinstance(template_thresholds, dict):
        template_thresholds = {}
    if isinstance(doctor_cfg.get("thresholds"), dict):
        template_thresholds = {**template_thresholds, **doctor_cfg.get("thresholds", {})}
    merged_thresholds = dict(BASE_DEFAULT_THRESHOLDS)
    merged_thresholds.update(template_thresholds)
    DEFAULT_THRESHOLDS = merged_thresholds

    required_ready_now = doctor_cfg.get("required_ready_now")
    blocked_phase2 = doctor_cfg.get("blocked_phase2_metrics")
    READY_NOW_METRICS = set(BASE_READY_NOW_METRICS)
    goals = cfg.get("goals", [])
    if isinstance(goals, list):
        for goal in goals:
            if not isinstance(goal, dict):
                continue
            goal_id = str(goal.get("goal_id", "")).strip().lower()
            metric = str(goal.get("default_primary_metric", "")).strip()
            if goal_id and metric:
                READY_NOW_METRICS.add(metric)
            risk_metric = str(goal.get("commander_default_metric", "")).strip()
            if risk_metric:
                READY_NOW_METRICS.add(risk_metric)
    metric_groups = cfg.get("metrics", {}).get("goal_metric_groups", {}) if isinstance(cfg.get("metrics"), dict) else {}
    if isinstance(metric_groups, dict):
        for values in metric_groups.values():
            if isinstance(values, list):
                READY_NOW_METRICS.update(str(x) for x in values if str(x).strip())
    if isinstance(cfg.get("metrics"), dict):
        READY_NOW_METRICS.update(str(x) for x in cfg["metrics"].get("secondary", []) if str(x).strip())
    guardrails = domain_guardrails_for("doctor_variance")
    DOCTOR_GUARDRAILS = [dict(row) for row in guardrails if isinstance(row, dict)]
    if not DOCTOR_GUARDRAILS:
        raise ConfigurationError("Missing Domain Template doctor guardrails")
    for row in DOCTOR_GUARDRAILS:
        metric_name = str(row.get("metric", "")).strip()
        if metric_name:
            READY_NOW_METRICS.add(metric_name)
    default_required: list[str] = []
    for row in DOCTOR_GUARDRAILS:
        metric_name = str(row.get("metric", "")).strip()
        if metric_name:
            default_required.append(metric_name)
    if isinstance(goals, list):
        for goal in goals:
            if not isinstance(goal, dict):
                continue
            txt = str(goal.get("default_primary_metric", "")).strip()
            if txt:
                default_required.append(txt)
    REQUIRED_READY_NOW = {
        str(x).strip()
        for x in (required_ready_now if isinstance(required_ready_now, list) and required_ready_now else default_required)
        if str(x).strip()
    }
    if not REQUIRED_READY_NOW:
        raise ConfigurationError("Missing Domain Template required_ready_now metrics")
    BLOCKED_PHASE2_METRICS = [str(x) for x in (blocked_phase2 if isinstance(blocked_phase2, list) else list(BASE_BLOCKED_PHASE2_METRICS)) if str(x).strip()]
    captain_issue_policies = doctor_cfg.get("captain_issue_policies") if isinstance(doctor_cfg.get("captain_issue_policies"), dict) else {}
    DOCTOR_CAPTAIN_ISSUE_POLICIES = {}
    for check_name, policy in captain_issue_policies.items():
        key = str(check_name or "").strip()
        if not key or not isinstance(policy, dict):
            continue
        DOCTOR_CAPTAIN_ISSUE_POLICIES[key] = {
            "on_hard_fail": str(policy.get("on_hard_fail", "")).strip().upper(),
            "on_warn": str(policy.get("on_warn", "")).strip().upper(),
            "on_info": str(policy.get("on_info", "")).strip().upper(),
            "risk_type": str(policy.get("risk_type", "template_policy")).strip() or "template_policy",
            "mitigation": str(policy.get("mitigation", "")).strip(),
        }
    run_config_rules = doctor_cfg.get("run_config_rules") if isinstance(doctor_cfg.get("run_config_rules"), list) else []
    DOCTOR_RUN_CONFIG_RULES = [dict(rule) for rule in run_config_rules if isinstance(rule, dict)]

    target_map = cfg.get("target_metric_to_primary_metric") if isinstance(cfg.get("target_metric_to_primary_metric"), dict) else {}
    GOAL_DEFAULT_PRIMARY_MAP = {}
    GOAL_ORDER = []
    if isinstance(goals, list):
        for goal in goals:
            if not isinstance(goal, dict):
                continue
            goal_id = str(goal.get("goal_id", "")).strip().lower()
            primary_metric = str(goal.get("default_primary_metric", "")).strip()
            if goal_id and primary_metric:
                GOAL_DEFAULT_PRIMARY_MAP[goal_id] = primary_metric
                GOAL_ORDER.append(goal_id)
    TARGET_METRIC_PRIMARY_MAP = {
        str(k).strip(): str(v).strip()
        for k, v in target_map.items()
        if str(k).strip() and str(v).strip()
    }
    if not GOAL_DEFAULT_PRIMARY_MAP:
        raise ConfigurationError("Domain template must provide goal default primary metrics")
    if not TARGET_METRIC_PRIMARY_MAP:
        raise ConfigurationError("Domain template must provide target_metric_to_primary_metric mapping")
    metric_to_goal: dict[str, str] = {}
    if isinstance(metric_groups, dict):
        for goal_id_raw, values in metric_groups.items():
            goal_id = str(goal_id_raw or "").strip().lower()
            if not goal_id or not isinstance(values, list):
                continue
            for metric in values:
                mm = str(metric).strip().lower()
                if mm:
                    metric_to_goal[mm] = goal_id
    alias_to_goal = domain_target_metric_alias_to_goal()
    for alias, goal_id in alias_to_goal.items():
        aa = str(alias).strip().lower()
        gg = str(goal_id).strip().lower()
        if aa and gg:
            metric_to_goal[aa] = gg
    METRIC_TO_GOAL = metric_to_goal
    ALLOWED_TARGET_METRICS = set(TARGET_METRIC_PRIMARY_MAP.keys())
    if not ALLOWED_TARGET_METRICS:
        raise ConfigurationError("Domain template must define at least one target metric alias")
    return cfg


def _redact_text(value: str) -> str:
    out = value
    for pattern, replacement in REDACTION_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_redact_obj(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_obj(v) for k, v in value.items()}
    return value


def _active_feature_flags() -> dict[str, int]:
    return load_reasoning_feature_flags(
        {
            "ENABLE_VISIBLE_REASONING_TRACE": ENABLE_VISIBLE_REASONING_TRACE,
            "CAPTAIN_ALLOW_NOVEL_ISSUES": CAPTAIN_ALLOW_NOVEL_ISSUES,
            "DOCTOR_DYNAMIC_HYPOTHESES": DOCTOR_DYNAMIC_HYPOTHESES,
        }
    )


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing {label}: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _load_text_optional(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _excerpt_for_prompt(text: str, max_chars: int = _DOMAIN_REFERENCE_CHAR_LIMIT) -> str:
    compact = re.sub(r"\n{3,}", "\n\n", str(text or "").strip())
    if len(compact) <= max_chars:
        return compact
    return compact[: max_chars - 17].rstrip() + "\n...[truncated]"


def _ordered_goal_ids() -> list[str]:
    if GOAL_ORDER:
        return [x for x in GOAL_ORDER if str(x).strip()]
    defs = domain_goal_definitions()
    out = [str(x.get("goal_id", "")).strip().lower() for x in defs if isinstance(x, dict) and str(x.get("goal_id", "")).strip()]
    if not out:
        raise ConfigurationError("Domain template must define at least one goal")
    return out


def _default_goal_id() -> str:
    goals = _ordered_goal_ids()
    return goals[0]


def _default_target_metric_alias() -> str:
    alias_map = _goal_to_target_alias_map()
    default_goal = _default_goal_id()
    alias = str(alias_map.get(default_goal, "")).strip()
    if alias:
        return alias
    aliases = sorted(domain_target_metric_aliases())
    if not aliases:
        raise ConfigurationError("Domain template must define target metric aliases")
    return aliases[0]


def _goal_to_default_metric(goal: str) -> str:
    g = str(goal or "").strip().lower()
    alias_map = _goal_to_target_alias_map()
    target_to_primary = domain_target_metric_to_primary_metric()
    alias = alias_map.get(g, "")
    if alias and alias in target_to_primary:
        return str(target_to_primary[alias])
    defaults = domain_goal_default_metrics()
    if g in defaults:
        return str(defaults[g])
    fallback_goal = _default_goal_id()
    if fallback_goal in defaults:
        return str(defaults[fallback_goal])
    raise ConfigurationError("Domain template default primary metric is missing")


def _resolve_experiment_primary_metric(experiment: dict[str, Any]) -> str:
    for key in ("primary_metric_id", "north_star_metric", "primary_metric"):
        metric = str(experiment.get(key, "")).strip()
        if metric:
            return metric
    success_metrics = experiment.get("success_metrics", [])
    if isinstance(success_metrics, list):
        for item in success_metrics:
            candidate = str(item or "").strip()
            if candidate:
                return candidate
    return ""


def _target_metric_to_primary_metric(target_metric: str) -> str:
    mapping = domain_target_metric_to_primary_metric()
    if not mapping:
        raise ConfigurationError("Domain template target-to-primary mapping is missing")
    target = str(target_metric or "").strip()
    return mapping.get(target, target)


def _target_metric_expected_direction(target_metric: str) -> str:
    alias_to_goal = domain_target_metric_alias_to_goal()
    goal_id = alias_to_goal.get(str(target_metric or "").strip(), "")
    goal_directions = domain_goal_expected_direction()
    direction = goal_directions.get(goal_id, "")
    if direction in {"increase", "decrease"}:
        return direction
    return "increase"


def _goal_to_target_alias_map() -> dict[str, str]:
    alias_to_goal = domain_target_metric_alias_to_goal()
    out = {goal: alias for alias, goal in alias_to_goal.items()}
    if out:
        return out
    raise ConfigurationError("Domain template alias-to-goal mapping is missing")


def _extract_srm_status(ab_report: dict[str, Any] | None) -> str:
    if not isinstance(ab_report, dict):
        return "MISSING"
    summary = ab_report.get("summary", {}) if isinstance(ab_report.get("summary"), dict) else {}
    guardrail_checks = summary.get("guardrail_checks", {}) if isinstance(summary.get("guardrail_checks"), dict) else {}
    sampling = ab_report.get("sampling", {}) if isinstance(ab_report.get("sampling"), dict) else {}
    for raw in [summary.get("srm_status"), guardrail_checks.get("srm_status"), sampling.get("srm_status")]:
        txt = str(raw or "").strip().upper()
        if txt:
            return txt
    return "MISSING"


def _llm_methodology_preflight_issue(
    experiment: dict[str, Any],
    measurement_state: str,
    ab_status: str,
    srm_status: str,
) -> str | None:
    if not _resolve_experiment_primary_metric(experiment):
        return "missing_primary_metric"
    if str(measurement_state or "").upper() in {"UNOBSERVABLE", "BLOCKED_BY_DATA"}:
        return "measurement_unobservable"
    if str(ab_status or "").upper() in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "INVALID_METHODS", "ASSIGNMENT_RECOVERED"}:
        return "ab_status_blocked"
    if str(srm_status or "").upper() in {"WARN", "FAIL"}:
        return "srm_not_pass"
    return None


def _domain_reference_pack() -> dict[str, Any]:
    global _DOMAIN_REFERENCE_CACHE
    if _DOMAIN_REFERENCE_CACHE is not None:
        return _DOMAIN_REFERENCE_CACHE

    canonical_text = _load_text_optional(CANONICAL_STANDARD_PATH)
    golden_ab_text = _load_text_optional(GOLDEN_AB_REPORT_PATH)
    golden_decision_text = _load_text_optional(GOLDEN_DECISION_CARD_PATH)
    _DOMAIN_REFERENCE_CACHE = {
        "sources": {
            "canonical_standard": str(CANONICAL_STANDARD_PATH),
            "golden_ab_report": str(GOLDEN_AB_REPORT_PATH),
            "golden_decision_card": str(GOLDEN_DECISION_CARD_PATH),
            "canonical_sha1": hashlib.sha1(canonical_text.encode("utf-8")).hexdigest() if canonical_text else None,
            "golden_ab_sha1": hashlib.sha1(golden_ab_text.encode("utf-8")).hexdigest() if golden_ab_text else None,
            "golden_decision_sha1": hashlib.sha1(golden_decision_text.encode("utf-8")).hexdigest() if golden_decision_text else None,
        },
        "canonical_rules": [
            "Primary metric must be explicit and stable across design, method, and interpretation.",
            "Decreasing-goal interpretation must avoid false wins from denominator drift; ratio semantics must be explicit.",
            "Inbound/inventory changes require store-time causal analysis and clear randomization/analysis unit consistency.",
            "Rollout requires primary effect evidence and safe guardrails; otherwise hold/stop with fix plan.",
            "If causality prerequisites fail (SRM, assignment, methodology mismatch), no uplift claims are allowed.",
        ],
        "canonical_excerpt": _excerpt_for_prompt(canonical_text),
        "golden_examples": {
            "ab_report_excerpt": _excerpt_for_prompt(golden_ab_text),
            "decision_card_excerpt": _excerpt_for_prompt(golden_decision_text),
        },
    }
    return _DOMAIN_REFERENCE_CACHE


def _reason(code: str, severity: str, message: str, refs: list[str]) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "evidence_refs": refs,
    }


def _load_thresholds() -> dict[str, Any]:
    out = dict(DEFAULT_THRESHOLDS)
    out.update(domain_thresholds_for("doctor_variance"))
    return out


def _doctor_guardrails(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    rows = domain_guardrails_for("doctor_variance")
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        metric = str(row.get("metric", "")).strip()
        op = str(row.get("op", "")).strip()
        if not metric or op not in {">=", "<=", ">", "<"}:
            continue
        threshold = row.get("threshold")
        if row.get("dynamic_baseline_ratio") is not None:
            baseline = float(metrics.get(metric) or 0.0)
            ratio = float(row.get("dynamic_baseline_ratio") or 0.0)
            threshold = max(0.0, baseline * ratio) if baseline > 0 else 0.0
        try:
            threshold_value = float(threshold)
        except Exception:
            continue
        out.append(
            {
                "metric": metric,
                "op": op,
                "threshold": threshold_value,
                "severity": str(row.get("severity", "WARN")).strip().upper() or "WARN",
            }
        )
    if out:
        return out
    raise ConfigurationError("Missing Domain Template doctor guardrails")


def _volume_gate_rules(thresholds: dict[str, Any]) -> list[dict[str, Any]]:
    guardrail_metrics = {str(x.get("metric", "")).strip() for x in _doctor_guardrails({}) if isinstance(x, dict)}
    rules: list[dict[str, Any]] = []
    for key, raw in thresholds.items():
        if not str(key).startswith("min_"):
            continue
        try:
            min_value = float(raw)
        except Exception:
            continue
        metric = str(key)[4:].strip()
        if not metric or metric in guardrail_metrics:
            continue
        if metric not in READY_NOW_METRICS:
            continue
        rules.append({"metric": metric, "min_value": min_value})
    if rules:
        return rules
    numeric_metrics = [m for m in sorted(READY_NOW_METRICS) if str(m).endswith("_cnt")]
    if numeric_metrics:
        return [{"metric": numeric_metrics[0], "min_value": 1.0}]
    return []


def _load_output_schema() -> dict[str, Any]:
    path = Path("configs/doctor/doctor_variance_output_schema.json")
    if not path.exists():
        raise FileNotFoundError("Missing schema file: configs/doctor/doctor_variance_output_schema.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _log_failure(run_id: str, context: str) -> Path:
    log_path = Path(f"data/logs/doctor_variance_{run_id}.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(_redact_text(context + "\n" + traceback.format_exc()), encoding="utf-8")
    return log_path


def _required_metrics_missing(metrics: dict[str, Any]) -> list[str]:
    return [m for m in sorted(REQUIRED_READY_NOW) if metrics.get(m) is None]


def _captain_checks(
    captain: dict[str, Any],
    run_id: str,
) -> tuple[str | None, list[dict[str, Any]], list[dict[str, Any]]]:
    reasons: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    result = captain.get("result", {}) if isinstance(captain.get("result"), dict) else {}
    eval_metrics = captain.get("eval_metrics", {}) if isinstance(captain.get("eval_metrics"), dict) else {}
    captain_issues = result.get("issues", []) if isinstance(result.get("issues"), list) else []
    verdict = str(result.get("verdict", "WARN"))

    if verdict in {"WARN", "FAIL"}:
        reasons.append(
            _reason(
                "captain_warn",
                "WARN",
                f"Captain verdict is {verdict}; proceed with caution",
                [f"artifact:data/llm_reports/{run_id}_captain.json#/result/verdict"],
            )
        )
        risks.append(
            {
                "risk_type": "data_quality",
                "check_name": "captain_verdict",
                "severity": "WARN",
                "mitigation": "Review captain issues and run listed read-only verification SQL",
            }
        )
        for idx, issue in enumerate(captain_issues):
            if not isinstance(issue, dict):
                continue
            check_name = str(issue.get("check_name", f"unknown_{idx}"))
            sev = str(issue.get("severity", "WARN"))
            if sev not in {"WARN", "HARD_FAIL", "INFO"}:
                sev = "WARN"
            reasons.append(
                _reason(
                    f"captain_issue_{check_name}",
                    sev,
                    str(issue.get("message", f"Captain flagged {check_name}")),
                    [f"artifact:data/llm_reports/{run_id}_captain.json#/result/issues/{idx}"],
                )
            )
            if sev in {"WARN", "HARD_FAIL"}:
                risks.append(
                    {
                        "risk_type": "data_quality",
                        "check_name": check_name,
                        "severity": sev,
                        "mitigation": "Run Captain verification_steps SQL/psql in read-only mode",
                    }
                )

    if verdict == "FAIL":
        reasons.append(
            _reason(
                "captain_fail",
                "HARD_FAIL",
                "Captain verdict is FAIL",
                [f"artifact:data/llm_reports/{run_id}_captain.json#/result/verdict"],
            )
        )
        return "STOP", reasons, risks

    if eval_metrics.get("safety") is False:
        reasons.append(
            _reason(
                "captain_safety_fail",
                "HARD_FAIL",
                "Captain safety check failed",
                [f"artifact:data/llm_reports/{run_id}_captain.json#/eval_metrics/safety"],
            )
        )
        return "STOP", reasons, risks

    if eval_metrics.get("no_extra_issues") is False:
        reasons.append(
            _reason(
                "captain_no_extra_issues_fail",
                "HARD_FAIL",
                "Captain produced issues outside DQ checks",
                [f"artifact:data/llm_reports/{run_id}_captain.json#/eval_metrics/no_extra_issues"],
            )
        )
        return "STOP", reasons, risks

    return None, reasons, risks


def _merge_gate_decision(current: str | None, candidate: str | None) -> str | None:
    rank = {None: 0, "": 0, "RUN_AB": 1, "HOLD_RISK": 2, "HOLD_NEED_DATA": 3, "STOP": 4}
    curr = str(current or "").strip().upper() if current else None
    cand = str(candidate or "").strip().upper() if candidate else None
    if rank.get(cand, 0) > rank.get(curr, 0):
        return cand
    return curr


def _enforce_template_captain_issue_policies(captain: dict[str, Any]) -> tuple[str | None, list[dict[str, Any]]]:
    if not DOCTOR_CAPTAIN_ISSUE_POLICIES:
        return None, []
    result = captain.get("result", {}) if isinstance(captain.get("result"), dict) else {}
    issues = result.get("issues", []) if isinstance(result.get("issues"), list) else []
    hits: list[dict[str, Any]] = []
    gate_decision: str | None = None
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        check_name = str(issue.get("check_name", "")).strip()
        policy = DOCTOR_CAPTAIN_ISSUE_POLICIES.get(check_name)
        if not policy:
            continue
        severity = str(issue.get("severity", "WARN")).strip().upper()
        msg = str(issue.get("message", "Captain issue detected"))
        decision_key = "on_warn"
        if severity == "HARD_FAIL":
            decision_key = "on_hard_fail"
        elif severity == "INFO":
            decision_key = "on_info"
        decision = str(policy.get(decision_key, "")).strip().upper()
        if decision not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB"}:
            decision = ""
        gate_decision = _merge_gate_decision(gate_decision, decision)
        hits.append(
            {
                "check_name": check_name,
                "severity": severity,
                "message": msg,
                "decision": decision,
                "risk_type": str(policy.get("risk_type", "template_policy") or "template_policy"),
                "mitigation": str(policy.get("mitigation", "")).strip(),
            }
        )
    return gate_decision, hits


def _enforce_template_run_config_rules(run_cfg: dict[str, Any], run_id: str) -> tuple[str | None, list[dict[str, Any]], list[dict[str, Any]]]:
    if not DOCTOR_RUN_CONFIG_RULES:
        return None, [], []
    gate_decision: str | None = None
    reasons: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    mode_tag = str(run_cfg.get("mode_tag", "") or "").strip().lower()
    for idx, rule in enumerate(DOCTOR_RUN_CONFIG_RULES):
        field = str(rule.get("field", "")).strip()
        if not field:
            continue
        raw_value = run_cfg.get(field)
        truthy_values = rule.get("truthy_values")
        if isinstance(truthy_values, list) and truthy_values:
            truthy_set = {str(x).strip().lower() for x in truthy_values if str(x).strip()}
        else:
            truthy_set = {"1", "true", "yes", "on"}
        if str(raw_value or "").strip().lower() not in truthy_set:
            continue
        required_mode_tag = str(rule.get("required_mode_tag_contains", "")).strip().lower()
        violated = bool(required_mode_tag) and required_mode_tag not in mode_tag
        if not violated:
            continue
        decision = str(rule.get("decision_on_fail", "HOLD_RISK")).strip().upper()
        if decision not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB"}:
            decision = "HOLD_RISK"
        gate_decision = _merge_gate_decision(gate_decision, decision)
        reason_code = str(rule.get("reason_code", "run_config_rule_violation")).strip() or "run_config_rule_violation"
        severity = str(rule.get("severity", "WARN")).strip().upper() or "WARN"
        message = (
            str(rule.get("message", "")).strip()
            or f"Run config rule violated for '{field}': expected mode_tag to include '{required_mode_tag}'."
        )
        check_name = str(rule.get("check_name", f"run_config_rule_{idx}")).strip() or f"run_config_rule_{idx}"
        mitigation = str(rule.get("mitigation", "")).strip() or "Adjust run_config to satisfy template policy."
        risk_type = str(rule.get("risk_type", "confounding")).strip() or "confounding"
        reasons.append(
            _reason(
                reason_code,
                severity,
                message,
                [f"artifact:data/metrics_snapshots/{run_id}.json#/run_config/{field}"],
            )
        )
        risks.append(
            {
                "risk_type": risk_type,
                "check_name": check_name,
                "severity": severity,
                "mitigation": mitigation,
            }
        )
    return gate_decision, reasons, risks


def _guardrail_checks(metrics: dict[str, Any], run_id: str, thresholds: dict[str, Any]) -> tuple[str | None, list[dict[str, Any]]]:
    reasons: list[dict[str, Any]] = []
    hard_fail = False
    for row in _doctor_guardrails(metrics):
        metric = str(row.get("metric", "")).strip()
        op = str(row.get("op", "")).strip()
        threshold = float(row.get("threshold", 0.0) or 0.0)
        value = float(metrics.get(metric) or 0.0)
        violated = (
            (op == ">=" and value < threshold)
            or (op == ">" and value <= threshold)
            or (op == "<=" and value > threshold)
            or (op == "<" and value >= threshold)
        )
        if not violated:
            continue
        severity = "HARD_FAIL" if str(row.get("severity", "WARN")).upper() == "HARD" else "WARN"
        reasons.append(
            _reason(
                f"guardrail_{metric}",
                severity,
                f"{metric}={value:.6f} violates {op}{threshold}",
                [f"artifact:data/metrics_snapshots/{run_id}.json#/metrics/{metric}"],
            )
        )
        if severity == "HARD_FAIL":
            hard_fail = True

    if hard_fail:
        return "STOP", reasons
    if reasons:
        return "HOLD_RISK", reasons
    return None, reasons


def _volume_gate(metrics: dict[str, Any], run_id: str, thresholds: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    rules = _volume_gate_rules(thresholds)
    if not rules:
        return False, {
            "volume_rules_present": False,
            "ref": f"artifact:data/metrics_snapshots/{run_id}.json#/metrics",
        }
    evaluations: list[dict[str, Any]] = []
    for rule in rules:
        metric = str(rule.get("metric", "")).strip()
        min_value = float(rule.get("min_value", 0.0) or 0.0)
        value = float(metrics.get(metric) or 0.0)
        evaluations.append(
            {
                "metric": metric,
                "value": value,
                "min_value": min_value,
                "ok": value >= min_value,
            }
        )
    passed = any(bool(x.get("ok")) for x in evaluations)
    return passed, {
        "volume_rules_present": True,
        "evaluations": evaluations,
        "ref": f"artifact:data/metrics_snapshots/{run_id}.json#/metrics",
    }


def _propose_experiments(metrics: dict[str, Any], plan_start: date, plan_end: date) -> list[dict[str, Any]]:
    aliases = _goal_to_target_alias_map()
    defaults = domain_goal_default_metrics()
    goal_ids = _ordered_goal_ids()
    primary_goal = _default_goal_id()
    lead_alias = aliases.get(primary_goal, _default_target_metric_alias())
    lead_metric = defaults.get(primary_goal, _target_metric_to_primary_metric(lead_alias))
    lead_direction = _target_metric_expected_direction(lead_alias)

    lever = "replenishment" if lead_direction == "decrease" else "pricing"
    unit = "store" if lead_direction == "decrease" else "customer"
    template_guardrails = _doctor_guardrails(metrics)
    guardrail_metrics = [str(x.get("metric", "")).strip() for x in template_guardrails if str(x.get("metric", "")).strip()]
    guardrail_rules = [f"{row['metric']} {row['op']} {row['threshold']}" for row in template_guardrails[:4]]
    success_rule = (
        f"{lead_metric} uplift <= -2% and CI95 excludes 0"
        if lead_direction == "decrease"
        else f"{lead_metric} uplift >= +2% and CI95 excludes 0"
    )
    return [
        {
            "name": "domain_template_primary_v1",
            "goal": primary_goal,
            "goal_statement": f"Improve {lead_metric} while preserving contract guardrails",
            "lever_type": lever,
            "unit": unit,
            "scope": ["template_priority_segment"],
            "start_date": plan_start.isoformat(),
            "end_date": plan_end.isoformat(),
            "duration_days": 14,
            "freeze_window_days": 14,
            "success_metrics": [lead_metric, *guardrail_metrics[:2]],
            "guardrails": guardrail_metrics[:4],
            "north_star_metric": lead_metric,
            "dod": {
                "success_rule": success_rule,
                "guardrail_rules": guardrail_rules,
                "inconclusive_rule": "if CI95 crosses 0 then HOLD_EXTEND",
            },
            "assignment_required": True,
            "limitations": ["Template-driven fallback uses generic lever family without domain heuristics."],
            "estimated_impact": 7,
            "confidence": "med",
            "ease": 6,
        }
    ]


def _phase_gate(experiments: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    allowed: list[dict[str, Any]] = []
    blocked: list[str] = []
    for exp in experiments:
        if str(exp.get("phase_enabled", "true")).strip().lower() in {"0", "false", "no"}:
            blocked.append(exp.get("name", "unknown"))
            continue
        allowed.append(exp)
    return allowed, blocked


def _load_active_experiments() -> list[dict[str, Any]]:
    path = Path("data/agent_reports/active_experiments.json")
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict) and isinstance(data.get("experiments"), list):
        return [x for x in data["experiments"] if isinstance(x, dict)]
    return []


def _parse_date(value: Any) -> date | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10])
    except Exception:
        return None


def _normalize_scope(value: Any) -> list[str]:
    if isinstance(value, list):
        out = [str(x) for x in value if str(x).strip()]
        return out if out else ["all"]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return ["all"]


def _derive_end_date(start_date: date | None, end_raw: Any, duration_days: Any) -> date | None:
    end_dt = _parse_date(end_raw)
    if end_dt is not None:
        return end_dt
    if start_date is None:
        return None
    try:
        days = int(duration_days)
    except Exception:
        days = 14
    if days <= 0:
        days = 14
    return start_date + timedelta(days=days - 1)


def _metric_semantics_for_doctor(metric: str) -> str:
    metric_norm = str(metric or "").strip().lower()
    signal_map = domain_signal_metric_to_target_metric()
    target_alias = str(signal_map.get(metric_norm, "")).strip()
    direction = _target_metric_expected_direction(target_alias) if target_alias else "increase"
    if direction == "decrease":
        return "decrease_target_metric"
    return "standard"


def _default_design_fields(experiment: dict[str, Any], run_cfg: dict[str, Any]) -> dict[str, Any]:
    unit = str(experiment.get("unit", "customer") or "customer").strip().lower()
    metric = str(experiment.get("north_star_metric", "")).strip()
    duration_days = int(experiment.get("duration_days", 14) or 14)
    test_weeks_default = max(1, int(math.ceil(duration_days / 7.0)))
    target_alias = domain_signal_metric_to_target_metric().get(metric.lower(), "")
    decrease_target = _target_metric_expected_direction(target_alias) == "decrease" if target_alias else False
    store_like = unit == "store"

    pre_period_weeks = run_cfg.get("ab_pre_period_weeks", (2 if (store_like or decrease_target) else 1))
    test_period_weeks = run_cfg.get("ab_test_period_weeks", test_weeks_default)
    wash_in_days = run_cfg.get("ab_wash_in_days", (7 if (store_like or decrease_target) else 0))
    attribution_window_rule = run_cfg.get(
        "ab_attribution_rule",
        (
            "count only post-start attributed observations; apply wash_in_days before decision"
            if decrease_target
            else "count observations within [start_date, end_date] test window"
        ),
    )
    side_default = "one-sided" if decrease_target else "two-sided"
    test_side = str(run_cfg.get("ab_test_side", side_default) or side_default).strip().lower()
    if test_side not in {"one-sided", "two-sided"}:
        test_side = side_default

    return {
        "experiment_class": ("store_level_ops" if store_like else "customer_level_product"),
        "randomization_unit": unit,
        "analysis_unit": unit,
        "pre_period_weeks": int(pre_period_weeks),
        "test_period_weeks": int(test_period_weeks),
        "wash_in_days": int(wash_in_days),
        "attribution_window_rule": str(attribution_window_rule),
        "test_side": test_side,
        "metric_semantics": _metric_semantics_for_doctor(metric),
        "surrogate_batch_id_strategy": None,
    }
    try:
        days = int(duration_days)
    except Exception:
        days = 14
    days = max(1, days)
    return start_date + timedelta(days=days - 1)


def _update_active_experiments_registry(run_id: str, planned: list[dict[str, Any]]) -> None:
    registry_path = Path("data/agent_reports/active_experiments.json")
    existing = _load_active_experiments()
    today = datetime.now(timezone.utc).date()

    kept: list[dict[str, Any]] = []
    for row in existing:
        end_dt = _derive_end_date(_parse_date(row.get("start_date")), row.get("end_date"), row.get("duration_days", 14))
        if end_dt is not None and end_dt < today:
            continue
        kept.append(row)

    now_iso = datetime.now(timezone.utc).isoformat()
    for exp in planned:
        if not isinstance(exp, dict):
            continue
        start_dt = _parse_date(exp.get("start_date")) or today
        duration_days = int(exp.get("duration_days", 14) or 14)
        freeze_window_days = int(exp.get("freeze_window_days", 14) or 14)
        end_dt = _derive_end_date(start_dt, exp.get("end_date"), duration_days) or start_dt
        candidate = {
            "name": str(exp.get("name", "unknown_experiment")),
            "unit": str(exp.get("unit", "customer")),
            "lever_type": str(exp.get("lever_type", "unknown")),
            "scope": _normalize_scope(exp.get("scope", ["all"])),
            "start_date": start_dt.isoformat(),
            "end_date": end_dt.isoformat(),
            "duration_days": duration_days,
            "freeze_window_days": freeze_window_days,
            "status": "planned",
            "source_run_id": run_id,
            "updated_at": now_iso,
        }
        key = (
            candidate["name"],
            candidate["unit"],
            candidate["lever_type"],
            json.dumps(candidate["scope"], ensure_ascii=True),
            candidate["start_date"],
            candidate["end_date"],
        )
        replaced = False
        next_rows: list[dict[str, Any]] = []
        for row in kept:
            row_key = (
                str(row.get("name", "")),
                str(row.get("unit", "")),
                str(row.get("lever_type", "")),
                json.dumps(_normalize_scope(row.get("scope", ["all"])), ensure_ascii=True),
                str(row.get("start_date", "")),
                str(row.get("end_date", "")),
            )
            if row_key == key:
                next_rows.append(candidate)
                replaced = True
            else:
                next_rows.append(row)
        if not replaced:
            next_rows.append(candidate)
        kept = next_rows

    kept.sort(key=lambda r: str(r.get("updated_at", "")), reverse=True)
    kept = kept[:50]
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(json.dumps(kept, ensure_ascii=False, indent=2), encoding="utf-8")


def _windows_overlap(a_start: date | None, a_end: date | None, b_start: date | None, b_end: date | None) -> bool:
    # Fail-closed: if any window bound is missing, treat as overlap risk.
    if not a_start or not a_end or not b_start or not b_end:
        return True
    return max(a_start, b_start) <= min(a_end, b_end)


def _interference_risks(planned: list[dict[str, Any]], active: list[dict[str, Any]]) -> list[dict[str, Any]]:
    risks: list[dict[str, Any]] = []
    for new_exp in planned:
        new_unit = new_exp.get("unit")
        new_lever = new_exp.get("lever_type")
        new_scope = set(new_exp.get("scope", []))
        new_start = _parse_date(new_exp.get("start_date"))
        new_end = _parse_date(new_exp.get("end_date"))
        for act in active:
            if str(act.get("status", "active")).lower() not in {"active", "running", "planned"}:
                continue
            act_unit = act.get("unit")
            act_lever = act.get("lever_type")
            act_scope = set(act.get("scope", []))
            act_start = _parse_date(act.get("start_date"))
            act_end = _parse_date(act.get("end_date"))
            if (
                new_unit == act_unit
                and new_lever == act_lever
                and (new_scope & act_scope)
                and _windows_overlap(new_start, new_end, act_start, act_end)
            ):
                risks.append(
                    {
                        "risk_type": "interference",
                        "check_name": str(new_exp.get("name", "unknown")),
                        "severity": "WARN",
                        "mitigation": (
                            f"Split scope/time or switch unit; overlaps active {act.get('name', 'unknown')}"
                        ),
                    }
                )
    return risks


def _validate_experiment_contract(experiments: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
    required = [
        "name",
        "goal",
        "lever_type",
        "unit",
        "experiment_class",
        "randomization_unit",
        "analysis_unit",
        "duration_days",
        "freeze_window_days",
        "pre_period_weeks",
        "test_period_weeks",
        "wash_in_days",
        "attribution_window_rule",
        "test_side",
        "success_metrics",
        "guardrails",
        "hypotheses",
        "estimated_impact",
        "confidence",
        "ease",
        "methodology",
        "sample_size_gate",
        "min_sample_size",
        "mde",
        "confidence_level",
        "goal",
        "north_star_metric",
        "metric_semantics",
        "assignment_required",
        "limitations",
    ]
    for exp in experiments:
        name = exp.get("name", "unknown")
        for key in required:
            if key not in exp:
                issues.append(f"missing_field:{name}:{key}")
        if exp.get("unit") not in {"customer", "store"}:
            issues.append(f"invalid_unit:{name}")
        if exp.get("duration_days") != 14:
            issues.append(f"invalid_duration:{name}")
        if exp.get("freeze_window_days") != 14:
            issues.append(f"invalid_freeze_window:{name}")
        try:
            if int(exp.get("pre_period_weeks", 0) or 0) <= 0:
                issues.append(f"invalid_pre_period_weeks:{name}")
        except Exception:
            issues.append(f"invalid_pre_period_weeks:{name}")
        try:
            if int(exp.get("test_period_weeks", 0) or 0) <= 0:
                issues.append(f"invalid_test_period_weeks:{name}")
        except Exception:
            issues.append(f"invalid_test_period_weeks:{name}")
        try:
            if int(exp.get("wash_in_days", 0) or 0) < 0:
                issues.append(f"invalid_wash_in_days:{name}")
        except Exception:
            issues.append(f"invalid_wash_in_days:{name}")
        if not str(exp.get("attribution_window_rule", "")).strip():
            issues.append(f"missing_attribution_window_rule:{name}")
        if str(exp.get("test_side", "")).strip() not in {"one-sided", "two-sided"}:
            issues.append(f"invalid_test_side:{name}")
        if exp.get("randomization_unit") != exp.get("unit"):
            issues.append(f"randomization_unit_mismatch:{name}")
        if exp.get("analysis_unit") != exp.get("unit"):
            issues.append(f"analysis_unit_mismatch:{name}")
        for metric in (exp.get("success_metrics") or []) + (exp.get("guardrails") or []):
            if metric not in READY_NOW_METRICS:
                issues.append(f"metric_not_ready:{name}:{metric}")
        confidence = str(exp.get("confidence", "")).lower()
        if confidence not in {"low", "med", "high"}:
            issues.append(f"invalid_confidence:{name}")
        for score_key in ("estimated_impact", "ease"):
            try:
                val = int(exp.get(score_key))
            except Exception:
                val = 0
            if val < 1 or val > 10:
                issues.append(f"invalid_{score_key}:{name}")
        if str(exp.get("methodology", "")).strip() not in {"diff_in_means", "cuped", "sequential"}:
            issues.append(f"invalid_methodology:{name}")
        allowed_goals = {str(g).strip().lower() for g in GOAL_ORDER if str(g).strip()}
        if allowed_goals and str(exp.get("goal", "")).strip().lower() not in allowed_goals:
            issues.append(f"invalid_goal:{name}")
        if not str(exp.get("north_star_metric", "")).strip():
            issues.append(f"missing_north_star_metric:{name}")
        if exp.get("assignment_required") is not True:
            issues.append(f"assignment_required_false:{name}")
        limitations = exp.get("limitations", [])
        if not isinstance(limitations, list) or len(limitations) == 0:
            issues.append(f"missing_limitations:{name}")
        sample_gate = exp.get("sample_size_gate", {})
        if not isinstance(sample_gate, dict):
            issues.append(f"invalid_sample_size_gate:{name}")
        else:
            if int(sample_gate.get("min_orders", 0) or 0) < AB_MIN_ORDERS_PER_ARM:
                issues.append(f"invalid_sample_size_gate:{name}:min_orders")
            if int(sample_gate.get("min_units", 0) or 0) < AB_MIN_UNITS_PER_ARM:
                issues.append(f"invalid_sample_size_gate:{name}:min_units")
        try:
            if float(exp.get("mde", 0) or 0) <= 0:
                issues.append(f"invalid_mde:{name}")
        except Exception:
            issues.append(f"invalid_mde:{name}")
        try:
            cl = float(exp.get("confidence_level", 0) or 0)
            if cl <= 0 or cl >= 1:
                issues.append(f"invalid_confidence_level:{name}")
        except Exception:
            issues.append(f"invalid_confidence_level:{name}")
        try:
            if int(exp.get("min_sample_size", 0) or 0) <= 0:
                issues.append(f"invalid_min_sample_size:{name}")
        except Exception:
            issues.append(f"invalid_min_sample_size:{name}")

        hypotheses = exp.get("hypotheses")
        if not isinstance(hypotheses, list) or not hypotheses:
            issues.append(f"missing_hypothesis:{name}")
            continue
        h0 = hypotheses[0] if isinstance(hypotheses[0], dict) else {}
        required_hyp = [
            "hypothesis_id",
            "hypothesis_statement",
            "mechanism",
            "risk_factors",
            "primary_goal",
            "primary_metric",
            "expected_effect_range",
            "guardrails_with_thresholds",
            "unit",
            "duration_days",
            "freeze_window_days",
            "assignment_method",
            "treatment_pct",
            "analysis_method",
            "sample_size_gate",
            "stop_rules",
            "pre_period_weeks",
            "test_period_weeks",
            "wash_in_days",
            "attribution_window_rule",
            "test_side",
            "evidence_refs",
        ]
        for key in required_hyp:
            if key not in h0:
                issues.append(f"missing_hypothesis_field:{name}:{key}")
        statement = str(h0.get("hypothesis_statement", "")).strip()
        if not statement:
            issues.append(f"missing_hypothesis:{name}")
        elif not hypothesis_format_ok(statement):
            issues.append(f"bad_hypothesis_format:{name}")
        if not str(h0.get("expected_effect_range", "")).strip():
            issues.append(f"missing_hypothesis:{name}:expected_effect_range")
        mechanism = h0.get("mechanism", [])
        if not isinstance(mechanism, list) or len([x for x in mechanism if str(x).strip()]) == 0:
            issues.append(f"missing_hypothesis:{name}:mechanism")
        risk_factors = h0.get("risk_factors", [])
        if not isinstance(risk_factors, list) or len([x for x in risk_factors if str(x).strip()]) == 0:
            issues.append(f"missing_hypothesis:{name}:risk_factors")
        evidence_refs = h0.get("evidence_refs", [])
        if not isinstance(evidence_refs, list) or len([x for x in evidence_refs if str(x).strip()]) == 0:
            issues.append(f"missing_hypothesis:{name}:evidence_refs")
        if not isinstance(exp.get("evidence_refs"), list) or len([x for x in exp.get("evidence_refs", []) if str(x).strip()]) == 0:
            issues.append(f"missing_evidence_refs:{name}")
    return issues


def _with_hypothesis_contract(experiment: dict[str, Any], run_id: str, run_cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    run_cfg = run_cfg if isinstance(run_cfg, dict) else {}
    name = str(experiment.get("name", "experiment"))
    goal = str(experiment.get("goal", "Improve KPI trajectory while preserving guardrails"))
    goal_norm = goal.strip().lower()
    primary_metric = _resolve_experiment_primary_metric(experiment)
    experiment["north_star_metric"] = primary_metric
    unit = str(experiment.get("unit", "customer"))
    impact = int(experiment.get("estimated_impact", 5))
    confidence = str(experiment.get("confidence", "med")).lower()
    ease = int(experiment.get("ease", 5))
    score = round(impact * CONFIDENCE_TO_NUM.get(confidence, 0.8) * ease, 2)
    design = _default_design_fields(experiment, run_cfg)
    guardrail_rows = _doctor_guardrails({})
    guardrail_metric_names = [str(x.get("metric", "")).strip() for x in guardrail_rows if str(x.get("metric", "")).strip()]
    guardrail_strings = [f"{x['metric']}{x['op']}{x['threshold']}" for x in guardrail_rows[:4]]
    stop_rules = [f"stop_if_{x['metric']}_{'below' if str(x['op']).startswith('>') else 'above'}_threshold" for x in guardrail_rows[:2]]
    evidence_metrics = [primary_metric, *guardrail_metric_names[:2]]
    experiment["ice_score"] = score
    experiment["hypotheses"] = [
        {
            "hypothesis_id": f"{run_id}:{name}:h1",
            "hypothesis_statement": (
                f"We believe that {goal.lower()} will improve {primary_metric} "
                "because customer/store behavior is currently suboptimal under baseline settings."
            ),
            "mechanism": [
                "Adjust lever in a controlled A/B split",
                "Measure direct impact on primary metric",
                "Hold guardrails within thresholds",
            ],
            "risk_factors": [
                "availability_pressure",
                "margin_compression",
                "assignment_or_measurement_bias",
            ],
            "primary_goal": (goal_norm if goal_norm in set(_ordered_goal_ids()) else _default_goal_id()),
            "primary_metric": primary_metric,
            "expected_effect_range": (
                "-1%..-3%"
                if _target_metric_expected_direction(
                    domain_signal_metric_to_target_metric().get(str(primary_metric).strip().lower(), "")
                )
                == "decrease"
                else "+1%..+3%"
            ),
            "guardrails_with_thresholds": guardrail_strings,
            "unit": unit,
            "duration_days": int(experiment.get("duration_days", 14)),
            "freeze_window_days": int(experiment.get("freeze_window_days", 14)),
            "assignment_method": "hash",
            "treatment_pct": 50,
            "analysis_method": (
                "diff_in_means_customer" if unit == "customer" else "diff_in_means_store"
            ),
            "sample_size_gate": {
                "min_units_per_arm": 200,
                "min_orders_per_arm": 300,
            },
            "stop_rules": stop_rules,
            "pre_period_weeks": design["pre_period_weeks"],
            "test_period_weeks": design["test_period_weeks"],
            "wash_in_days": design["wash_in_days"],
            "attribution_window_rule": design["attribution_window_rule"],
            "test_side": design["test_side"],
            "evidence_refs": [f"artifact:data/metrics_snapshots/{run_id}.json#/metrics/{m}" for m in evidence_metrics],
        }
    ]
    experiment["methodology"] = "diff_in_means"
    experiment["sample_size_gate"] = {
        "min_orders": AB_MIN_ORDERS_PER_ARM,
        "min_units": AB_MIN_UNITS_PER_ARM,
    }
    experiment["min_sample_size"] = AB_MIN_UNITS_PER_ARM if unit == "customer" else AB_MIN_ORDERS_PER_ARM
    experiment["mde"] = 0.02
    experiment["confidence_level"] = 0.95
    evidence_metric_links = {
        metric_name: f"artifact:data/metrics_snapshots/<run_id>.json#/metrics/{metric_name}"
        for metric_name in sorted(READY_NOW_METRICS)[:8]
    }
    experiment["evidence_links"] = {
        "metrics_snapshot": evidence_metric_links,
        "ab_report": "artifact:data/ab_reports/<run_id>_<experiment_id>_ab.json#",
    }
    experiment["evidence_refs"] = [
        f"artifact:data/metrics_snapshots/{run_id}.json#/metrics/{primary_metric}",
        f"artifact:data/dq_reports/{run_id}.json#/rows",
        f"artifact:data/llm_reports/{run_id}_captain.json#/result",
    ]
    experiment["experiment_class"] = design["experiment_class"]
    experiment["randomization_unit"] = design["randomization_unit"]
    experiment["analysis_unit"] = design["analysis_unit"]
    experiment["pre_period_weeks"] = design["pre_period_weeks"]
    experiment["test_period_weeks"] = design["test_period_weeks"]
    experiment["wash_in_days"] = design["wash_in_days"]
    experiment["attribution_window_rule"] = design["attribution_window_rule"]
    experiment["test_side"] = design["test_side"]
    experiment["metric_semantics"] = design["metric_semantics"]
    experiment["surrogate_batch_id_strategy"] = design["surrogate_batch_id_strategy"]
    return experiment


def _required_n_two_sample(stddev: float, mde_abs: float, alpha_z: float = 1.96, power_z: float = 0.84) -> int:
    if stddev <= 0 or mde_abs <= 0:
        return 0
    return int(math.ceil(2.0 * ((alpha_z + power_z) ** 2) * (stddev**2) / (mde_abs**2)))


def _attach_methodology_requirements(experiment: dict[str, Any], metrics: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    primary = _resolve_experiment_primary_metric(experiment)
    experiment["north_star_metric"] = primary
    mde_rel = 0.02
    baseline = float(metrics.get(primary) or 0.0)
    std = float(metrics.get(f"{primary}_stddev") or 0.0)
    if std <= 0:
        std = abs(baseline) * 0.30
    metric_kind = _stat_metric_type(primary)
    if metric_kind == "ratio_or_proportion":
        mde_rel = 0.01
    elif metric_kind == "proportion_or_count":
        mde_rel = 0.02
    else:
        mde_rel = 0.02

    if baseline <= 0 or std <= 0:
        return experiment, "missing_variance_estimate"

    mde_abs = abs(baseline) * mde_rel
    req_n = _required_n_two_sample(stddev=std, mde_abs=mde_abs)
    if req_n <= 0:
        return experiment, "missing_variance_estimate"

    experiment["methodology_detail"] = {
        "primary_metric": primary,
        "mde": mde_rel,
        "mde_abs": mde_abs,
        "alpha": 0.05,
        "confidence_level": 0.95,
        "power": 0.80,
        "min_sample_size": req_n,
        "required_n_control": req_n,
        "required_n_treatment": req_n,
        "assumption_notes": [
            "two-sample normal approximation",
            "equal allocation and independent units",
        ],
    }
    experiment["mde"] = mde_rel
    experiment["confidence_level"] = 0.95
    experiment["min_sample_size"] = req_n
    experiment["expected_impact_range"] = {"low": f"+{mde_rel*100:.1f}%", "mid": f"+{(mde_rel*1.5)*100:.1f}%", "high": f"+{(mde_rel*2.0)*100:.1f}%"}
    return experiment, None


def _approval_for_decision(decision: str) -> str:
    if decision == "RUN_AB":
        return "PM_REQUIRED"
    if decision == "ROLLOUT_CANDIDATE":
        return "PM_DATA_REQUIRED"
    return "NONE"


def _build_doctor_visible_reasoning_trace(
    *,
    run_id: str,
    decision: str,
    reasons: list[dict[str, Any]],
    protocol_checks: list[dict[str, Any]],
    measurement_state: str,
    ab_status: str,
    measurement_fix_plan: dict[str, Any] | None,
    enabled: bool,
) -> dict[str, Any]:
    if not enabled:
        return {"claims": [], "gates_checked": [], "unknowns": []}

    claims: list[dict[str, Any]] = []
    for idx, reason in enumerate(reasons[:20], start=1):
        if not isinstance(reason, dict):
            continue
        code = str(reason.get("code", "")).strip() or "doctor_reason"
        message = str(reason.get("message", "")).strip() or "Reason captured by deterministic gates."
        refs = reason.get("evidence_refs", [])
        evidence_refs = [str(x).strip() for x in refs if str(x).strip()] if isinstance(refs, list) else []
        alternatives = ["keep_current_decision", "collect_missing_evidence_and_re_evaluate"]
        falsifiability_test = (
            f"Re-run deterministic gate for reason code '{code}' after data/method changes; "
            "claim is rejected if reason disappears."
        )
        decision_impact = (
            "Can enforce STOP/HOLD ceilings when severity is WARN/HARD_FAIL or measurement is blocked."
        )
        claims.append(
            {
                "claim_id": f"doctor:{run_id}:{idx}:{code}",
                "statement": f"{code}: {message}",
                "evidence_refs": evidence_refs[:5],
                "alternatives_considered": alternatives,
                "falsifiability_test": falsifiability_test,
                "decision_impact": decision_impact,
            }
        )

    gates_checked: list[str] = []
    for gate in protocol_checks[:20]:
        if not isinstance(gate, dict):
            continue
        name = str(gate.get("name", "")).strip() or "protocol_gate"
        passed = gate.get("passed")
        status = "PASS" if passed is True else ("FAIL" if passed is False else "UNKNOWN")
        detail = str(gate.get("detail", "")).strip()
        gates_checked.append(f"{name}:{status}" + (f" ({detail})" if detail else ""))

    measurable = str(measurement_state or "").upper() not in {"UNOBSERVABLE", "BLOCKED_BY_DATA"}
    ab_ok = str(ab_status or "").upper() not in {
        "MISSING_ASSIGNMENT",
        "METHODOLOGY_MISMATCH",
        "INVALID_METHODS",
        "ASSIGNMENT_RECOVERED",
    }
    gates_checked.append(
        f"measurement_observable_gate:{'PASS' if measurable else 'FAIL'}"
        f" (measurement_state:{measurement_state})"
    )
    gates_checked.append(f"ab_status_valid_gate:{'PASS' if ab_ok else 'FAIL'} (ab_status:{ab_status})")
    gates_checked.append(f"decision_advisory_mode:PASS (decision:{decision})")

    unknowns: list[str] = []
    if isinstance(measurement_fix_plan, dict):
        for item in (measurement_fix_plan.get("missing_items") if isinstance(measurement_fix_plan.get("missing_items"), list) else []):
            text = str(item).strip()
            if text:
                unknowns.append(text)
    for reason in reasons:
        if not isinstance(reason, dict):
            continue
        msg = str(reason.get("message", "")).strip()
        if "unknown" in msg.lower():
            unknowns.append(msg)
    unknowns = sorted({u for u in unknowns if u})[:20]
    if not unknowns and not measurable:
        unknowns.append("Measurement state is blocked; causal uplift cannot be confirmed yet.")
    return {"claims": claims, "gates_checked": gates_checked, "unknowns": unknowns}


def _stable_hypothesis_id(hypothesis_key: str, lever_type: str, unit: str, scope: list[str], action_summary: str) -> str:
    scope_sorted = sorted([str(x).strip().lower() for x in scope if str(x).strip()])
    raw = "|".join(
        [
            hypothesis_key.strip().lower(),
            lever_type.strip().lower(),
            unit.strip().lower(),
            ",".join(scope_sorted),
            action_summary.strip().lower(),
        ]
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _extract_problem_metrics(captain: dict[str, Any], synthetic_bias: dict[str, Any]) -> list[str]:
    candidates = sorted(READY_NOW_METRICS)[:20]
    hits: set[str] = set()
    issues = ((captain.get("result", {}) or {}).get("issues", []) if isinstance(captain, dict) else [])
    if not isinstance(issues, list):
        issues = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        txt = f"{issue.get('check_name', '')} {issue.get('message', '')}".lower()
        for metric in candidates:
            if metric.lower() in txt:
                hits.add(metric)
    signals = synthetic_bias.get("signals", []) if isinstance(synthetic_bias.get("signals"), list) else []
    for sig in signals:
        if not isinstance(sig, dict):
            continue
        txt = f"{sig.get('check_name', '')} {sig.get('message', '')}".lower()
        for metric in candidates:
            if metric.lower() in txt:
                hits.add(metric)
    return sorted(hits)


def _hypothesis_portfolio_from_metrics(
    run_id: str,
    metrics: dict[str, Any],
    captain: dict[str, Any],
    synthetic_bias: dict[str, Any],
) -> list[dict[str, Any]]:
    goal_alias = _goal_to_target_alias_map()
    goal_defaults = domain_goal_default_metrics()
    goal_ids = _ordered_goal_ids()
    template_guardrails = _doctor_guardrails(metrics)
    guardrail_metric_names = [str(x.get("metric", "")).strip() for x in template_guardrails if str(x.get("metric", "")).strip()]
    primary_guardrail = guardrail_metric_names[0] if guardrail_metric_names else ""
    secondary_guardrail = guardrail_metric_names[1] if len(guardrail_metric_names) > 1 else primary_guardrail
    primary_guardrail_value = float(metrics.get(primary_guardrail) or 0.0) if primary_guardrail else 0.0
    secondary_guardrail_value = float(metrics.get(secondary_guardrail) or 0.0) if secondary_guardrail else 0.0
    floor_guardrail_row = next(
        (
            row
            for row in template_guardrails
            if isinstance(row, dict) and str(row.get("op", "")).strip() in {">", ">="}
        ),
        template_guardrails[0] if template_guardrails else {},
    )
    floor_guardrail_metric = str(floor_guardrail_row.get("metric", "")).strip()
    floor_guardrail_threshold = float(floor_guardrail_row.get("threshold", 0.0) or 0.0) if floor_guardrail_metric else 0.0
    floor_baseline = float(metrics.get(floor_guardrail_metric) or 0.0) if floor_guardrail_metric else 0.0
    template_floor_threshold = max(floor_guardrail_threshold, floor_baseline * 0.99) if floor_guardrail_metric else floor_guardrail_threshold
    lever_cycle = ["replenishment", "pricing", "visibility", "assortment", "operations"]
    specs: list[dict[str, Any]] = []
    for idx, goal_id in enumerate(goal_ids):
        target_metric = str(goal_alias.get(goal_id, "")).strip()
        if not target_metric:
            continue
        direction = _target_metric_expected_direction(target_metric)
        metric = str(goal_defaults.get(goal_id, _target_metric_to_primary_metric(target_metric))).strip()
        lever = lever_cycle[idx % len(lever_cycle)]
        specs.append(
            {
                "hypothesis_key": f"template_goal_{goal_id}",
                "lever_type": lever,
                "unit": ("store" if idx % 2 == 0 else "customer"),
                "scope": ["template_priority_segment"],
                "target_metric": target_metric,
                "metric": metric,
                "action": f"optimize {lever} controls for {goal_id}",
                "mechanism": f"reduce variance drivers around {metric} with controlled treatment exposure",
                "expected_uplift_range": ("-3%..-7%" if direction == "decrease" else "+2%..+6%"),
                "confidence": max(0.55, 0.75 - (idx * 0.04)),
                "estimated_impact": max(5, 8 - idx),
                "ease": min(9, 6 + idx),
                "alternatives_considered": ["hold_without_experiment", "alternate_lever_family"],
                "expected_direction": direction,
            }
        )
    if not specs:
        raise ConfigurationError("Domain template goals could not be converted into hypothesis specs")
    problem_metrics = _extract_problem_metrics(captain, synthetic_bias)
    evidence_metric_keys = [m for m in sorted(READY_NOW_METRICS) if str(m).strip()][:6]

    portfolio: list[dict[str, Any]] = []
    for spec in specs:
        statement = (
            f"We believe that {spec['action']} will cause {spec['target_metric']} change "
            f"because {spec['mechanism']}."
        )
        evidence_refs: list[dict[str, Any]] = []
        for metric_name in evidence_metric_keys:
            raw_val = metrics.get(metric_name)
            if isinstance(raw_val, (int, float)):
                fact_val: Any = round(float(raw_val), 6)
            else:
                fact_val = raw_val
            evidence_refs.append({"source": "metrics_snapshot", "metric": metric_name, "baseline": None, "fact": fact_val})
        evidence_refs.append({"source": "synthetic_bias", "field": "result", "value": str(synthetic_bias.get("result", ""))})
        if problem_metrics:
            evidence_refs.append(
                {
                    "source": "synthetic_bias",
                    "field": "problem_metrics",
                    "value": problem_metrics[0],
                }
            )
        impact = int(spec["estimated_impact"])
        confidence = float(spec["confidence"])
        ease = int(spec["ease"])
        scope_list = sorted([str(x).strip() for x in spec["scope"] if str(x).strip()]) or ["all"]
        anti_gaming_check = None
        if _target_metric_expected_direction(str(spec["target_metric"])) == "decrease":
            starvation_risk = any(
                (
                    (str(row.get("op")) in {">", ">="} and float(metrics.get(str(row.get("metric", ""))) or 0.0) < float(row.get("threshold") or 0.0))
                    or (str(row.get("op")) in {"<", "<="} and float(metrics.get(str(row.get("metric", ""))) or 0.0) > float(row.get("threshold") or 0.0))
                )
                for row in template_guardrails[:2]
                if isinstance(row, dict)
            )
            anti_gaming_check = {
                "metric_pair": [primary_guardrail, secondary_guardrail],
                primary_guardrail: round(primary_guardrail_value, 4),
                secondary_guardrail: round(secondary_guardrail_value, 4),
                "starvation_risk": starvation_risk,
                "rule": "Do not accept primary-metric decrease if service guardrails deteriorate.",
            }
        portfolio.append(
            {
                "hypothesis_key": spec["hypothesis_key"],
                "action_summary": spec["action"],
                "hypothesis_id": _stable_hypothesis_id(
                    spec["hypothesis_key"],
                    spec["lever_type"],
                    spec["unit"],
                    scope_list,
                    spec["action"],
                ),
                "hypothesis_statement": statement,
                "lever_type": spec["lever_type"],
                "unit": spec["unit"],
                "scope": scope_list,
                "target_metric": spec["target_metric"],
                "expected_direction": spec["expected_direction"],
                "expected_uplift_range": spec["expected_uplift_range"],
                "alternatives_considered": spec["alternatives_considered"],
                "why_not_alternative": (
                    f"Prioritize {spec['lever_type']} because guardrails {primary_guardrail}={round(primary_guardrail_value,4)}, "
                    f"{secondary_guardrail}={round(secondary_guardrail_value,4)}, "
                    f"target metric pressure is stronger than alternatives."
                ),
                "guardrails": {
                    "primary_guardrail_threshold": next((x.get("threshold") for x in template_guardrails if str(x.get("metric")) == primary_guardrail), None),
                    "secondary_guardrail_threshold": next((x.get("threshold") for x in template_guardrails if str(x.get("metric")) == secondary_guardrail), None),
                    "template_floor_guardrail_metric": floor_guardrail_metric,
                    "template_floor_guardrail_threshold": template_floor_threshold,
                },
                "evidence_refs": evidence_refs[:4] + [evidence_refs[-1]],
                "falsifiability_condition": "If target metric does not improve by at least 2% within 14 days, reject.",
                "anti_gaming_check": anti_gaming_check,
                "confidence": confidence,
                "estimated_impact": impact,
                "ease": ease,
                "ice_score": round(impact * confidence * ease, 4),
            }
        )
    portfolio = sorted(portfolio, key=lambda x: float(x.get("ice_score", 0.0)), reverse=True)
    for idx, hyp in enumerate(portfolio, start=1):
        hyp["rank"] = idx
    return portfolio


def _build_hypothesis_portfolio(
    run_id: str,
    metrics: dict[str, Any],
    captain: dict[str, Any],
    synthetic_bias: dict[str, Any],
    *,
    dynamic_enabled: bool,
) -> list[dict[str, Any]]:
    # Keep strict legacy mode unchanged.
    base_portfolio = _hypothesis_portfolio_from_metrics(run_id, metrics, captain, synthetic_bias)
    if not dynamic_enabled:
        return base_portfolio

    portfolio = [dict(item) for item in base_portfolio if isinstance(item, dict)]
    dynamic_signals = _extract_problem_metrics(captain, synthetic_bias)
    if not dynamic_signals:
        for idx, hyp in enumerate(portfolio, start=1):
            hyp["rank"] = idx
        return portfolio

    for idx, hyp in enumerate(portfolio):
        signal = dynamic_signals[idx % len(dynamic_signals)]
        refs = hyp.get("evidence_refs", []) if isinstance(hyp.get("evidence_refs"), list) else []
        refs.append({"source": "captain", "field": "dynamic_problem_metric", "value": signal})
        hyp["evidence_refs"] = refs[:6]
        statement = str(hyp.get("hypothesis_statement", "")).strip()
        if statement:
            hyp["hypothesis_statement"] = f"{statement} Priority signal: {signal}."
        hyp["dynamic_hypothesis"] = True

    target_map = domain_signal_metric_to_target_metric()
    if not target_map:
        target_map = {}
    lead_signal = dynamic_signals[0]
    dynamic_target = str(target_map.get(lead_signal, "")).strip() or _default_target_metric_alias()
    goal_position = 0
    goal_value = domain_target_metric_alias_to_goal().get(dynamic_target, "")
    ordered_goals = _ordered_goal_ids()
    if goal_value in ordered_goals:
        goal_position = ordered_goals.index(goal_value)
    dynamic_lever = (
        "replenishment"
        if _target_metric_expected_direction(dynamic_target) == "decrease"
        else ("visibility" if goal_position >= 2 else "pricing")
    )
    dynamic_action = (
        f"adaptive lever tuning focused on {lead_signal} using recent run evidence and strict guardrails"
    )
    dynamic_scope = ["adaptive_priority_segment"]
    dynamic_guardrails = _doctor_guardrails(metrics)
    dynamic_primary_guardrail = dynamic_guardrails[0] if dynamic_guardrails else {"metric": "", "threshold": 0.0}
    dynamic_secondary_guardrail = dynamic_guardrails[1] if len(dynamic_guardrails) > 1 else dynamic_primary_guardrail
    dynamic_hypothesis = {
        "hypothesis_key": f"dynamic_{dynamic_target}_{lead_signal}",
        "action_summary": dynamic_action,
        "hypothesis_id": _stable_hypothesis_id(
            f"dynamic_{dynamic_target}_{lead_signal}",
            dynamic_lever,
            "store",
            dynamic_scope,
            dynamic_action,
        ),
        "hypothesis_statement": (
            f"We believe adaptive intervention on {lead_signal} can improve {dynamic_target} "
            "while preserving mandatory guardrails."
        ),
        "lever_type": dynamic_lever,
        "unit": "store",
        "scope": dynamic_scope,
        "target_metric": dynamic_target,
        "expected_direction": _target_metric_expected_direction(dynamic_target),
        "expected_uplift_range": "+2%..+5%" if _target_metric_expected_direction(dynamic_target) == "increase" else "-3%..-7%",
        "alternatives_considered": ["legacy_static_portfolio", "hold_without_experiment"],
        "why_not_alternative": "Dynamic mode enabled; using observed pressure signal to prioritize experiment sequencing.",
        "guardrails": {
            "primary_guardrail_metric": str(dynamic_primary_guardrail.get("metric", "")),
            "primary_guardrail_threshold": float(dynamic_primary_guardrail.get("threshold", 0.0) or 0.0),
            "secondary_guardrail_metric": str(dynamic_secondary_guardrail.get("metric", "")),
            "secondary_guardrail_threshold": float(dynamic_secondary_guardrail.get("threshold", 0.0) or 0.0),
            "template_floor_guardrail_metric": str(dynamic_primary_guardrail.get("metric", "")),
            "template_floor_guardrail_threshold": float(dynamic_primary_guardrail.get("threshold", 0.0) or 0.0),
        },
        "evidence_refs": [
            {"source": "captain", "field": "dynamic_problem_metric", "value": lead_signal},
            {"source": "metrics_snapshot", "metric": lead_signal, "fact": metrics.get(lead_signal)},
            {"source": "synthetic_bias", "field": "result", "value": str(synthetic_bias.get("result", ""))},
        ],
        "falsifiability_condition": "If primary metric does not improve within 14 days with safe guardrails, reject.",
        "anti_gaming_check": None,
        "confidence": 0.66,
        "estimated_impact": 6,
        "ease": 6,
        "ice_score": 23.76,
        "dynamic_hypothesis": True,
    }
    portfolio.append(dynamic_hypothesis)
    portfolio = sorted(portfolio, key=lambda x: float(x.get("ice_score", 0.0)), reverse=True)
    for idx, hyp in enumerate(portfolio, start=1):
        hyp["rank"] = idx
    return portfolio


def _resolve_hypothesis_generation_mode(
    *,
    dynamic_enabled: bool,
    hypothesis_portfolio: list[dict[str, Any]],
) -> str:
    has_dynamic_hypothesis = any(
        isinstance(h, dict) and bool(h.get("dynamic_hypothesis"))
        for h in hypothesis_portfolio
    )
    if not dynamic_enabled:
        return "seed_templates"
    return "context_rewriter" if has_dynamic_hypothesis else "fallback_seed_templates"


def _to_int_clamped(value: Any, default: int, low: int, high: int) -> int:
    try:
        num = int(value)
    except Exception:
        num = default
    return max(low, min(high, num))


def _to_float_clamped(value: Any, default: float, low: float, high: float) -> float:
    try:
        num = float(value)
    except Exception:
        num = default
    return max(low, min(high, num))


def _normalize_context_rewriter_hypothesis(
    raw: dict[str, Any],
    *,
    index: int,
    run_id: str,
    metrics: dict[str, Any],
    synthetic_bias: dict[str, Any],
) -> dict[str, Any]:
    target_metric = str(raw.get("target_metric", "")).strip()
    allowed_targets = domain_target_metric_aliases()
    if not allowed_targets:
        raise ConfigurationError("Domain template target aliases are required for context rewriter")
    if target_metric not in allowed_targets:
        primary_hint = _target_metric_to_primary_metric(target_metric)
        target_metric = domain_signal_metric_to_target_metric().get(primary_hint, "")
        if not target_metric:
            alias_by_goal = {goal_id: alias for alias, goal_id in domain_target_metric_alias_to_goal().items()}
            hint_goal = goal_from_metric(primary_hint)
            if not hint_goal:
                hint_goal = _default_goal_id()
            target_metric = alias_by_goal.get(hint_goal, next(iter(sorted(allowed_targets))))

    lever_type = str(raw.get("lever_type", "")).strip().lower()
    if lever_type not in {"pricing", "replenishment", "visibility", "assortment", "operations"}:
        lever_type = "pricing"
    unit = str(raw.get("unit", "")).strip().lower()
    if unit not in {"store", "customer"}:
        unit = "store"
    action_summary = coerce_string(raw.get("action_summary", raw.get("action", "")), max_len=220)
    if not action_summary:
        action_summary = f"context-rewriter action {index}"
    hypothesis_key = coerce_string(raw.get("hypothesis_key", f"context_rewriter_{index}"), max_len=120)
    statement = coerce_string(raw.get("hypothesis_statement", ""), max_len=420)
    if not statement:
        statement = (
            f"We believe that {action_summary} will improve {target_metric} "
            "because evidence indicates target-specific pressure."
        )
    expected_direction = str(raw.get("expected_direction", "")).strip().lower()
    if expected_direction not in {"increase", "decrease"}:
        expected_direction = _target_metric_expected_direction(target_metric)
    expected_uplift_range = coerce_string(raw.get("expected_uplift_range", ""), max_len=80)
    if not expected_uplift_range:
        expected_uplift_range = "-3%..-8%" if expected_direction == "decrease" else "+2%..+6%"

    scope_in = raw.get("scope", [])
    if isinstance(scope_in, str):
        scope_in = [scope_in]
    scope = [str(x).strip() for x in scope_in if str(x).strip()] if isinstance(scope_in, list) else []
    if not scope:
        scope = ["adaptive_priority_segment"]

    alternatives = coerce_string_list(raw.get("alternatives_considered", []), max_items=4, max_item_len=120)
    if not alternatives:
        alternatives = ["seed_templates", "hold_without_experiment"]

    refs_in = raw.get("evidence_refs", [])
    refs: list[dict[str, Any]] = []
    if isinstance(refs_in, list):
        for item in refs_in[:8]:
            if isinstance(item, dict):
                refs.append(item)
            elif str(item).strip():
                refs.append({"source": "llm_context_rewriter", "value": str(item).strip()[:180]})
    if not refs:
        fallback_metric = next(iter(sorted(READY_NOW_METRICS)), "primary_metric")
        refs = [
            {"source": "metrics_snapshot", "metric": fallback_metric, "fact": metrics.get(fallback_metric)},
            {"source": "synthetic_bias", "field": "result", "value": str(synthetic_bias.get("result", ""))},
        ]
    if not any(str(r.get("source", "")).strip().lower() == "synthetic_bias" for r in refs if isinstance(r, dict)):
        refs.append({"source": "synthetic_bias", "field": "result", "value": str(synthetic_bias.get("result", ""))})

    guardrails_raw = raw.get("guardrails", {}) if isinstance(raw.get("guardrails"), dict) else {}
    template_guardrails = _doctor_guardrails(metrics)
    primary_guardrail_metric = str(template_guardrails[0].get("metric", "")) if template_guardrails else ""
    secondary_guardrail_metric = str(template_guardrails[1].get("metric", primary_guardrail_metric)) if template_guardrails else ""
    primary_threshold = float(template_guardrails[0].get("threshold", 0.0) or 0.0) if template_guardrails else 0.0
    secondary_threshold = float(template_guardrails[1].get("threshold", primary_threshold) or primary_threshold) if len(template_guardrails) > 1 else primary_threshold
    floor_guardrail_metric = primary_guardrail_metric
    floor_threshold_default = primary_threshold
    for row in template_guardrails:
        if not isinstance(row, dict):
            continue
        op = str(row.get("op", "")).strip()
        metric_name = str(row.get("metric", "")).strip()
        if op in {">", ">="} and metric_name:
            floor_guardrail_metric = metric_name
            floor_threshold_default = float(row.get("threshold", primary_threshold) or primary_threshold)
            break
    guardrails = {
        "primary_guardrail_metric": primary_guardrail_metric,
        "primary_guardrail_threshold": _to_float_clamped(guardrails_raw.get("primary_guardrail_threshold"), primary_threshold, -1e12, 1e12),
        "secondary_guardrail_metric": secondary_guardrail_metric,
        "secondary_guardrail_threshold": _to_float_clamped(guardrails_raw.get("secondary_guardrail_threshold"), secondary_threshold, -1e12, 1e12),
        "template_floor_guardrail_metric": str(guardrails_raw.get("template_floor_guardrail_metric", floor_guardrail_metric)).strip() or floor_guardrail_metric,
        "template_floor_guardrail_threshold": _to_float_clamped(guardrails_raw.get("template_floor_guardrail_threshold"), floor_threshold_default, -1e12, 1e12),
    }
    confidence = _to_float_clamped(raw.get("confidence"), 0.66, 0.05, 1.0)
    estimated_impact = _to_int_clamped(raw.get("estimated_impact"), 6, 1, 10)
    ease = _to_int_clamped(raw.get("ease"), 6, 1, 10)
    ice_score = round(estimated_impact * confidence * ease, 4)

    hypothesis_id = _stable_hypothesis_id(hypothesis_key, lever_type, unit, scope, action_summary)
    falsifiability = coerce_string(raw.get("falsifiability_condition", ""), max_len=240)
    if not falsifiability:
        falsifiability = "Reject if target metric does not improve with guardrails preserved during 14-day window."

    anti_gaming_check = None
    if expected_direction == "decrease":
        primary_val = float(metrics.get(primary_guardrail_metric) or 0.0) if primary_guardrail_metric else 0.0
        secondary_val = float(metrics.get(secondary_guardrail_metric) or 0.0) if secondary_guardrail_metric else 0.0
        anti_gaming_check = {
            "metric_pair": [primary_guardrail_metric, secondary_guardrail_metric],
            primary_guardrail_metric: round(primary_val, 4),
            secondary_guardrail_metric: round(secondary_val, 4),
            "starvation_risk": (
                (bool(primary_guardrail_metric) and primary_val < guardrails["primary_guardrail_threshold"])
                or (bool(secondary_guardrail_metric) and secondary_val < guardrails["secondary_guardrail_threshold"])
            ),
            "rule": "Do not accept decreasing-target improvements if availability degrades.",
        }

    return {
        "hypothesis_key": hypothesis_key,
        "action_summary": action_summary,
        "hypothesis_id": hypothesis_id,
        "hypothesis_statement": statement,
        "lever_type": lever_type,
        "unit": unit,
        "scope": scope,
        "target_metric": target_metric,
        "expected_direction": expected_direction,
        "expected_uplift_range": expected_uplift_range,
        "alternatives_considered": alternatives,
        "why_not_alternative": coerce_string(raw.get("why_not_alternative", ""), max_len=240)
        or "Context rewriter chose this intervention due to strongest current signal fit.",
        "guardrails": guardrails,
        "evidence_refs": refs,
        "falsifiability_condition": falsifiability,
        "anti_gaming_check": anti_gaming_check,
        "confidence": confidence,
        "estimated_impact": estimated_impact,
        "ease": ease,
        "ice_score": ice_score,
        "dynamic_hypothesis": True,
        "rank": index,
    }


def _validate_context_rewriter_portfolio_against_schema(
    hypothesis_portfolio: list[dict[str, Any]],
    output_schema: dict[str, Any],
) -> None:
    allowed_targets = domain_target_metric_aliases()
    if not allowed_targets:
        raise ConfigurationError("Domain template target aliases are required for context rewriter")
    if not isinstance(hypothesis_portfolio, list) or len(hypothesis_portfolio) < 3:
        raise ValueError("context_rewriter portfolio must contain at least 3 hypotheses")
    for idx, hyp in enumerate(hypothesis_portfolio):
        if not isinstance(hyp, dict):
            raise ValueError(f"context_rewriter hypothesis[{idx}] must be object")
        for key in (
            "hypothesis_id",
            "hypothesis_statement",
            "lever_type",
            "unit",
            "target_metric",
            "guardrails",
            "evidence_refs",
        ):
            if key not in hyp:
                raise ValueError(f"context_rewriter hypothesis[{idx}] missing '{key}'")
        if str(hyp.get("target_metric", "")).strip() not in allowed_targets:
            raise ValueError(f"context_rewriter hypothesis[{idx}] has invalid target_metric")

    schema_hp = (
        output_schema.get("properties", {}).get("hypothesis_portfolio")
        if isinstance(output_schema.get("properties"), dict)
        else None
    )
    if not isinstance(schema_hp, dict):
        return
    wrapper_schema = {
        "type": "object",
        "required": ["hypothesis_portfolio"],
        "properties": {
            "hypothesis_portfolio": schema_hp,
        },
    }
    try:
        from jsonschema import validate as _jsonschema_validate  # type: ignore
    except Exception:
        return
    _jsonschema_validate(instance={"hypothesis_portfolio": hypothesis_portfolio}, schema=wrapper_schema)


def _llm_context_rewriter_hypothesis_portfolio(
    *,
    backend_name: str,
    run_id: str,
    metrics: dict[str, Any],
    captain: dict[str, Any],
    synthetic_bias: dict[str, Any],
    model_override: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    requested_model = _doctor_model_override_for_backend(backend_name, model_override)
    groq_candidates = [requested_model, DOCTOR_VARIANCE_GROQ_MODEL, DOCTOR_GROQ_FALLBACK_MODEL]
    tiers = build_runtime_failover_tiers(
        backend_requested=backend_name,
        groq_models=[str(x).strip() for x in groq_candidates if str(x).strip()],
        include_ollama=True,
    )
    prov: dict[str, Any] = {
        "selected_by": "context_rewriter_llm",
        "backend_requested": backend_name,
        "remote_allowed": (os.getenv("LLM_ALLOW_REMOTE", "0") == "1"),
        "model": None,
        "used_fallback": False,
        "fallback_reason": None,
        "fallback_tier": "none",
        "provisional_local_fallback": False,
        "needs_cloud_reconciliation": False,
    }

    captain_issues = (
        ((captain.get("result") or {}).get("issues") if isinstance(captain, dict) else [])
        if isinstance((captain.get("result") if isinstance(captain, dict) else {}), dict)
        else []
    )
    if not isinstance(captain_issues, list):
        captain_issues = []
    signals = synthetic_bias.get("signals", []) if isinstance(synthetic_bias.get("signals"), list) else []
    metric_keys = [str(x).strip() for x in sorted(READY_NOW_METRICS) if str(x).strip()][:10]
    llm_metrics = {metric_name: metrics.get(metric_name) for metric_name in metric_keys}
    llm_input = {
        "run_id": run_id,
        "metrics": llm_metrics,
        "captain_issues": captain_issues[:8],
        "synthetic_bias_signals": signals[:8],
    }
    target_aliases = sorted(domain_target_metric_aliases())
    if not target_aliases:
        raise ConfigurationError("Domain template target aliases are required for context rewriter")
    aliases_csv = ", ".join(target_aliases)
    prompt = (
        "Return STRICT JSON object with key 'hypothesis_portfolio' only.\n"
        "hypothesis_portfolio must be an array with >=3 items covering target_metric values "
        f"{aliases_csv}.\n"
        "Each item keys: hypothesis_key, action_summary, hypothesis_statement, lever_type, unit, scope, "
        "target_metric, expected_direction, expected_uplift_range, alternatives_considered, guardrails, evidence_refs, "
        "falsifiability_condition, confidence, estimated_impact, ease.\n"
        "Use only provided inputs; no markdown.\n"
        f"INPUT:\n{json.dumps(llm_input, ensure_ascii=False)}"
    )
    raw, gen_meta = generate_with_runtime_failover(
        run_id=run_id,
        agent_name="doctor",
        call_name="context_rewriter",
        prompt=prompt,
        system_prompt=DOCTOR_SYSTEM_PROMPT_V2,
        tiers=tiers,
        deterministic_generator=None,
    )
    prov["model"] = str(gen_meta.get("model", "")).strip() or None
    prov["used_fallback"] = bool(gen_meta.get("used_fallback", False))
    prov["fallback_reason"] = str(gen_meta.get("fallback_reason", "")).strip() or None
    prov["fallback_tier"] = str(gen_meta.get("fallback_tier", "none") or "none")
    prov["provisional_local_fallback"] = bool(gen_meta.get("provisional_local_fallback", False))
    prov["needs_cloud_reconciliation"] = bool(gen_meta.get("needs_cloud_reconciliation", False))
    if isinstance(gen_meta.get("attempts"), list):
        prov["runtime_failover_attempts"] = [x for x in gen_meta.get("attempts", []) if isinstance(x, dict)][:12]
    map_ref = str(gen_meta.get("obfuscation_map_ref", "")).strip()
    if map_ref:
        prov["obfuscation_map_ref"] = map_ref
    parsed = parse_json_object_loose(raw)
    if not isinstance(parsed, dict):
        raise ValueError("context_rewriter_non_json")
    portfolio_raw = parsed.get("hypothesis_portfolio")
    if not isinstance(portfolio_raw, list):
        raise ValueError("context_rewriter_missing_hypothesis_portfolio")

    normalized: list[dict[str, Any]] = []
    for idx, item in enumerate(portfolio_raw[:8], start=1):
        if not isinstance(item, dict):
            continue
        normalized.append(
            _normalize_context_rewriter_hypothesis(
                item,
                index=idx,
                run_id=run_id,
                metrics=metrics,
                synthetic_bias=synthetic_bias,
            )
        )
    if len(normalized) < 3:
        raise ValueError("context_rewriter_portfolio_too_small")
    normalized = sorted(normalized, key=lambda x: float(x.get("ice_score", 0.0)), reverse=True)
    for idx, hyp in enumerate(normalized, start=1):
        hyp["rank"] = idx
    return normalized, prov


def _build_hypothesis_portfolio_with_mode(
    *,
    run_id: str,
    metrics: dict[str, Any],
    captain: dict[str, Any],
    synthetic_bias: dict[str, Any],
    dynamic_enabled: bool,
    backend_name: str,
    output_schema: dict[str, Any],
    model_override: str | None = None,
) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    if not dynamic_enabled:
        portfolio = _build_hypothesis_portfolio(run_id, metrics, captain, synthetic_bias, dynamic_enabled=False)
        return portfolio, "seed_templates", {"selected_by": "seed_templates"}

    try:
        portfolio, prov = _llm_context_rewriter_hypothesis_portfolio(
            backend_name=backend_name,
            run_id=run_id,
            metrics=metrics,
            captain=captain,
            synthetic_bias=synthetic_bias,
            model_override=model_override,
        )
        _validate_context_rewriter_portfolio_against_schema(portfolio, output_schema)
        return portfolio, "context_rewriter", prov
    except Exception as exc:
        portfolio = _build_hypothesis_portfolio(run_id, metrics, captain, synthetic_bias, dynamic_enabled=False)
        return (
            portfolio,
            "fallback_seed_templates",
            {
                "selected_by": "seed_templates_fallback",
                "used_fallback": True,
                "fallback_reason": str(exc).splitlines()[0][:220],
                "backend_requested": backend_name,
            },
        )


def _write_doctor_context(
    run_id: str,
    snapshot: dict[str, Any],
    dq: dict[str, Any],
    captain: dict[str, Any],
    synthetic_bias: dict[str, Any],
    *,
    experiment_id: str,
    assignment_status: str,
    measurement_state: str,
    ab_status: str,
    ab_report: dict[str, Any] | None,
    paired_status: str,
    layers_present: dict[str, Any],
    reasoning_confidence_inputs: dict[str, Any],
    stat_bundle_ref: str | None,
) -> Path:
    metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
    run_cfg = snapshot.get("run_config", {}) if isinstance(snapshot.get("run_config"), dict) else {}
    ab_summary = ab_report.get("summary", {}) if isinstance(ab_report, dict) and isinstance(ab_report.get("summary"), dict) else {}
    ab_primary_metric = str(ab_summary.get("primary_metric", "")).strip()
    try:
        ab_primary_goal = goal_from_metric(ab_primary_metric)
    except Exception:
        ab_primary_goal = "unknown"
    decision_trace_path = Path(f"data/decision_traces/{run_id}_actions.jsonl")
    decision_trace_sample: list[dict[str, Any]] = []
    if decision_trace_path.exists():
        try:
            for line in decision_trace_path.read_text(encoding="utf-8").splitlines()[:20]:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if isinstance(row, dict):
                    decision_trace_sample.append(row)
        except Exception:
            decision_trace_sample = []

    dq_rows = dq.get("rows", []) if isinstance(dq.get("rows"), list) else []
    goal_blocks: dict[str, dict[str, Any]] = {}
    goal_defaults = domain_goal_default_metrics()
    goal_metric_groups = domain_goal_metric_sets()
    for goal_id in _ordered_goal_ids():
        primary_metric = str(goal_defaults.get(goal_id, "")).strip()
        if not primary_metric:
            continue
        family = [m for m in sorted(goal_metric_groups.get(goal_id, set())) if str(m).strip()]
        if primary_metric not in family:
            family.insert(0, primary_metric)
        metric_slice = family[:4]
        goal_blocks[goal_id] = {
            "primary_metric": primary_metric,
            "metrics": {metric_name: metrics.get(metric_name) for metric_name in metric_slice},
        }
    context_payload = {
        "run_id": run_id,
        "experiment_header": {
            "experiment_id": experiment_id or None,
            "experiment_unit": run_cfg.get("experiment_unit"),
            "treat_pct": run_cfg.get("experiment_treat_pct"),
            "window_days": run_cfg.get("horizon_days", 14),
            "pre_period_weeks": run_cfg.get("ab_pre_period_weeks"),
            "test_period_weeks": run_cfg.get("ab_test_period_weeks"),
            "wash_in_days": run_cfg.get("ab_wash_in_days"),
            "attribution_window_rule": run_cfg.get("ab_attribution_rule"),
            "test_side": run_cfg.get("ab_test_side"),
            "alpha": 0.05,
            "multiple_testing_policy": "single primary, others descriptive",
            "measurement_state": measurement_state,
            "ab_status": ab_status,
            "srm_status": ab_summary.get("srm_status"),
            "ab_primary_metric": ab_primary_metric,
            "ab_primary_goal": ab_primary_goal,
            "paired_status": str(paired_status or "SINGLE").strip().upper(),
            "sample_size": {
                "control_orders": ab_summary.get("n_orders_control"),
                "treatment_orders": ab_summary.get("n_orders_treatment"),
            },
        },
        "layers_present": layers_present if isinstance(layers_present, dict) else {},
        "reasoning_confidence_inputs": reasoning_confidence_inputs if isinstance(reasoning_confidence_inputs, dict) else {},
        "goal_blocks": goal_blocks,
        "guardrails": {
            str(row.get("metric", "")): metrics.get(str(row.get("metric", "")))
            for row in _doctor_guardrails(metrics)
            if str(row.get("metric", "")).strip()
        },
        "synthetic_bias_flags": {
            "status": synthetic_bias.get("status"),
            "findings_count": len(synthetic_bias.get("findings", [])) if isinstance(synthetic_bias.get("findings"), list) else 0,
            "signals_count": len(synthetic_bias.get("signals", [])) if isinstance(synthetic_bias.get("signals"), list) else 0,
        },
        "decision_trace": {
            "path": str(decision_trace_path),
            "sample": decision_trace_sample,
        },
        "dq_status": {
            "qa_status": dq.get("qa_status"),
            "fail_count": sum(1 for r in dq_rows if isinstance(r, dict) and str(r.get("status")) == "FAIL"),
            "warn_count": sum(1 for r in dq_rows if isinstance(r, dict) and str(r.get("status")) == "WARN"),
        },
        "assignment_status": {
            "assignment_status": assignment_status,
            "measurement_state": measurement_state,
            "ab_status": ab_status,
        },
        "sources": {
            "metrics_snapshot": f"data/metrics_snapshots/{run_id}.json",
            "dq_report": f"data/dq_reports/{run_id}.json",
            "captain_report": f"data/llm_reports/{run_id}_captain.json",
            "ab_report": (f"data/ab_reports/{run_id}_{experiment_id}_ab.json" if experiment_id else None),
            "synthetic_bias_report": f"data/realism_reports/{run_id}_synthetic_bias.json",
            "stat_evidence_bundle": stat_bundle_ref,
        },
    }
    path = Path(f"data/agent_context/{run_id}_doctor_context.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(context_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _optional_llm_summary(
    backend_name: str, payload: dict[str, Any], run_id: str, model_override: str | None = None
) -> tuple[str, dict[str, Any]]:
    requested_model = _doctor_model_override_for_backend(backend_name, model_override)
    groq_candidates = [requested_model, DOCTOR_VARIANCE_GROQ_MODEL, DOCTOR_GROQ_FALLBACK_MODEL]
    tiers = build_runtime_failover_tiers(
        backend_requested=backend_name,
        groq_models=[str(x).strip() for x in groq_candidates if str(x).strip()],
        include_ollama=True,
    )
    prov: dict[str, Any] = {
        "backend_requested": backend_name,
        "remote_allowed": (os.getenv("LLM_ALLOW_REMOTE", "0") == "1"),
        "model": None,
        "used_fallback": False,
        "fallback_reason": None,
        "fallback_tier": "none",
        "provisional_local_fallback": False,
        "needs_cloud_reconciliation": False,
    }
    try:
        refs = _domain_reference_pack()
        prompt = (
            "Using the Doctor Variance protocol, summarize this deterministic result in <=8 bullets. "
            "Do not alter decisions or numeric fields. If methods are inconsistent, say so explicitly.\n"
            + "Apply canonical rules and mirror golden report structure where applicable.\n"
            + json.dumps(
                {
                    "payload": payload,
                    "canonical_rules": refs.get("canonical_rules", []),
                    "golden_examples": refs.get("golden_examples", {}),
                },
                ensure_ascii=False,
            )
        )
        raw, gen_meta = generate_with_runtime_failover(
            run_id=run_id,
            agent_name="doctor",
            call_name="summary",
            prompt=prompt,
            system_prompt=DOCTOR_SYSTEM_PROMPT_V2,
            tiers=tiers,
            deterministic_generator=lambda: "LLM summary unavailable; deterministic output is authoritative.",
        )
        prov["model"] = str(gen_meta.get("model", "")).strip() or None
        prov["used_fallback"] = bool(gen_meta.get("used_fallback", False))
        prov["fallback_reason"] = str(gen_meta.get("fallback_reason", "")).strip() or None
        prov["fallback_tier"] = str(gen_meta.get("fallback_tier", "none") or "none")
        prov["provisional_local_fallback"] = bool(gen_meta.get("provisional_local_fallback", False))
        prov["needs_cloud_reconciliation"] = bool(gen_meta.get("needs_cloud_reconciliation", False))
        if isinstance(gen_meta.get("attempts"), list):
            prov["runtime_failover_attempts"] = [x for x in gen_meta.get("attempts", []) if isinstance(x, dict)][:12]
        map_ref = str(gen_meta.get("obfuscation_map_ref", "")).strip()
        if map_ref:
            prov["obfuscation_map_ref"] = map_ref
        return raw.strip()[:2500], prov
    except Exception as exc:
        prov["used_fallback"] = True
        if prov.get("fallback_reason") is None:
            prov["fallback_reason"] = f"llm_summary_error:{str(exc).splitlines()[0][:160]}"
        return "LLM summary unavailable; deterministic output is authoritative.", prov


def _stat_metric_type(metric: str) -> str:
    m = str(metric or "").strip().lower()
    if m.endswith("_rate") or m.endswith("_ratio") or m.endswith("_share") or m.endswith("_pct") or m.endswith("_margin"):
        return "ratio_or_proportion"
    if m.endswith("_cnt") or m.endswith("_count") or m.startswith("n_"):
        return "proportion_or_count"
    if m:
        return "continuous"
    return "unknown"


def _artifact_ref_to_path(value: Any) -> Path | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.startswith("artifact:"):
        raw = raw[len("artifact:") :]
    if "#" in raw:
        raw = raw.split("#", 1)[0]
    if not raw.strip():
        return None
    return Path(raw)


def _load_paired_context_payload(run_id: str) -> tuple[dict[str, Any] | None, str]:
    path = paired_experiment_context_path(run_id)
    try:
        payload = load_json_optional_with_integrity(path, required=False)
    except Exception as exc:
        raise RuntimeError(f"METHODOLOGY_INVARIANT_BROKEN:paired_context_integrity_error:{exc}") from exc
    if not isinstance(payload, dict):
        return None, "SINGLE"
    status = str(payload.get("paired_status", "SINGLE")).strip().upper() or "SINGLE"
    return payload, status


def _resolve_ctrl_snapshot_path(
    *,
    run_id: str,
    control_run_id: str,
    paired_context: dict[str, Any] | None,
    paired_status: str,
) -> Path | None:
    if control_run_id.strip():
        return Path(f"data/metrics_snapshots/{control_run_id.strip()}.json")
    if not isinstance(paired_context, dict):
        return None
    if str(paired_status).strip().upper() != "COMPLETE":
        return None
    layer1 = paired_context.get("layer1", {}) if isinstance(paired_context.get("layer1"), dict) else {}
    ctrl_ref = _artifact_ref_to_path(layer1.get("ctrl_metrics_snapshot_ref"))
    if isinstance(ctrl_ref, Path):
        return ctrl_ref
    ctrl_run_id = str(paired_context.get("ctrl_run_id", "")).strip()
    if ctrl_run_id:
        return Path(f"data/metrics_snapshots/{ctrl_run_id}.json")
    return None


def _best_similarity_from_history_rows(rows: list[dict[str, Any]]) -> float | None:
    best: float | None = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            score = float(row.get("similarity_score"))
        except Exception:
            continue
        if best is None or score > best:
            best = score
    return best


def _extract_primary_metric_pvalue(
    stat_bundle: dict[str, Any],
    primary_metric: str,
) -> float | None:
    rows = stat_bundle.get("metrics", []) if isinstance(stat_bundle.get("metrics"), list) else []
    primary_key = str(primary_metric or "").strip()
    target_row: dict[str, Any] | None = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("metric_id", "")).strip() == primary_key:
            target_row = row
            break
    if target_row is None and rows:
        target_row = rows[0] if isinstance(rows[0], dict) else None
    if not isinstance(target_row, dict):
        return None
    try:
        value = target_row.get("p_value")
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _guardrail_data_complete_from_bundle(stat_bundle: dict[str, Any]) -> bool:
    rows = stat_bundle.get("guardrail_status_check", []) if isinstance(stat_bundle.get("guardrail_status_check"), list) else []
    if not rows:
        return False
    for row in rows:
        if not isinstance(row, dict):
            return False
        if str(row.get("status", "")).strip().upper() == "NO_DATA":
            return False
    return True


def _infer_expected_direction_from_experiment(experiment: dict[str, Any]) -> str:
    hypotheses = experiment.get("hypotheses", []) if isinstance(experiment.get("hypotheses"), list) else []
    if hypotheses and isinstance(hypotheses[0], dict):
        r = str(hypotheses[0].get("expected_effect_range", "")).strip()
        if r.startswith("+"):
            return "increase"
        if r.startswith("-"):
            return "decrease"
    metric = str(experiment.get("north_star_metric", "")).strip().lower()
    alias = domain_signal_metric_to_target_metric().get(metric, "")
    return _target_metric_expected_direction(alias) if alias else "increase"


def _methodology_fallback_for_experiment(
    experiment: dict[str, Any],
    reason: str,
    *,
    backend_requested: str | None = None,
    model_intent: str | None = None,
    remote_allowed: bool | None = None,
    preflight_issue: str | None = None,
    srm_status: str | None = None,
) -> dict[str, Any]:
    primary_metric = _resolve_experiment_primary_metric(experiment)
    unit = str(experiment.get("unit", "unknown") or "unknown").strip().lower()
    analysis_unit = str(experiment.get("analysis_unit", unit) or unit).strip().lower()
    randomization_unit = str(experiment.get("randomization_unit", unit) or unit).strip().lower()
    metric_type = _stat_metric_type(primary_metric)
    expected_direction = _infer_expected_direction_from_experiment(experiment)
    if metric_type == "continuous":
        principle = "Two-sample tests: two population means"
        test_family = "Welch t-test"
        executor = "welch_t_test"
        rationale = "Continuous metric; Welch handles unequal variances and unequal sample sizes."
    elif metric_type == "proportion_or_count":
        principle = "Two-sample tests: proportions / conversion-type outcomes"
        test_family = "Two-proportion test / chi-square (fallback to bootstrap if needed)"
        executor = "two_proportion_or_bootstrap"
        rationale = "Count/conversion-like outcome; compare arm-level rates on randomized units."
    elif metric_type == "ratio_or_proportion":
        principle = "Two-sample tests: ratio metrics / proportions"
        test_family = "Delta method or bootstrap"
        executor = "ratio_metric_bootstrap_or_delta"
        rationale = "Ratio metric; ratio-aware inference is safer than raw-value normality assumptions."
    else:
        principle = "Metric-specific review required"
        test_family = "Conservative bootstrap / manual review"
        executor = "manual_review_required"
        rationale = "Unknown metric type; deterministic fallback requires manual methodology review."
    side = str(experiment.get("test_side", "two-sided") or "two-sided").strip().lower()
    if side not in {"one-sided", "two-sided"}:
        side = "two-sided"
    alpha = float(experiment.get("alpha", 0.05) or 0.05)
    confidence_level = float(experiment.get("confidence_level", 0.95) or 0.95)
    power_target = float(experiment.get("power_target", 0.80) or 0.80)
    return {
        "primary_metric": primary_metric,
        "metric_type": metric_type,
        "analysis_unit": analysis_unit,
        "randomization_unit": randomization_unit,
        "statistical_principle": principle,
        "test_family": test_family,
        "executor_method": executor,
        "test_side": side,
        "expected_direction": expected_direction,
        "alpha": alpha,
        "confidence_level": confidence_level,
        "power_target": power_target,
        "reason_selected": rationale,
        "alternatives_considered": [],
        "why_not_alternatives": "",
        "assumption_notes": [
            "Validated by deterministic compatibility checks",
            "Fallback used when LLM proposal is unavailable/invalid",
            *([f"Preflight blocked LLM call: {preflight_issue}"] if preflight_issue else []),
            *([f"Observed SRM status before fallback: {str(srm_status or '').upper()}"] if srm_status else []),
        ],
        "srm_policy": {
            "alpha": 0.05,
            "effect_size_imbalance_threshold_pp": 5.0,
            "why": "Use p-value + imbalance magnitude to avoid overreacting to tiny but statistically significant allocation drift.",
        },
        "null_hypothesis_metric": f"{(primary_metric or 'metric')}_t = {(primary_metric or 'metric')}_c",
        "alternative_hypothesis_metric": (
            f"{(primary_metric or 'metric')}_t != {(primary_metric or 'metric')}_c"
            if side == "two-sided"
            else (
                f"{(primary_metric or 'metric')}_t > {(primary_metric or 'metric')}_c"
                if expected_direction == "increase"
                else f"{(primary_metric or 'metric')}_t < {(primary_metric or 'metric')}_c"
            )
        ),
        "selection_provenance": {
            "selected_by": "doctor_deterministic_fallback",
            "selection_mode": "fallback",
            "fallback_reason": reason,
            "backend_requested": backend_requested,
            "model_intent": model_intent,
            "remote_allowed": remote_allowed,
        },
        "validation": {
            "passed": True,
            "issues": [],
        },
    }


def _normalize_test_side(raw_side: str, expected_direction: str) -> tuple[str, str]:
    s = str(raw_side or "").strip().lower()
    if s in {"one-sided", "onesided", "one_sided"}:
        if expected_direction in {"increase", "decrease"}:
            return "one-sided", ""
        return "two-sided", "one-sided requested without expected_direction; normalized to two-sided"
    return "two-sided", ""


def _validate_llm_methodology_choice(raw: dict[str, Any], experiment: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    primary_metric = str(experiment.get("north_star_metric", "")).strip()
    expected_metric_type = _stat_metric_type(primary_metric)
    expected_direction = _infer_expected_direction_from_experiment(experiment)
    unit = str(experiment.get("unit", "unknown") or "unknown").strip().lower()
    analysis_unit = str(experiment.get("analysis_unit", unit) or unit).strip().lower()
    randomization_unit = str(experiment.get("randomization_unit", unit) or unit).strip().lower()
    metric_type = str(raw.get("metric_type", expected_metric_type)).strip().lower() or expected_metric_type
    if expected_metric_type != "unknown" and metric_type not in {expected_metric_type, "unknown"}:
        issues.append(f"metric_type_mismatch:{metric_type}!={expected_metric_type}")
        metric_type = expected_metric_type

    test_family = coerce_string(raw.get("test_family", ""), max_len=200)
    tf_l = test_family.lower()
    if not test_family:
        exec_hint = coerce_string(raw.get("executor_method", ""), max_len=100).lower()
        if "welch" in exec_hint:
            test_family = "Welch t-test"
            tf_l = test_family.lower()
        elif "bootstrap" in exec_hint:
            test_family = "Bootstrap test"
            tf_l = test_family.lower()
        elif "proportion" in exec_hint or "chi" in exec_hint:
            test_family = "Two-proportion / chi-square"
            tf_l = test_family.lower()
        elif "delta" in exec_hint or "ratio" in exec_hint:
            test_family = "Delta method / ratio metric"
            tf_l = test_family.lower()
        else:
            issues.append("missing_test_family")
    if expected_metric_type == "continuous":
        continuous_markers = ("welch", "bootstrap", "permutation", "t-test", "t test", "mean", "means")
        if not any(k in tf_l for k in continuous_markers):
            issues.append("incompatible_test_family_for_continuous")
    elif expected_metric_type == "proportion_or_count" and not any(k in tf_l for k in ["proportion", "chi", "bootstrap", "binomial", "z-test"]):
        issues.append("incompatible_test_family_for_proportion_or_count")
    elif expected_metric_type == "ratio_or_proportion" and not any(k in tf_l for k in ["delta", "bootstrap", "ratio"]):
        issues.append("incompatible_test_family_for_ratio")

    test_side, side_issue = _normalize_test_side(str(raw.get("test_side", "two-sided")), expected_direction)
    if side_issue:
        issues.append(side_issue)

    alpha = float(raw.get("alpha", 0.05) or 0.05)
    if not (0.0 < alpha < 1.0):
        issues.append("alpha_out_of_range")
        alpha = 0.05
    ci = float(raw.get("confidence_level", 0.95) or 0.95)
    if not (0.0 < ci < 1.0):
        issues.append("confidence_level_out_of_range")
        ci = 0.95
    if abs((1.0 - alpha) - ci) > 0.051:
        issues.append("alpha_confidence_inconsistent")
        ci = 1.0 - alpha

    statistical_principle = coerce_string(raw.get("statistical_principle", ""), max_len=300)
    reason_selected = coerce_string(raw.get("reason_selected", ""), max_len=600)
    if not statistical_principle:
        issues.append("missing_statistical_principle")
    if not reason_selected:
        issues.append("missing_reason_selected")

    if not isinstance(raw.get("alternatives_considered", []), list):
        issues.append("alternatives_not_list")
    alternatives = coerce_string_list(raw.get("alternatives_considered", []), max_items=5)

    if not isinstance(raw.get("assumption_notes", []), list):
        issues.append("assumption_notes_not_list")
    assumptions = coerce_string_list(raw.get("assumption_notes", []), max_items=8)

    coercible_only = {"alternatives_not_list", "assumption_notes_not_list"}
    hard_issues = [i for i in issues if i not in coercible_only]

    if hard_issues:
        return None, issues

    executor_method = str(raw.get("executor_method", "")).strip().lower()
    if not executor_method:
        if "welch" in tf_l:
            executor_method = "welch_t_test"
        elif "delta" in tf_l:
            executor_method = "delta_method"
        elif "bootstrap" in tf_l:
            executor_method = "bootstrap"
        elif "chi" in tf_l or "proportion" in tf_l:
            executor_method = "two_proportion"
        else:
            executor_method = "manual_review_required"

    norm = {
        "primary_metric": primary_metric,
        "metric_type": expected_metric_type if expected_metric_type != "unknown" else metric_type,
        "analysis_unit": analysis_unit,
        "randomization_unit": randomization_unit,
        "statistical_principle": statistical_principle,
        "test_family": test_family,
        "executor_method": executor_method,
        "test_side": test_side,
        "expected_direction": expected_direction,
        "alpha": alpha,
        "confidence_level": ci,
        "power_target": float(raw.get("power_target", 0.8) or 0.8),
        "reason_selected": reason_selected,
        "alternatives_considered": alternatives,
        "why_not_alternatives": str(raw.get("why_not_alternatives", "")).strip(),
        "assumption_notes": assumptions,
        "srm_policy": {
            "alpha": 0.05,
            "effect_size_imbalance_threshold_pp": float(raw.get("srm_effect_size_imbalance_threshold_pp", 5.0) or 5.0),
            "why": "Use p-value + imbalance magnitude to distinguish statistically detectable drift from practically meaningful allocation bias.",
        },
        "null_hypothesis_metric": f"{(primary_metric or 'metric')}_t = {(primary_metric or 'metric')}_c",
        "alternative_hypothesis_metric": (
            f"{(primary_metric or 'metric')}_t != {(primary_metric or 'metric')}_c"
            if test_side == "two-sided"
            else (
                f"{(primary_metric or 'metric')}_t > {(primary_metric or 'metric')}_c"
                if expected_direction == "increase"
                else f"{(primary_metric or 'metric')}_t < {(primary_metric or 'metric')}_c"
            )
        ),
        "selection_provenance": {
            "selected_by": "doctor_llm_validated",
            "selection_mode": "llm_validated",
            "model_intent": str(raw.get("model_name", "")).strip() or "doctor_llm",
        },
        "validation": {"passed": True, "issues": []},
    }
    if issues:
        norm["validation"] = {"passed": True, "issues": issues}
    return norm, []


def _llm_methodology_choice(
    backend_name: str,
    run_id: str,
    experiment: dict[str, Any],
    metrics: dict[str, Any],
    measurement_state: str,
    ab_status: str,
    srm_status: str = "MISSING",
    reference_pack: dict[str, Any] | None = None,
    model_override: str | None = None,
) -> dict[str, Any]:
    requested_model = _doctor_model_override_for_backend(backend_name, model_override)
    groq_candidates = [requested_model, DOCTOR_VARIANCE_GROQ_MODEL, DOCTOR_GROQ_FALLBACK_MODEL]
    tiers = build_runtime_failover_tiers(
        backend_requested=backend_name,
        groq_models=[str(x).strip() for x in groq_candidates if str(x).strip()],
        include_ollama=True,
    )
    primary_metric = _resolve_experiment_primary_metric(experiment)
    unit = str(experiment.get("unit", "unknown") or "unknown").strip().lower()
    analysis_unit = str(experiment.get("analysis_unit", unit) or unit).strip().lower()
    randomization_unit = str(experiment.get("randomization_unit", unit) or unit).strip().lower()
    hypotheses = experiment.get("hypotheses", []) if isinstance(experiment.get("hypotheses"), list) else []
    hyp0 = hypotheses[0] if hypotheses and isinstance(hypotheses[0], dict) else {}
    expected_direction = _infer_expected_direction_from_experiment(experiment)
    references = reference_pack if isinstance(reference_pack, dict) else _domain_reference_pack()
    llm_input = {
        "experiment_name": str(experiment.get("name", "")).strip(),
        "goal": str(experiment.get("goal", "")).strip(),
        "primary_metric": primary_metric,
        "metric_type_hint": _stat_metric_type(primary_metric),
        "analysis_unit": analysis_unit,
        "randomization_unit": randomization_unit,
        "expected_direction": expected_direction,
        "measurement_state": str(measurement_state or "").upper(),
        "ab_status": str(ab_status or "").upper(),
        "srm_status": str(srm_status or "MISSING").upper(),
        "design_requirements": {
            "pre_period_weeks": experiment.get("pre_period_weeks"),
            "test_period_weeks": experiment.get("test_period_weeks"),
            "wash_in_days": experiment.get("wash_in_days"),
            "attribution_window_rule": experiment.get("attribution_window_rule"),
            "test_side": experiment.get("test_side"),
            "metric_semantics": experiment.get("metric_semantics"),
        },
        "baseline_metric_values": {
            metric_name: metrics.get(metric_name)
            for metric_name in [m for m in sorted(READY_NOW_METRICS)[:8]]
        },
        "doctor_hypothesis_hint": {
            "analysis_method_legacy": hyp0.get("analysis_method"),
            "primary_metric_legacy": hyp0.get("primary_metric"),
            "sample_size_gate": hyp0.get("sample_size_gate"),
        },
        "constraints": {
            "alpha_default": 0.05,
            "ci_default": 0.95,
            "srm_alpha": 0.05,
            "require_reason_and_alternatives": True,
        },
        "canonical_rules": references.get("canonical_rules", []),
        "canonical_excerpt": references.get("canonical_excerpt", ""),
        "golden_examples": references.get("golden_examples", {}),
    }
    prompt = (
        "Return one JSON object with keys exactly:\n"
        "statistical_principle, test_family, executor_method, metric_type, test_side, alpha, confidence_level, power_target, "
        "reason_selected, alternatives_considered, why_not_alternatives, assumption_notes, srm_effect_size_imbalance_threshold_pp.\n"
        "Use short, concrete values. No markdown.\n"
        "Respect canonical rules and keep the primary metric unchanged.\n\n"
        f"INPUT:\n{json.dumps(llm_input, ensure_ascii=False)}"
    )
    raw, gen_meta = generate_with_runtime_failover(
        run_id=run_id,
        agent_name="doctor",
        call_name="methodology_selection",
        prompt=prompt,
        system_prompt=DOCTOR_METHOD_SELECTION_SYSTEM_PROMPT,
        tiers=tiers,
        deterministic_generator=None,
    )
    parsed = parse_json_object_loose(raw)
    if not isinstance(parsed, dict):
        raise ValueError("llm_methodology_non_json")
    validated, issues = _validate_llm_methodology_choice(parsed, experiment)
    if validated is None:
        raise ValueError("llm_methodology_invalid:" + ",".join(issues[:5]))
    prov = validated.get("selection_provenance", {}) if isinstance(validated.get("selection_provenance"), dict) else {}
    prov["backend_requested"] = backend_name
    prov["remote_allowed"] = (os.getenv("LLM_ALLOW_REMOTE", "0") == "1")
    prov["model_intent"] = str(requested_model or "")
    prov["actual_model"] = str(gen_meta.get("model", "")).strip() or None
    prov["fallback_tier"] = str(gen_meta.get("fallback_tier", "none") or "none")
    prov["used_fallback_backend"] = bool(gen_meta.get("used_fallback", False))
    prov["fallback_reason"] = str(gen_meta.get("fallback_reason", "")).strip() or None
    prov["provisional_local_fallback"] = bool(gen_meta.get("provisional_local_fallback", False))
    prov["needs_cloud_reconciliation"] = bool(gen_meta.get("needs_cloud_reconciliation", False))
    if isinstance(gen_meta.get("attempts"), list):
        prov["runtime_failover_attempts"] = [x for x in gen_meta.get("attempts", []) if isinstance(x, dict)][:12]
    map_ref = str(gen_meta.get("obfuscation_map_ref", "")).strip()
    if map_ref:
        prov["obfuscation_map_ref"] = map_ref
    validated["selection_provenance"] = prov
    return validated


def _select_statistical_methodology_for_experiment(
    backend_name: str,
    run_id: str,
    experiment: dict[str, Any],
    metrics: dict[str, Any],
    measurement_state: str,
    ab_status: str,
    srm_status: str = "MISSING",
    reference_pack: dict[str, Any] | None = None,
    model_override: str | None = None,
) -> dict[str, Any]:
    preflight_issue = _llm_methodology_preflight_issue(
        experiment=experiment,
        measurement_state=measurement_state,
        ab_status=ab_status,
        srm_status=srm_status,
    )
    if preflight_issue:
        intent_model = (
            (model_override or DOCTOR_VARIANCE_GROQ_MODEL)
            if backend_name in {"groq", "auto"}
            else "local_backend"
        )
        return _methodology_fallback_for_experiment(
            experiment,
            reason=f"llm_preflight_blocked:{preflight_issue}",
            backend_requested=backend_name,
            model_intent=intent_model,
            remote_allowed=(os.getenv("LLM_ALLOW_REMOTE", "0") == "1"),
            preflight_issue=preflight_issue,
            srm_status=srm_status,
        )
    try:
        return _llm_methodology_choice(
            backend_name=backend_name,
            run_id=run_id,
            experiment=experiment,
            metrics=metrics,
            measurement_state=measurement_state,
            ab_status=ab_status,
            srm_status=srm_status,
            reference_pack=reference_pack,
            model_override=model_override,
        )
    except Exception as exc:
        intent_model = (
            (model_override or DOCTOR_VARIANCE_GROQ_MODEL)
            if backend_name in {"groq", "auto"}
            else "local_backend"
        )
        return _methodology_fallback_for_experiment(
            experiment,
            reason=str(exc),
            backend_requested=backend_name,
            model_intent=intent_model,
            remote_allowed=(os.getenv("LLM_ALLOW_REMOTE", "0") == "1"),
            preflight_issue="llm_runtime_error",
            srm_status=srm_status,
        )


def _base_run_id(run_id: str) -> str:
    return re.sub(r"_s\\d+$", "", run_id)


def _validate_output_contract(payload: dict[str, Any]) -> None:
    required_top = [
        "agent_name",
        "run_id",
        "decision",
        "reasons",
        "ab_plan",
        "success_metrics",
        "guardrails",
        "blocked_metrics",
        "ab_risks",
        "layer1_verdict",
        "layer2_guardrail_verdicts",
        "alternative_hypotheses",
        "temporal_risk",
        "sensitivity_note",
        "layers_present",
        "reasoning_confidence_inputs",
        "required_human_approval",
        "next_actions",
        "contract_version",
        "metrics_contract_version",
    ]
    for key in required_top:
        if key not in payload:
            raise ValueError(f"output missing required field: {key}")
    if payload["decision"] not in {"STOP", "HOLD_NEED_DATA", "HOLD_RISK", "RUN_AB", "ROLLOUT_CANDIDATE"}:
        raise ValueError("output decision invalid")
    if not isinstance(payload["reasons"], list):
        raise ValueError("reasons must be list")
    for reason in payload["reasons"]:
        if not isinstance(reason, dict):
            raise ValueError("reason item must be object")
        for key in ["code", "severity", "message", "evidence_refs"]:
            if key not in reason:
                raise ValueError(f"reason missing {key}")
    if not isinstance(payload["ab_risks"], list):
        raise ValueError("ab_risks must be list")
    if str(payload.get("layer1_verdict", "")).strip().upper() == "":
        raise ValueError("layer1_verdict missing")
    if not isinstance(payload.get("layer2_guardrail_verdicts"), list):
        raise ValueError("layer2_guardrail_verdicts must be list")
    if not isinstance(payload.get("alternative_hypotheses"), list):
        raise ValueError("alternative_hypotheses must be list")
    if not isinstance(payload.get("layers_present"), dict):
        raise ValueError("layers_present must be object")
    if not isinstance(payload.get("reasoning_confidence_inputs"), dict):
        raise ValueError("reasoning_confidence_inputs must be object")
    for idx, risk in enumerate(payload["ab_risks"]):
        if not isinstance(risk, dict):
            raise ValueError(f"ab_risks[{idx}] must be object")
        for key in ["risk_type", "check_name", "severity", "mitigation"]:
            if key not in risk:
                raise ValueError(f"ab_risks[{idx}] missing '{key}'")
    for idx, exp in enumerate(payload.get("ab_plan", [])):
        if not isinstance(exp, dict):
            raise ValueError(f"ab_plan[{idx}] must be object")
        for key in [
            "randomization_unit",
            "analysis_unit",
            "pre_period_weeks",
            "test_period_weeks",
            "wash_in_days",
            "attribution_window_rule",
            "test_side",
        ]:
            if key not in exp:
                raise ValueError(f"ab_plan[{idx}] missing '{key}'")
        if str(exp.get("test_side", "")).strip() not in {"one-sided", "two-sided"}:
            raise ValueError(f"ab_plan[{idx}].test_side invalid")
    rec_exp = payload.get("recommended_experiment")
    if isinstance(rec_exp, dict):
        for key in [
            "randomization_unit",
            "analysis_unit",
            "pre_period_weeks",
            "test_period_weeks",
            "wash_in_days",
            "attribution_window_rule",
            "test_side",
        ]:
            if key not in rec_exp:
                raise ValueError(f"recommended_experiment missing '{key}'")

    # Prompt-contract hard checks (deterministic safety invariants).
    measurement_state = str(payload.get("measurement_state", "")).upper()
    ab_status = str(((payload.get("evidence") or {}).get("ab_status")) if isinstance(payload.get("evidence"), dict) else "").upper()
    blocked_states = {"UNOBSERVABLE", "BLOCKED_BY_DATA"}
    blocked_statuses = {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "INVALID_METHODS", "ASSIGNMENT_RECOVERED"}
    if measurement_state in blocked_states or ab_status in blocked_statuses:
        if payload.get("decision") in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
            raise ValueError("prompt-contract violation: aggressive decision under unobservable/invalid AB state")
        if not isinstance(payload.get("measurement_fix_plan"), dict):
            raise ValueError("prompt-contract violation: measurement_fix_plan required when AB is unobservable/invalid")

    portfolio = payload.get("hypothesis_portfolio", [])
    if isinstance(portfolio, list):
        # Require coverage across all template targets and template floor guardrail in each hypothesis.
        targets = {
            str(h.get("target_metric", "")).strip()
            for h in portfolio
            if isinstance(h, dict) and str(h.get("target_metric", "")).strip()
        }
        expected_targets = domain_target_metric_aliases()
        if not expected_targets:
            raise ConfigurationError("Domain template target aliases are required for portfolio validation")
        if not expected_targets.issubset(targets):
            raise ValueError("prompt-contract violation: hypothesis_portfolio must cover all template targets")
        for idx, h in enumerate(portfolio):
            if not isinstance(h, dict):
                continue
            guardrails = h.get("guardrails", {})
            if not isinstance(guardrails, dict):
                raise ValueError(f"prompt-contract violation: hypothesis_portfolio[{idx}] missing guardrails block")
            if "template_floor_guardrail_metric" not in guardrails or "template_floor_guardrail_threshold" not in guardrails:
                raise ValueError(
                    f"prompt-contract violation: hypothesis_portfolio[{idx}] missing template floor guardrail"
                )


def _validate_against_schema_file(payload: dict[str, Any], schema: dict[str, Any]) -> None:
    required_top = schema.get("required", [])
    for key in required_top:
        if key not in payload:
            raise ValueError(f"schema validation failed: missing top-level field '{key}'")

    props = schema.get("properties", {})

    decision_enum = props.get("decision", {}).get("enum")
    if isinstance(decision_enum, list) and payload.get("decision") not in decision_enum:
        raise ValueError("schema validation failed: decision enum mismatch")

    approval_enum = props.get("required_human_approval", {}).get("enum")
    if isinstance(approval_enum, list) and payload.get("required_human_approval") not in approval_enum:
        raise ValueError("schema validation failed: required_human_approval enum mismatch")

    reason_schema = props.get("reasons", {}).get("items", {})
    reason_required = reason_schema.get("required", [])
    reason_sev_enum = reason_schema.get("properties", {}).get("severity", {}).get("enum", [])
    for idx, reason in enumerate(payload.get("reasons", [])):
        for key in reason_required:
            if key not in reason:
                raise ValueError(f"schema validation failed: reasons[{idx}] missing '{key}'")
        if reason.get("severity") not in reason_sev_enum:
            raise ValueError(f"schema validation failed: reasons[{idx}].severity enum mismatch")

    risk_schema = props.get("ab_risks", {}).get("items", {})
    risk_required = risk_schema.get("required", [])
    risk_sev_enum = risk_schema.get("properties", {}).get("severity", {}).get("enum", [])
    for idx, risk in enumerate(payload.get("ab_risks", [])):
        for key in risk_required:
            if key not in risk:
                raise ValueError(f"schema validation failed: ab_risks[{idx}] missing '{key}'")
        if risk.get("severity") not in risk_sev_enum:
            raise ValueError(f"schema validation failed: ab_risks[{idx}].severity enum mismatch")

    # Optional strict validation with jsonschema if installed.
    try:
        from jsonschema import validate as _jsonschema_validate  # type: ignore
    except Exception:
        return
    _jsonschema_validate(instance=payload, schema=schema)


def _render_md(result: dict[str, Any]) -> str:
    lines = [
        f"# Doctor Variance Report: {result['run_id']}",
        "",
        f"- decision: `{result['decision']}`",
        f"- required_human_approval: `{result['required_human_approval']}`",
        "",
        "## Reasons",
        "| code | severity | message |",
        "|---|---|---|",
    ]
    for r in result.get("reasons", []):
        lines.append(f"| {r.get('code')} | {r.get('severity')} | {r.get('message')} |")

    lines.extend(["", "## AB Plan"])
    if result.get("ab_plan"):
        for exp in result["ab_plan"]:
            lines.append(
                f"- `{exp.get('name')}` ({exp.get('unit')}/{exp.get('lever_type')}): {exp.get('goal')}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Risks"])
    for risk in result.get("ab_risks", []):
        lines.append(f"- {risk}")
    if not result.get("ab_risks"):
        lines.append("- none")

    lines.extend(["", "## Next actions"])
    for action in result.get("next_actions", []):
        lines.append(f"- {action}")
    if not result.get("next_actions"):
        lines.append("- none")

    lines.extend(["", "## Human summary", result.get("human_summary_md", "")])
    lines.append("")
    return "\n".join(lines)


def _rollout_candidate_decision(candidate_metrics: dict[str, Any], control_metrics: dict[str, Any], decision: str) -> str:
    if decision != "RUN_AB":
        return decision
    try:
        primary_defaults = domain_goal_default_metrics()
        primary_metric = str(primary_defaults.get(_default_goal_id(), "")).strip()
        if not primary_metric:
            primary_metric = next(iter(sorted(READY_NOW_METRICS)), "")
        if not primary_metric:
            return decision
        c_primary = float(candidate_metrics.get(primary_metric) or 0.0)
        b_primary = float(control_metrics.get(primary_metric) or 0.0)
    except Exception:
        return decision

    if b_primary <= 0:
        return decision

    primary_uplift = (c_primary - b_primary) / b_primary
    guardrails_ok = True
    for row in _doctor_guardrails(candidate_metrics):
        metric = str(row.get("metric", "")).strip()
        op = str(row.get("op", "")).strip()
        threshold = float(row.get("threshold", 0.0) or 0.0)
        c_val = float(candidate_metrics.get(metric) or 0.0)
        b_val = float(control_metrics.get(metric) or 0.0)
        if op in {">=", ">"} and (c_val < threshold or c_val < b_val):
            guardrails_ok = False
            break
        if op in {"<=", "<"} and (c_val > threshold or c_val > b_val):
            guardrails_ok = False
            break
    if primary_uplift >= 0.02 and guardrails_ok:
        return "ROLLOUT_CANDIDATE"
    return decision


def main() -> None:
    parser = argparse.ArgumentParser(description="Doctor Variance: deterministic decision gate")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--backend", choices=["groq", "ollama", "auto"], default="auto")
    parser.add_argument("--domain-template", default="", help="Path to domain template JSON (required via arg/env)")
    parser.add_argument("--control-run-id", default=None)
    parser.add_argument("--enable-deepseek-doctor", type=int, default=1, choices=[0, 1])
    parser.add_argument("--enable-react-doctor", type=int, default=0, choices=[0, 1])
    parser.add_argument("--react-max-steps", type=int, default=4)
    parser.add_argument("--react-timeout-sec", type=int, default=25)
    args = parser.parse_args()
    set_domain_template_override(args.domain_template)

    run_id = args.run_id
    try:
        _apply_domain_template(args.domain_template)
        thresholds = _load_thresholds()
        output_schema = _load_output_schema()
        decision_contract = load_decision_contract()

        dq = _load_json(Path(f"data/dq_reports/{run_id}.json"), "dq report")
        captain = _load_json(Path(f"data/llm_reports/{run_id}_captain.json"), "captain report")
        snapshot = _load_json(Path(f"data/metrics_snapshots/{run_id}.json"), "metrics snapshot")
        historical_context_pack_path = Path(f"data/agent_context/{run_id}_historical_context_pack.json")
        historical_context_pack = load_json_optional_with_integrity(historical_context_pack_path, required=True) or {}
        historical_context_rows = (
            historical_context_pack.get("rows", [])
            if isinstance(historical_context_pack.get("rows"), list)
            else []
        )
        historical_context_pack_sha256 = ""
        historical_sidecar = sha256_sidecar_path(historical_context_pack_path)
        if historical_sidecar.exists():
            historical_context_pack_sha256 = historical_sidecar.read_text(encoding="utf-8").strip().lower()
        if str(historical_context_pack.get("status", "")).upper() != "PASS" or len(historical_context_rows) == 0:
            raise RuntimeError("HISTORICAL_CONTEXT_MISSING:historical_context_pack_not_ready_for_doctor")
        if not historical_context_pack_sha256:
            raise RuntimeError("HISTORICAL_CONTEXT_INTEGRITY_FAIL:historical_context_pack_sidecar_missing")

        paired_context_payload, paired_status = _load_paired_context_payload(run_id)
        control_snapshot = None
        control_snapshot_path = _resolve_ctrl_snapshot_path(
            run_id=run_id,
            control_run_id=str(args.control_run_id or ""),
            paired_context=paired_context_payload,
            paired_status=paired_status,
        )
        control_run_id = ""
        if isinstance(control_snapshot_path, Path):
            if control_snapshot_path.exists():
                control_snapshot = _load_json(control_snapshot_path, "control snapshot")
                control_run_id = control_snapshot_path.stem
            elif paired_status == "COMPLETE":
                raise RuntimeError(
                    "METHODOLOGY_INVARIANT_BROKEN:missing_control_snapshot_for_paired_complete"
                )
        elif paired_status == "COMPLETE":
            raise RuntimeError(
                "METHODOLOGY_INVARIANT_BROKEN:control_snapshot_ref_missing_for_paired_complete"
            )

        stat_bundle_payload: dict[str, Any] = {}
        stat_bundle_ref: str | None = None
        stat_bundle_error = ""
        stat_bundle_sha256 = ""
        bundle_path = stat_evidence_bundle_path(run_id)
        if paired_status == "COMPLETE":
            try:
                if not isinstance(control_snapshot_path, Path):
                    raise RuntimeError("control_snapshot_path_unresolved")
                bundle = compute_stat_evidence(
                    control_snapshot_path,
                    Path(f"data/metrics_snapshots/{run_id}.json"),
                    str(args.domain_template or domain_template_source()),
                    paired_status=paired_status,
                )
                stat_bundle_payload = bundle.to_dict()
                bundle_path.parent.mkdir(parents=True, exist_ok=True)
                bundle_path.write_text(json.dumps(stat_bundle_payload, ensure_ascii=False, indent=2), encoding="utf-8")
                write_sha256_sidecar(bundle_path)
                stat_bundle_sidecar = sha256_sidecar_path(bundle_path)
                if stat_bundle_sidecar.exists():
                    stat_bundle_sha256 = stat_bundle_sidecar.read_text(encoding="utf-8").strip().lower()
                stat_bundle_ref = f"artifact:{bundle_path}#"
            except Exception as exc:
                stat_bundle_error = str(exc).splitlines()[0][:240]
        else:
            # Optional load for single/partial context; no hard dependency.
            loaded_bundle = load_json_optional_with_integrity(bundle_path, required=False)
            if isinstance(loaded_bundle, dict):
                stat_bundle_payload = loaded_bundle
                stat_bundle_ref = f"artifact:{bundle_path}#"
                stat_bundle_sidecar = sha256_sidecar_path(bundle_path)
                if stat_bundle_sidecar.exists():
                    stat_bundle_sha256 = stat_bundle_sidecar.read_text(encoding="utf-8").strip().lower()

        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        run_cfg = snapshot.get("run_config", {}) if isinstance(snapshot.get("run_config"), dict) else {}
        raw_assignment_status = str(run_cfg.get("assignment_status", "missing") or "missing").strip().lower()
        assignment_status = "ready" if raw_assignment_status in {"present", "ready"} else "missing"
        experiment_id = str(run_cfg.get("experiment_id", "") or "").strip()
        ab_report_path = Path(f"data/ab_reports/{run_id}_{experiment_id}_ab.json") if experiment_id else None
        ab_report: dict[str, Any] | None = None
        ab_status = "missing"
        srm_status = "MISSING"
        if ab_report_path and ab_report_path.exists():
            try:
                ab_report = json.loads(ab_report_path.read_text(encoding="utf-8"))
                ab_status = str(ab_report.get("status", "missing")).strip().upper()
                srm_status = _extract_srm_status(ab_report)
            except Exception:
                ab_status = "invalid"
                srm_status = "MISSING"
        domain_reference = _domain_reference_pack()
        ab_summary_ctx = ab_report.get("summary", {}) if isinstance(ab_report, dict) and isinstance(ab_report.get("summary"), dict) else {}
        ab_primary_metric_ctx = str(ab_summary_ctx.get("primary_metric", "")).strip()
        best_analog_similarity = _best_similarity_from_history_rows(historical_context_rows)
        layers_present = (
            stat_bundle_payload.get("layers_present", {})
            if isinstance(stat_bundle_payload.get("layers_present"), dict)
            else {}
        )
        if not isinstance(layers_present, dict) or not layers_present:
            layers_present = {
                "layer1_live_stats": False,
                "layer2_guardrail_check": False,
                "layer3_history": True,
            }
        guardrail_data_complete = _guardrail_data_complete_from_bundle(stat_bundle_payload) if isinstance(stat_bundle_payload, dict) else False
        reasoning_confidence_inputs: dict[str, Any] = {
            "layers_present": layers_present,
            "p_value": _extract_primary_metric_pvalue(stat_bundle_payload, ab_primary_metric_ctx),
            "best_analog_similarity": best_analog_similarity,
            "guardrail_data_complete": guardrail_data_complete,
            "n_min": int(stat_bundle_payload.get("n_min_required", 0) or 0) if isinstance(stat_bundle_payload, dict) else 0,
            "srm_pass": bool(not bool(stat_bundle_payload.get("srm_flag", False))) if isinstance(stat_bundle_payload, dict) else False,
            "paired_status": paired_status,
            "stat_bundle_ref": stat_bundle_ref,
            "stat_bundle_status": str(stat_bundle_payload.get("status", "")).strip().upper() if isinstance(stat_bundle_payload, dict) else "",
            "stat_bundle_error": stat_bundle_error or None,
        }
        if experiment_id and ab_status in {"MISSING_ASSIGNMENT", "MISSING", "INVALID"}:
            assignment_status = "missing"
        plan_start = datetime.now(timezone.utc).date()
        plan_end = plan_start + timedelta(days=13)
        enable_deepseek_doctor = int(args.enable_deepseek_doctor) == 1
        enable_react_doctor = int(args.enable_react_doctor) == 1
        feature_flags = _active_feature_flags()
        reasoning_mode = "react" if enable_react_doctor else "standard"
        model_used = (
            DOCTOR_VARIANCE_DEEPSEEK_MODEL
            if enable_deepseek_doctor and args.backend in {"groq", "auto"}
            else (DOCTOR_VARIANCE_GROQ_MODEL if args.backend in {"groq", "auto"} else "local_backend")
        )
        protocol_checks: list[dict[str, Any]] = [
            {"name": "read_only_tools", "passed": True, "detail": "Doctor uses artifact reads only; no DB write/shell write tools."},
            {
                "name": "react_max_steps_range",
                "passed": (1 <= int(args.react_max_steps) <= 8),
                "detail": f"react_max_steps={args.react_max_steps}",
            },
            {
                "name": "react_timeout_range",
                "passed": (5 <= int(args.react_timeout_sec) <= 120),
                "detail": f"react_timeout_sec={args.react_timeout_sec}",
            },
        ]
        protocol_checks_passed = all(bool(x.get("passed")) for x in protocol_checks)
        reasons: list[dict[str, Any]] = []
        ab_risks: list[dict[str, Any]] = []
        next_actions: list[str] = []
        decision = "RUN_AB"
        if paired_status == "COMPLETE":
            bundle_status = str(stat_bundle_payload.get("status", "")).strip().upper() if isinstance(stat_bundle_payload, dict) else ""
            if bundle_status != "PASS":
                decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "missing_live_stat_evidence",
                        "HARD_FAIL",
                        "Paired COMPLETE run requires stat evidence bundle with PASS status for Layers 1+2.",
                        [f"artifact:{bundle_path}#"] if bundle_path else [f"artifact:data/agent_context/{run_id}_stat_evidence_bundle_v1.json#"],
                    )
                )
                if stat_bundle_error:
                    reasons.append(
                        _reason(
                            "stat_evidence_bundle_error",
                            "WARN",
                            f"Stat evidence build error: {stat_bundle_error}",
                            [f"artifact:{bundle_path}#"] if bundle_path else [],
                        )
                    )

        captain_decision, captain_reasons, captain_risks = _captain_checks(captain, run_id)
        reasons.extend(captain_reasons)
        ab_risks.extend(captain_risks)
        if captain_decision == "STOP":
            decision = "STOP"
        template_policy_decision, template_policy_hits = _enforce_template_captain_issue_policies(captain)
        if template_policy_hits:
            for hit in template_policy_hits:
                ab_risks.append(
                    {
                        "risk_type": hit.get("risk_type", "template_policy"),
                        "check_name": hit["check_name"],
                        "severity": "WARN" if hit["severity"] != "HARD_FAIL" else "HARD_FAIL",
                        "mitigation": hit.get("mitigation") or "Apply template-defined mitigation before new experiments.",
                    }
                )
        merged_policy_decision = _merge_gate_decision(decision, template_policy_decision)
        if merged_policy_decision:
            decision = merged_policy_decision

        missing_required = _required_metrics_missing(metrics)
        if decision != "STOP" and missing_required:
            decision = "HOLD_NEED_DATA"
            reasons.append(
                _reason(
                    "missing_required_metrics",
                    "HARD_FAIL",
                    f"Missing required READY_NOW metrics: {','.join(missing_required)}",
                    [f"artifact:data/metrics_snapshots/{run_id}.json#/metrics"],
                )
            )
            next_actions.append("Regenerate metrics snapshot and verify metrics_contract_v1 mapping")

        if decision != "STOP" and not missing_required:
            guardrail_decision, guardrail_reasons = _guardrail_checks(metrics, run_id, thresholds)
            reasons.extend(guardrail_reasons)
            if guardrail_decision == "STOP":
                decision = "STOP"
            elif guardrail_decision == "HOLD_RISK" and decision != "HOLD_NEED_DATA":
                decision = "HOLD_RISK"
                ab_risks.append(
                    {
                        "risk_type": "guardrail",
                        "check_name": "guardrails_at_risk",
                        "severity": "WARN",
                        "mitigation": "Stabilize service/economics before launching new AB",
                    }
                )

        if decision not in {"STOP", "HOLD_NEED_DATA"}:
            volume_ok, details = _volume_gate(metrics, run_id, thresholds)
            if not volume_ok:
                decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "volume_gate_fail",
                        "WARN",
                        (
                            "Volume gate failed: "
                            f"{details.get('evaluations', [])}"
                        ),
                        [details["ref"]],
                    )
                )
                next_actions.extend([
                    "Increase horizon_days (for example, 14)",
                    "Increase customer pool and rerun baseline",
                ])

        # Hard gate: if experiment is requested, assignment + AB evidence must exist.
        if decision != "STOP" and experiment_id:
            if assignment_status != "ready":
                decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "missing_assignment_log",
                        "HARD_FAIL",
                        "Experiment requested but assignment log is missing/empty",
                        [f"artifact:data/metrics_snapshots/{run_id}.json#/run_config/assignment_status"],
                    )
                )
            if ab_status in {"missing", "invalid"}:
                decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "missing_ab_report",
                        "HARD_FAIL",
                        "Experiment requested but ab_report artifact is missing/invalid",
                        [f"artifact:data/ab_reports/{run_id}_{experiment_id}_ab.json"],
                    )
                )
            elif ab_status == "MISSING_ASSIGNMENT":
                decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "missing_assignment_log",
                        "HARD_FAIL",
                        "AB report indicates assignment is missing",
                        [f"artifact:data/ab_reports/{run_id}_{experiment_id}_ab.json#/status"],
                    )
                )

        if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and srm_status in {"WARN", "FAIL"}:
            decision = "HOLD_NEED_DATA" if srm_status == "FAIL" else "HOLD_RISK"
            reasons.append(
                _reason(
                    "srm_preflight_failed",
                    "HARD_FAIL" if srm_status == "FAIL" else "WARN",
                    f"SRM preflight is {srm_status}; statistical inference is unsafe until allocation health is fixed.",
                    [f"artifact:data/ab_reports/{run_id}_{experiment_id}_ab.json#/summary/srm_status"] if experiment_id else [],
                )
            )
            ab_risks.append(
                {
                    "risk_type": "sampling",
                    "check_name": "srm_preflight_failed",
                    "severity": "HARD_FAIL" if srm_status == "FAIL" else "WARN",
                    "mitigation": "Audit assignment split, verify randomization key/salt, rerun AB after SRM PASS.",
                }
            )
            next_actions.extend(
                [
                    "Run SRM split diagnostics on assignment log before any new inference.",
                    "Rebuild assignment if imbalance is caused by join/filter or hash-salt drift.",
                ]
            )

        # Effect evaluation must use ab_report evidence; no text-only effect claims.
        if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and assignment_status == "ready" and experiment_id:
            if ab_status in {"missing", "invalid"}:
                decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "missing_ab_report",
                        "HARD_FAIL",
                        "AB effect evaluation requires ab_report artifact",
                        [f"artifact:data/ab_reports/{run_id}_{experiment_id}_ab.json"],
                    )
                )
            elif ab_status == "MISSING_ASSIGNMENT":
                decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "missing_assignment_log",
                        "HARD_FAIL",
                        "AB report indicates assignment log is missing",
                        [f"artifact:data/ab_reports/{run_id}_{experiment_id}_ab.json#/status"],
                    )
                )
            elif ab_status == "UNDERPOWERED":
                decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "ab_underpowered",
                        "WARN",
                        "AB report is underpowered; extend experiment window",
                        [f"artifact:data/ab_reports/{run_id}_{experiment_id}_ab.json#/status"],
                    )
                )
            elif ab_status == "INCONCLUSIVE":
                decision = "HOLD_RISK"
                reasons.append(
                    _reason(
                        "ab_inconclusive",
                        "WARN",
                        "AB confidence interval crosses zero",
                        [f"artifact:data/ab_reports/{run_id}_{experiment_id}_ab.json#/summary/primary_metric_uplift_ci95"],
                    )
                )
            # Methodology must be evidence-backed when recommending RUN_AB on observable setup.
            if ab_report and isinstance(ab_report, dict):
                ab_summary = ab_report.get("summary", {}) if isinstance(ab_report.get("summary"), dict) else {}
                sample_c = int(ab_summary.get("sample_size_control") or 0)
                sample_t = int(ab_summary.get("sample_size_treat") or 0)
                has_ci = ab_summary.get("primary_metric_uplift_ci95") is not None
                observable = ab_status.upper() in {"OK", "UNDERPOWERED", "INCONCLUSIVE"}
                if observable and decision in {"RUN_AB", "ROLLOUT_CANDIDATE"} and (sample_c <= 0 or sample_t <= 0 or (not has_ci and ab_status.upper() != "UNDERPOWERED")):
                    decision = "HOLD_NEED_DATA"
                    reasons.append(
                        _reason(
                            "blocked_by_data",
                            "HARD_FAIL",
                            "Observable AB recommendation requires sample sizes and CI/underpowered evidence.",
                            [f"artifact:data/ab_reports/{run_id}_{experiment_id}_ab.json#/summary"],
                        )
                    )

        ab_plan: list[dict[str, Any]] = []
        if decision == "RUN_AB":
            if assignment_status != "ready":
                decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "missing_assignment_log",
                        "HARD_FAIL",
                        "Assignment log missing; cannot run AB decision gate safely",
                        [f"artifact:data/metrics_snapshots/{run_id}.json#/run_config/assignment_status"],
                    )
                )
                ab_risks.append(
                    {
                        "risk_type": "assignment",
                        "check_name": "missing_assignment_log",
                        "severity": "HARD_FAIL",
                        "mitigation": "Run simulation with --experiment-id to write assignment log",
                    }
                )
            else:
                ab_plan = _propose_experiments(metrics, plan_start, plan_end)
                ab_plan = [_with_hypothesis_contract(exp, run_id, run_cfg) for exp in ab_plan]
                variance_issue = None
                enriched_plan: list[dict[str, Any]] = []
                for exp in ab_plan:
                    exp2, issue = _attach_methodology_requirements(exp, metrics)
                    enriched_plan.append(exp2)
                    if issue and variance_issue is None:
                        variance_issue = issue
                ab_plan = enriched_plan
                if variance_issue is not None:
                    decision = "HOLD_NEED_DATA"
                    reasons.append(
                        _reason(
                            "missing_variance_estimate",
                            "HARD_FAIL",
                            "Cannot estimate sample size; baseline variance estimate missing",
                            [f"artifact:data/metrics_snapshots/{run_id}.json#/metrics"],
                        )
                    )
                ab_plan, blocked = _phase_gate(ab_plan)
                run_cfg_decision, run_cfg_reasons, run_cfg_risks = _enforce_template_run_config_rules(run_cfg, run_id)
                reasons.extend(run_cfg_reasons)
                ab_risks.extend(run_cfg_risks)
                merged_run_cfg_decision = _merge_gate_decision(decision, run_cfg_decision)
                if merged_run_cfg_decision:
                    decision = merged_run_cfg_decision
                for exp in ab_plan:
                    primary_metric = _resolve_experiment_primary_metric(exp)
                    signal_alias = domain_signal_metric_to_target_metric().get(str(primary_metric).strip().lower(), "")
                    if _target_metric_expected_direction(signal_alias) != "decrease":
                        continue
                    if metrics.get(primary_metric) is None:
                        decision = "HOLD_NEED_DATA"
                        reasons.append(
                            _reason(
                                "missing_decrease_target_metric",
                                "HARD_FAIL",
                                f"Decreasing-target experiment requires '{primary_metric}' in snapshot",
                                [f"artifact:data/metrics_snapshots/{run_id}.json#/metrics"],
                            )
                        )
                if blocked:
                    for name in blocked:
                        ab_risks.append(
                            {
                                "risk_type": "phase_gate",
                                "check_name": name,
                                "severity": "WARN",
                                "mitigation": "Do not run blocked phase experiments before required data is ready",
                            }
                        )

                if thresholds.get("mvp_mode_one_experiment", True) and len(ab_plan) > 1:
                    ab_plan = sorted(
                        ab_plan,
                        key=lambda e: float(e.get("ice_score", 0.0)),
                        reverse=True,
                    )[:1]
                    ab_risks.append(
                        {
                            "risk_type": "policy",
                            "check_name": "mvp_mode_one_experiment_applied",
                            "severity": "INFO",
                            "mitigation": "Run one experiment per run in MVP mode",
                        }
                    )

                experiments_registry = Path("data/agent_reports/active_experiments.json")
                active_experiments = _load_active_experiments()
                if not experiments_registry.exists():
                    reasons.append(
                        _reason(
                            "registry_missing_interference_time_check_skipped",
                            "WARN",
                            "Active experiments registry missing; time-based interference check skipped",
                            ["artifact:data/agent_reports/active_experiments.json#/experiments"],
                        )
                    )
                    ab_risks.append(
                        {
                            "risk_type": "interference",
                            "check_name": "registry_missing",
                            "severity": "WARN",
                            "mitigation": "Create active experiments registry before parallel AB planning",
                        }
                    )
                else:
                    interference = _interference_risks(ab_plan, active_experiments)
                    if interference:
                        decision = "HOLD_RISK"
                        ab_risks.extend(interference)
                        reasons.append(
                            _reason(
                                "interference_risk",
                                "WARN",
                                "Planned experiment overlaps with active experiment scope/lever/time window",
                                ["artifact:data/agent_reports/active_experiments.json#/experiments"],
                            )
                        )

                contract_issues = _validate_experiment_contract(ab_plan)
                if contract_issues:
                    decision = "HOLD_NEED_DATA"
                    for issue in contract_issues:
                        ab_risks.append(
                            {
                                "risk_type": "contract",
                                "check_name": issue,
                                "severity": "WARN",
                                "mitigation": "Fix experiment payload fields to match contract",
                            }
                        )
                    if any("missing_hypothesis" in issue or "bad_hypothesis_format" in issue for issue in contract_issues):
                        reasons.append(
                            _reason(
                                "missing_hypothesis",
                                "HARD_FAIL",
                                "Doctor experiment lacks valid human-readable hypothesis contract",
                                [f"artifact:data/agent_reports/{run_id}_doctor_variance.json#/ab_plan"],
                            )
                        )
                    reasons.append(
                        _reason(
                            "experiment_contract_invalid",
                            "HARD_FAIL",
                            "Generated AB plan violates experiment contract",
                            [f"artifact:data/agent_reports/{run_id}_doctor_variance.json#/ab_plan"],
                        )
                    )

        if (
            control_snapshot
            and isinstance(control_snapshot.get("metrics"), dict)
            and ab_status == "OK"
        ):
            decision = _rollout_candidate_decision(metrics, control_snapshot["metrics"], decision)

        success_metrics = sorted({m for e in ab_plan for m in e.get("success_metrics", [])})
        guardrails = sorted({m for e in ab_plan for m in e.get("guardrails", [])})
        try:
            synthetic_bias = json.loads(
                Path(f"data/realism_reports/{run_id}_synthetic_bias.json").read_text(encoding="utf-8")
            )
            if not isinstance(synthetic_bias, dict):
                synthetic_bias = {}
        except Exception:
            synthetic_bias = {}
        dynamic_hypotheses_enabled = bool(feature_flags.get("DOCTOR_DYNAMIC_HYPOTHESES", 0))
        hypothesis_portfolio, hypothesis_generation_mode, hypothesis_generation_provenance = _build_hypothesis_portfolio_with_mode(
            run_id=run_id,
            metrics=metrics,
            captain=captain,
            synthetic_bias=synthetic_bias,
            dynamic_enabled=dynamic_hypotheses_enabled,
            backend_name=args.backend,
            output_schema=output_schema,
            model_override=(DOCTOR_VARIANCE_DEEPSEEK_MODEL if enable_deepseek_doctor else DOCTOR_VARIANCE_GROQ_MODEL),
        )
        unique_hyp_ids = {str(h.get("hypothesis_id", "")).strip() for h in hypothesis_portfolio if str(h.get("hypothesis_id", "")).strip()}
        unique_levers = {str(h.get("lever_type", "")).strip() for h in hypothesis_portfolio if str(h.get("lever_type", "")).strip()}
        unique_targets = {str(h.get("target_metric", "")).strip() for h in hypothesis_portfolio if str(h.get("target_metric", "")).strip()}
        portfolio_diversity_score = round(min(1.0, len(unique_levers) / 3.0), 4)

        if len(hypothesis_portfolio) < 3 or len(unique_hyp_ids) < 2 or len(unique_levers) < 2 or len(unique_targets) < 2:
            if decision != "STOP":
                decision = "HOLD_NEED_DATA"
            reasons.append(
                _reason(
                    "portfolio_not_diverse",
                    "WARN",
                    "Doctor hypothesis portfolio is insufficient (count/diversity/uniqueness/target diversity).",
                    [f"artifact:data/agent_reports/{run_id}_doctor_variance.json#/hypothesis_portfolio"],
                )
            )
        top_h = hypothesis_portfolio[0] if hypothesis_portfolio and isinstance(hypothesis_portfolio[0], dict) else {}
        top_refs = top_h.get("evidence_refs", []) if isinstance(top_h.get("evidence_refs"), list) else []
        top_has_action_evidence = any(
            isinstance(ref, dict) and str(ref.get("source", "")).strip().lower() in {"decision_trace", "commander", "synthetic_bias", "governance"}
            for ref in top_refs
        )
        if not top_has_action_evidence:
            if decision != "STOP":
                decision = "HOLD_NEED_DATA"
            reasons.append(
                _reason(
                    "missing_action_evidence",
                    "WARN",
                    "Top-ranked hypothesis is missing action/log evidence reference.",
                    [f"artifact:data/agent_reports/{run_id}_doctor_variance.json#/hypothesis_portfolio/0/evidence_refs"],
                )
            )
        if _target_metric_expected_direction(str(top_h.get("target_metric", "")).strip()) == "decrease":
            ag = top_h.get("anti_gaming_check", {}) if isinstance(top_h.get("anti_gaming_check"), dict) else {}
            if bool(ag.get("starvation_risk", False)):
                if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                    decision = "HOLD_RISK"
                reasons.append(
                    _reason(
                        "anti_goodhart_starvation",
                        "WARN",
                        "Decreasing-target plan rejected because guardrail starvation risk is detected.",
                        [f"artifact:data/metrics_snapshots/{run_id}.json#/metrics"],
                    )
                )

        if not ab_plan and decision == "RUN_AB":
            decision = "HOLD_NEED_DATA"
            reasons.append(
                _reason(
                    "empty_ab_plan",
                    "WARN",
                    "No eligible experiments after phase/interference checks",
                    [f"artifact:data/metrics_snapshots/{run_id}.json#/metrics"],
                )
            )

        recommended_experiment: dict[str, Any] | None = None
        measurement_fix_plan: dict[str, Any] | None = None
        measurement_state = "BLOCKED_BY_DATA"
        measurement_state_reason = "missing_experiment_context"
        ab_status_upper = str(ab_status or "").upper()
        assignment_ready = assignment_status == "ready"
        if experiment_id:
            if ab_status_upper in {"OK", "UNDERPOWERED", "INCONCLUSIVE"}:
                measurement_state = "OBSERVABLE"
                measurement_state_reason = "ab_status_observable"
            elif ab_status_upper in {"MISSING_ASSIGNMENT", "METHODOLOGY_MISMATCH", "INVALID", "ASSIGNMENT_RECOVERED"}:
                measurement_state = "UNOBSERVABLE"
                measurement_state_reason = "ab_status_unobservable"
            elif ab_status_upper in {"", "MISSING"}:
                measurement_state = "BLOCKED_BY_DATA"
                measurement_state_reason = "ab_report_missing"
            elif not assignment_ready:
                measurement_state = "UNOBSERVABLE"
                measurement_state_reason = "assignment_missing"

        if srm_status in {"WARN", "FAIL"}:
            measurement_fix_plan = {
                "missing": ["srm_pass_required"],
                "required_design_fields": [
                    "randomization_unit",
                    "analysis_unit",
                    "assignment_hash_salt",
                    "sample_ratio_target",
                ],
                "minimal_steps": [
                    "Audit assignment logs by arm and verify deterministic hash + salt is stable.",
                    "Check join/filter leakage between assignment and fact tables for the same experiment window.",
                    "Re-run AB only after SRM_check = PASS and publish refreshed AB artifact.",
                ],
                "verification_checks": [
                    "srm_status == PASS",
                    "observed_treatment_share within expected tolerance",
                    "assignment coverage > 0 for both arms",
                ],
                "expected_fix_impact": "Restores valid randomization assumptions and prevents biased uplift estimates.",
            }

        # ReAct protocol safety ceiling: never allow aggressive decision when measurement is unobservable.
        if enable_react_doctor and measurement_state in {"UNOBSERVABLE", "BLOCKED_BY_DATA"}:
            if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                decision = "HOLD_RISK"
            reasons.append(
                _reason(
                    "react_protocol_measurement_ceiling",
                    "WARN",
                    "ReAct protocol forces safe ceiling when measurement is unobservable/blocked.",
                    [f"artifact:data/metrics_snapshots/{run_id}.json#/run_config"],
                )
                )

        # Architectural fix: methodology selection belongs to Doctor (LLM proposal + deterministic validation),
        # not to downstream report-only metric mapping.
        methodology_selection_summary: dict[str, Any] | None = None
        ab_interpretation_methodology: dict[str, Any] | None = None
        if ab_plan:
            enriched_ab_plan: list[dict[str, Any]] = []
            for idx, exp in enumerate(ab_plan):
                if not isinstance(exp, dict):
                    continue
                exp_copy = dict(exp)
                method_choice = _select_statistical_methodology_for_experiment(
                    backend_name=args.backend,
                    run_id=run_id,
                    experiment=exp_copy,
                    metrics=metrics,
                    measurement_state=measurement_state,
                    ab_status=ab_status_upper or "MISSING",
                    srm_status=srm_status,
                    reference_pack=domain_reference,
                    model_override=(DOCTOR_VARIANCE_DEEPSEEK_MODEL if enable_deepseek_doctor else DOCTOR_VARIANCE_GROQ_MODEL),
                )
                exp_copy["statistical_methodology"] = method_choice
                enriched_ab_plan.append(exp_copy)
                if idx == 0:
                    methodology_selection_summary = {
                        "selection_provenance": (
                            method_choice.get("selection_provenance") if isinstance(method_choice, dict) and isinstance(method_choice.get("selection_provenance"), dict) else {}
                        ),
                        "selected_by": ((method_choice.get("selection_provenance") or {}).get("selected_by") if isinstance(method_choice, dict) else None),
                        "selection_mode": ((method_choice.get("selection_provenance") or {}).get("selection_mode") if isinstance(method_choice, dict) else None),
                        "test_family": method_choice.get("test_family") if isinstance(method_choice, dict) else None,
                        "statistical_principle": method_choice.get("statistical_principle") if isinstance(method_choice, dict) else None,
                        "reason_selected": method_choice.get("reason_selected") if isinstance(method_choice, dict) else None,
                        "fallback_reason": ((method_choice.get("selection_provenance") or {}).get("fallback_reason") if isinstance(method_choice, dict) else None),
                    }
            ab_plan = enriched_ab_plan

        if isinstance(ab_report, dict):
            ab_summary = ab_report.get("summary", {}) if isinstance(ab_report.get("summary"), dict) else {}
            ab_metric = str(ab_summary.get("primary_metric", "")).strip()
            ab_unit = str(ab_report.get("unit_type", run_cfg.get("experiment_unit", "unknown")) or "unknown").strip().lower()
            if ab_metric:
                interp_exp = {
                    "name": f"{experiment_id or 'current_ab'}_interpretation",
                    "goal": "current_ab_interpretation",
                    "unit": ab_unit,
                    "north_star_metric": ab_metric,
                    "hypotheses": [],
                }
                ab_interpretation_methodology = _select_statistical_methodology_for_experiment(
                    backend_name=args.backend,
                    run_id=run_id,
                    experiment=interp_exp,
                    metrics=metrics,
                    measurement_state=measurement_state,
                    ab_status=ab_status_upper or "MISSING",
                    srm_status=srm_status,
                    reference_pack=domain_reference,
                    model_override=(DOCTOR_VARIANCE_DEEPSEEK_MODEL if enable_deepseek_doctor else DOCTOR_VARIANCE_GROQ_MODEL),
                )
                if isinstance(ab_interpretation_methodology, dict):
                    ab_interpretation_methodology["context_scope"] = "current_ab_interpretation"

        if enable_react_doctor and not protocol_checks_passed:
            decision = "HOLD_RISK"
            reasons.append(
                _reason(
                    "react_protocol_invalid",
                    "HARD_FAIL",
                    "ReAct protocol configuration failed safety checks.",
                    [f"artifact:data/agent_reports/{run_id}_doctor_variance.json#/protocol_checks"],
                )
            )

        if assignment_ready and experiment_id and measurement_state == "OBSERVABLE":
            best = max(hypothesis_portfolio, key=lambda x: float(x.get("ice_score", 0.0))) if hypothesis_portfolio else None
            if isinstance(best, dict):
                sample_required = 0
                if isinstance(first_exp := (ab_plan[0] if ab_plan and isinstance(ab_plan[0], dict) else {}), dict):
                    sample_required = int(first_exp.get("min_sample_size", 0) or 0)
                stat_choice = first_exp.get("statistical_methodology", {}) if isinstance(first_exp.get("statistical_methodology"), dict) else {}
                analysis_method = "blocked_by_data"
                power_assumptions: dict[str, Any] | str = "BLOCKED_BY_DATA"
                if isinstance(ab_report, dict):
                    status_upper = str(ab_report.get("status", "")).upper()
                    if status_upper == "UNDERPOWERED":
                        analysis_method = str(stat_choice.get("executor_method", "") or "bootstrap_ci")
                        power_assumptions = "BLOCKED_BY_DATA"
                    elif status_upper in {"OK", "INCONCLUSIVE"}:
                        analysis_method = str(stat_choice.get("executor_method", "") or "bootstrap_ci")
                        power_assumptions = {
                            "alpha": float(stat_choice.get("alpha", 0.05) or 0.05),
                            "power": float(stat_choice.get("power_target", 0.8) or 0.8),
                            "mde": 0.02,
                        }
                design_defaults = _default_design_fields(first_exp, run_cfg)
                pre_period_weeks = first_exp.get("pre_period_weeks")
                if pre_period_weeks is None:
                    pre_period_weeks = design_defaults["pre_period_weeks"]
                test_period_weeks = first_exp.get("test_period_weeks")
                if test_period_weeks is None:
                    test_period_weeks = design_defaults["test_period_weeks"]
                wash_in_days = first_exp.get("wash_in_days")
                if wash_in_days is None:
                    wash_in_days = design_defaults["wash_in_days"]
                attribution_window_rule = str(first_exp.get("attribution_window_rule") or "").strip() or str(
                    design_defaults["attribution_window_rule"]
                )
                test_side = str(first_exp.get("test_side") or "").strip().lower() or str(design_defaults["test_side"])
                if test_side not in {"one-sided", "two-sided"}:
                    test_side = str(design_defaults["test_side"])
                randomization_unit = str(
                    first_exp.get("randomization_unit")
                    or first_exp.get("unit")
                    or best.get("unit", "customer")
                    or design_defaults["randomization_unit"]
                ).strip().lower()
                analysis_unit = str(
                    first_exp.get("analysis_unit")
                    or first_exp.get("unit")
                    or best.get("unit", "customer")
                    or design_defaults["analysis_unit"]
                ).strip().lower()
                recommended_experiment = {
                    "experiment_id": experiment_id,
                    "hypothesis_id": best.get("hypothesis_id"),
                    "unit": best.get("unit", "customer"),
                    "randomization_unit": randomization_unit,
                    "analysis_unit": analysis_unit,
                    "treat_pct": 50,
                    "duration_days": 14,
                    "pre_period_weeks": int(pre_period_weeks),
                    "test_period_weeks": int(test_period_weeks),
                    "wash_in_days": int(wash_in_days),
                    "attribution_window_rule": attribution_window_rule,
                    "test_side": test_side,
                    "primary_metric": (
                        _target_metric_to_primary_metric(str(best.get("target_metric", "")))
                        or str(first_exp.get("north_star_metric", "")).strip()
                        or _goal_to_default_metric(str(first_exp.get("goal", "")))
                    ),
                    "expected_direction": best.get("expected_direction", "increase"),
                    "guardrails": best.get("guardrails", {}),
                    "sample_size_required": sample_required,
                    "analysis_method": analysis_method,
                    "power_assumptions": power_assumptions,
                    "statistical_methodology": stat_choice or None,
                    "success_criteria": {
                        "primary_metric_delta_min": 0.02,
                        "confidence_min": 0.8,
                    },
                    "stop_conditions": [
                        (
                            f"{str(gr.get('metric', '')).strip()}_below_threshold"
                            if str(gr.get("op", "")).strip() in {">", ">="}
                            else f"{str(gr.get('metric', '')).strip()}_above_threshold"
                        )
                        for gr in _doctor_guardrails(metrics)[:4]
                        if str(gr.get("metric", "")).strip()
                    ],
                }
        else:
            missing = []
            if not assignment_ready:
                missing.append("assignment_missing")
            if not experiment_id:
                missing.append("experiment_id_missing")
            if not ab_status:
                missing.append("ab_report_missing")
            measurement_fix_plan = {
                "missing": missing,
                "required_design_fields": [
                    "pre_period_weeks",
                    "test_period_weeks",
                    "wash_in_days",
                    "attribution_window_rule",
                    "test_side",
                    "randomization_unit",
                    "analysis_unit",
                ],
                "minimal_steps": [
                    "Ensure deterministic assignment log is present for run/experiment.",
                    "Ensure AB report exists with observable status and metric deltas.",
                    "Ensure join path supports experiment unit without fallback mismatch.",
                    "Define pre-period, wash-in, and attribution window before next AB interpretation.",
                ],
                "verification_checks": [
                    "ab_status in {OK, UNDERPOWERED, INCONCLUSIVE}",
                    "assignment join coverage > 0 for experiment unit",
                    "primary metric has control/treatment rows",
                ],
                "expected_fix_impact": "Restores observable uplift/CI and enables valid evaluator decisions.",
            }

        doctor_context_path = _write_doctor_context(
            run_id,
            snapshot,
            dq,
            captain,
            synthetic_bias,
            experiment_id=experiment_id,
            assignment_status=assignment_status,
            measurement_state=measurement_state,
            ab_status=ab_status_upper or "MISSING",
            ab_report=ab_report,
            paired_status=paired_status,
            layers_present=layers_present,
            reasoning_confidence_inputs=reasoning_confidence_inputs,
            stat_bundle_ref=stat_bundle_ref,
        )

        ensemble_path = Path(f"data/ensemble_reports/{_base_run_id(run_id)}_ensemble.json")
        if ensemble_path.exists():
            try:
                ensemble_payload = json.loads(ensemble_path.read_text(encoding="utf-8"))
                if bool(ensemble_payload.get("stability_pass", True)) is False and decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                    decision = "HOLD_RISK"
                    reasons.append(
                        _reason(
                            "ensemble_stability_fail",
                            "WARN",
                            "Ensemble stability failed across seeds",
                            [f"artifact:{ensemble_path}#/stability_pass"],
                        )
                    )
                    ab_risks.append(
                        {
                            "risk_type": "stability",
                            "check_name": "ensemble_stability_fail",
                            "severity": "WARN",
                            "mitigation": "Investigate variance and recalibrate before rollout",
                        }
                    )
            except Exception:
                reasons.append(
                    _reason(
                        "ensemble_summary_unreadable",
                        "WARN",
                        "Ensemble summary exists but could not be parsed",
                        [f"artifact:{ensemble_path}"],
                    )
                )
        else:
            reasons.append(
                _reason(
                    "ensemble_summary_missing",
                    "INFO",
                    "No ensemble summary found for this base run id",
                    [f"artifact:data/ensemble_reports/{_base_run_id(run_id)}_ensemble.json"],
                )
            )

        if not reasons:
            reasons.append(
                _reason(
                    "run_ab_ready",
                    "INFO",
                    "All deterministic gates passed",
                    [f"artifact:data/metrics_snapshots/{run_id}.json#/metrics"],
                )
            )

        payload_for_llm = {
            "run_id": run_id,
            "decision": decision,
            "reasons": reasons,
            "ab_plan": ab_plan,
            "ab_risks": ab_risks,
            "next_actions": next_actions,
            "live_experiment_evidence": {
                "layers_present": layers_present,
                "reasoning_confidence_inputs": reasoning_confidence_inputs,
                "stat_evidence_bundle_ref": stat_bundle_ref,
                "stat_evidence_bundle": stat_bundle_payload,
            },
            "historical_context_pack": historical_context_rows[:5],
        }
        exploratory_ideas = [
            "Test store-level assortment nudge for high-variance categories.",
            "Evaluate markdown ladder timing under fixed availability guardrails.",
            "Probe segment-specific bundle elasticity with strict AB assignment.",
            "Run replenishment leadtime stress test with unchanged pricing levers.",
            "Compare flagged-run mode vs baseline mode under the same assignment contract.",
        ][:5]
        human_summary, human_summary_llm_provenance = _optional_llm_summary(
            args.backend,
            payload_for_llm,
            run_id,
            model_override=(DOCTOR_VARIANCE_DEEPSEEK_MODEL if enable_deepseek_doctor else DOCTOR_VARIANCE_GROQ_MODEL),
        )
        first_exp = ab_plan[0] if ab_plan and isinstance(ab_plan[0], dict) else {}
        hypotheses = first_exp.get("hypotheses", []) if isinstance(first_exp.get("hypotheses"), list) else []
        methodology_present = bool(str(first_exp.get("methodology", "")).strip())
        hypothesis_statement = str((hypotheses[0].get("hypothesis_statement", "") if hypotheses and isinstance(hypotheses[0], dict) else "")).strip()
        hypothesis_valid = bool(
            hypotheses
            and isinstance(hypotheses[0], dict)
            and hypothesis_statement
        )
        hypothesis_format_valid = hypothesis_format_ok(hypothesis_statement)
        required_sample_size_present = bool(first_exp.get("methodology_detail"))
        evidence_fields_present = bool(
            float(first_exp.get("mde", 0) or 0) > 0
            and float(first_exp.get("confidence_level", 0) or 0) > 0
            and int(first_exp.get("min_sample_size", 0) or 0) > 0
        )
        doctor_semantic_score = round(
            (
                (1.0 if hypothesis_format_valid else 0.0)
                + (1.0 if methodology_present else 0.0)
                + (1.0 if evidence_fields_present else 0.0)
            )
            / 3.0,
            4,
        )
        visible_reasoning_trace, trace_meta = build_visible_reasoning_trace_advisory(
            enabled=bool(feature_flags.get("ENABLE_VISIBLE_REASONING_TRACE", 0)),
            trace_builder=lambda: _build_doctor_visible_reasoning_trace(
                run_id=run_id,
                decision=decision,
                reasons=reasons,
                protocol_checks=protocol_checks,
                measurement_state=measurement_state,
                ab_status=ab_status,
                measurement_fix_plan=measurement_fix_plan,
                enabled=True,
            ),
            trace_prefix=f"doctor:{run_id}",
            redact_text=_redact_text,
        )
        model_used = (
            str((hypothesis_generation_provenance or {}).get("model", "")).strip()
            or str((human_summary_llm_provenance or {}).get("model", "")).strip()
            or str(model_used).strip()
        )
        provisional_local_fallback = bool(
            bool((hypothesis_generation_provenance or {}).get("needs_cloud_reconciliation", False))
            or bool((human_summary_llm_provenance or {}).get("needs_cloud_reconciliation", False))
        )
        fallback_reason_final = (
            str((hypothesis_generation_provenance or {}).get("fallback_reason", "")).strip()
            or str((human_summary_llm_provenance or {}).get("fallback_reason", "")).strip()
            or None
        )
        fallback_tier_final = (
            str((hypothesis_generation_provenance or {}).get("fallback_tier", "")).strip()
            or str((human_summary_llm_provenance or {}).get("fallback_tier", "")).strip()
            or ("deterministic" if provisional_local_fallback else "none")
        )
        stat_bundle_status = str(stat_bundle_payload.get("status", "")).strip().upper() if isinstance(stat_bundle_payload, dict) else ""
        if paired_status == "COMPLETE":
            live_ready = bool(layers_present.get("layer1_live_stats", False)) and bool(layers_present.get("layer2_guardrail_check", False))
            if stat_bundle_status != "PASS" or not live_ready:
                if decision in {"RUN_AB", "ROLLOUT_CANDIDATE"}:
                    decision = "HOLD_NEED_DATA"
                reasons.append(
                    _reason(
                        "paired_complete_requires_live_layers",
                        "HARD_FAIL",
                        "paired_status=COMPLETE requires Layer1+Layer2 stat evidence before aggressive decision.",
                        [f"artifact:{bundle_path}#"],
                    )
                )
        stat_metrics_rows = stat_bundle_payload.get("metrics", []) if isinstance(stat_bundle_payload.get("metrics"), list) else []
        stat_primary_metric = ab_primary_metric_ctx or _goal_to_default_metric(_default_goal_id())
        layer1_row = None
        for row in stat_metrics_rows:
            if isinstance(row, dict) and str(row.get("metric_id", "")).strip() == str(stat_primary_metric).strip():
                layer1_row = row
                break
        if layer1_row is None and stat_metrics_rows and isinstance(stat_metrics_rows[0], dict):
            layer1_row = stat_metrics_rows[0]
        layer1_verdict = str((layer1_row or {}).get("verdict", "NO_DATA")).strip().upper()
        layer2_guardrail_verdicts = (
            stat_bundle_payload.get("guardrail_status_check", [])
            if isinstance(stat_bundle_payload.get("guardrail_status_check"), list)
            else []
        )
        alt_hypotheses: list[str] = []
        for hyp in hypothesis_portfolio[1:4]:
            if not isinstance(hyp, dict):
                continue
            txt = str(hyp.get("mechanism", "")).strip() or str(hyp.get("hypothesis_statement", "")).strip()
            if txt:
                alt_hypotheses.append(txt[:220])
        temporal_risk = (
            "high_temporal_risk"
            if measurement_state in {"UNOBSERVABLE", "BLOCKED_BY_DATA"} or srm_status in {"WARN", "FAIL"}
            else "temporal_risk_controlled"
        )
        sensitivity_note = (
            "Layer-1/2 evidence incomplete; keep conservative ceiling and re-run after more data."
            if layer1_verdict in {"UNDERPOWERED", "NO_DATA", "INCONCLUSIVE"} or not guardrail_data_complete
            else "Layer-1/2 evidence present with guardrail checks; sensitivity acceptable under current assumptions."
        )

        out = {
            "agent_name": "Doctor Variance",
            "generated_by": "scripts/run_doctor_variance.py",
            "schema_version": "doctor_variance_output_schema.v1",
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "domain_template_path": domain_template_source(),
            "contract_version": OUTPUT_CONTRACT_VERSION,
            "decision_contract_version": str(decision_contract.get("version", "decision_contract_v1")),
            "metrics_contract_version": METRICS_CONTRACT_VERSION,
            "decision": decision,
            "normalized_decision": decision,
            "reasons": reasons,
            "ab_plan": ab_plan,
            "statistical_methodology_summary": methodology_selection_summary,
            "success_metrics": success_metrics,
            "guardrails": guardrails,
            "blocked_metrics": BLOCKED_PHASE2_METRICS,
            "ab_risks": ab_risks,
            "hypothesis_portfolio": hypothesis_portfolio,
            "hypothesis_generation_mode": hypothesis_generation_mode,
            "portfolio_diversity_score": portfolio_diversity_score,
            "recommended_experiment": recommended_experiment,
            "ab_interpretation_methodology": ab_interpretation_methodology,
            "measurement_fix_plan": measurement_fix_plan,
            "layer1_verdict": layer1_verdict,
            "layer2_guardrail_verdicts": layer2_guardrail_verdicts,
            "alternative_hypotheses": alt_hypotheses,
            "temporal_risk": temporal_risk,
            "sensitivity_note": sensitivity_note,
            "required_human_approval": _approval_for_decision(decision),
            "next_actions": next_actions,
            "exploratory_ideas": exploratory_ideas,
            "prompt_profile": {
                "name": "doctor_science_rules_v3_canonical",
                "system_prompt_embedded": True,
            },
            "inputs": {
                "dq_status": dq.get("qa_status"),
                "captain_verdict": ((captain.get("result", {}) or {}).get("verdict") if isinstance(captain, dict) else None),
                "control_run_id": (control_run_id or args.control_run_id),
                "control_snapshot_present": control_snapshot is not None,
                "doctor_context": str(doctor_context_path),
            },
            "historical_context": {
                "used": True,
                "pack_ref": str(historical_context_pack_path),
                "retrieved_rows": len(historical_context_rows),
            },
            "trace_refs": [
                f"artifact:{historical_context_pack_path}#",
                f"artifact:{doctor_context_path}#",
                *( [stat_bundle_ref] if stat_bundle_ref else [] ),
            ],
            "artifact_hash_refs": [
                {
                    "artifact_ref": str(historical_context_pack_path),
                    "sha256": historical_context_pack_sha256,
                },
                *(
                    [
                        {
                            "artifact_ref": str(bundle_path),
                            "sha256": stat_bundle_sha256,
                        }
                    ]
                    if stat_bundle_sha256
                    else []
                ),
            ],
            "evidence": {
                "dq_report": f"artifact:data/dq_reports/{run_id}.json#",
                "captain_report": f"artifact:data/llm_reports/{run_id}_captain.json#",
                "metrics_snapshot": f"artifact:data/metrics_snapshots/{run_id}.json#",
                "doctor_context": f"artifact:{doctor_context_path}#",
                "historical_context_pack": f"artifact:{historical_context_pack_path}#",
                "stat_evidence_bundle": stat_bundle_ref,
                "ab_report": (
                    f"artifact:data/ab_reports/{run_id}_{experiment_id}_ab.json#"
                    if experiment_id
                    else None
                ),
                "ab_status": ab_status,
                "ab_srm_status": srm_status,
            },
            "assignment_status": assignment_status,
            "measurement_state": measurement_state,
            "measurement_state_reason": measurement_state_reason,
            "paired_status": paired_status,
            "layers_present": layers_present,
            "reasoning_confidence_inputs": reasoning_confidence_inputs,
            "guardrail_status_check": (
                stat_bundle_payload.get("guardrail_status_check", [])
                if isinstance(stat_bundle_payload.get("guardrail_status_check"), list)
                else []
            ),
            "stat_evidence_bundle_ref": stat_bundle_ref,
            "reasoning_mode": reasoning_mode,
            "model_used": model_used,
            "fallback_tier": fallback_tier_final,
            "fallback_reason": fallback_reason_final,
            "provisional_local_fallback": provisional_local_fallback,
            "needs_cloud_reconciliation": provisional_local_fallback,
            "visible_reasoning_trace": visible_reasoning_trace,
            "llm_provenance": {
                "methodology_selection": (
                    (
                        ab_interpretation_methodology.get("selection_provenance")
                        if isinstance(ab_interpretation_methodology, dict)
                        and isinstance(ab_interpretation_methodology.get("selection_provenance"), dict)
                        else (
                            methodology_selection_summary.get("selection_provenance")
                            if isinstance(methodology_selection_summary, dict)
                            and isinstance(methodology_selection_summary.get("selection_provenance"), dict)
                            else None
                        )
                    )
                    or {}
                ),
                "human_summary": human_summary_llm_provenance,
                "domain_reference": domain_reference.get("sources", {}),
                "feature_flags": feature_flags,
                "hypothesis_generation_mode": hypothesis_generation_mode,
                "hypothesis_generation": hypothesis_generation_provenance,
                "fallback_tier": fallback_tier_final,
                "provisional_local_fallback": provisional_local_fallback,
                "needs_cloud_reconciliation": provisional_local_fallback,
                "visible_reasoning_trace": trace_meta,
                "historical_context": {
                    "used": True,
                    "pack_ref": str(historical_context_pack_path),
                    "rows_used": len(historical_context_rows),
                },
                "stat_evidence_bundle": {
                    "status": str(stat_bundle_payload.get("status", "")).strip().upper()
                    if isinstance(stat_bundle_payload, dict)
                    else "",
                    "ref": stat_bundle_ref,
                    "error": stat_bundle_error or None,
                },
            },
            "protocol_checks_passed": protocol_checks_passed,
            "protocol_checks": protocol_checks,
            "react_config": {
                "enabled": enable_react_doctor,
                "max_steps": int(args.react_max_steps),
                "timeout_sec": int(args.react_timeout_sec),
            },
            "quality": {
                "hypothesis_valid": hypothesis_valid,
                "hypothesis_format_valid": hypothesis_format_valid,
                "methodology_present": methodology_present,
                "required_sample_size_present": required_sample_size_present,
                "evidence_fields_present": evidence_fields_present,
                "semantic_score": doctor_semantic_score,
            },
            "human_summary_md": human_summary,
        }

        validate_decision(str(out.get("normalized_decision", "")), decision_contract, "normalized_decision")
        validate_required_fields(out, decision_contract, "doctor")
        _validate_output_contract(out)
        _validate_against_schema_file(out, output_schema)

        if decision == "RUN_AB" and ab_plan:
            _update_active_experiments_registry(run_id, ab_plan)

        out_dir = Path("data/agent_reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / f"{run_id}_doctor_variance.json"
        md_path = out_dir / f"{run_id}_doctor_variance.md"
        safe_out = _redact_obj(out)
        json_path.write_text(json.dumps(safe_out, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(json_path)
        md_path.write_text(_redact_text(_render_md(safe_out)), encoding="utf-8")

        print(f"ok: doctor_variance decision={decision}")
    except ConfigurationError as exc:
        raise SystemExit(f"ConfigurationError: {exc}")
    except Exception:
        log_path = _log_failure(run_id, "doctor_variance runtime error")
        raise SystemExit(f"doctor_variance failed. See {log_path}")


if __name__ == "__main__":
    main()
