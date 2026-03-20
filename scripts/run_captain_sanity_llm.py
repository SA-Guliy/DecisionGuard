#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root imports work when script runs from scripts/
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.llm_contract_utils import coerce_string, coerce_string_list
from src.model_policy import CAPTAIN_GROQ_MODEL
from src.runtime_controls import get_retry_budget_status, load_retry_policy_contract, register_retry_outcome, write_retry_guard_report
from src.runtime_failover import build_runtime_failover_tiers, generate_with_runtime_failover
from src.semantic_scoring import captain_semantic_score, drop_unproven_novel_issues, is_novel_check_name
from src.reasoning_feature_flags import load_reasoning_feature_flags
from src.security_utils import write_sha256_sidecar
from src.visible_reasoning_trace import build_visible_reasoning_trace_advisory
from src.domain_template import ConfigurationError, load_domain_template

SYSTEM_PROMPT = (
    "You are Captain Sanity, a strict QA engineer for simulation runs. "
    "Use only provided input. NEVER invent causes. "
    "If uncertain, write 'unknown' and provide verification SQL/psql steps. "
    "Output STRICT JSON only with schema: "
    "{verdict: PASS|WARN|FAIL, issues:[{check_name,severity,message,hypotheses,verification_steps}],recommendations:[...]}. "
    "No extra top-level keys."
)

ENABLE_VISIBLE_REASONING_TRACE = 0
CAPTAIN_ALLOW_NOVEL_ISSUES = 0
DOCTOR_DYNAMIC_HYPOTHESES = 0

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\\s*=\\s*\\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\\s*=\\s*)\\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\\s*=\\s*)\\S+", re.IGNORECASE), r"\1[REDACTED]"),
]

SAFETY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"postgresql://", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9_]*_API_KEY", re.IGNORECASE),
    re.compile(r"password\\s*=", re.IGNORECASE),
    re.compile(r"token\\s*=", re.IGNORECASE),
    re.compile(r"gsk_", re.IGNORECASE),
]

DEFAULT_ALLOWED_SQL_TABLES = {
    "step1.vw_valid_orders",
    "step1.vw_valid_order_items",
    "step1.vw_valid_customer_daily",
    "step1.step1_orders",
    "step1.step1_order_items",
    "step1.step1_customer_daily",
    "step1.step1_run_registry",
    "raw.raw_orders_stream",
    "raw.raw_products",
}

DEFAULT_SQL_STEP_TEMPLATES = [
    "SELECT ... FROM step1.vw_valid_orders WHERE run_id = '<run_id>';",
    "SELECT ... FROM step1.vw_valid_order_items WHERE run_id = '<run_id>';",
    "SELECT ... FROM step1.vw_valid_customer_daily WHERE run_id = '<run_id>';",
    "SELECT ... FROM step1.step1_orders WHERE run_id = '<run_id>';",
    "SELECT ... FROM step1.step1_order_items WHERE run_id = '<run_id>';",
    "SELECT ... FROM step1.step1_customer_daily WHERE run_id = '<run_id>';",
]
ALLOWED_SQL_TABLES = set(DEFAULT_ALLOWED_SQL_TABLES)
SQL_STEP_TEMPLATES = list(DEFAULT_SQL_STEP_TEMPLATES)
MUTATING_SQL_KEYWORDS = ("drop ", "delete ", "truncate ", "update ", "insert ", "alter ", "create ", "merge ")
_NOVEL_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_REL_TABLE_RE = re.compile(r"^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$")


def _active_feature_flags() -> dict[str, int]:
    return load_reasoning_feature_flags(
        {
            "ENABLE_VISIBLE_REASONING_TRACE": ENABLE_VISIBLE_REASONING_TRACE,
            "CAPTAIN_ALLOW_NOVEL_ISSUES": CAPTAIN_ALLOW_NOVEL_ISSUES,
            "DOCTOR_DYNAMIC_HYPOTHESES": DOCTOR_DYNAMIC_HYPOTHESES,
        }
    )


def _apply_domain_template(domain_template_path: str = "") -> dict[str, Any]:
    global ALLOWED_SQL_TABLES, SQL_STEP_TEMPLATES
    cfg = load_domain_template(domain_template_path)
    captain_cfg = cfg.get("captain", {}) if isinstance(cfg.get("captain"), dict) else {}
    allowed_tables = captain_cfg.get("allowed_sql_tables", [])
    sql_templates = captain_cfg.get("sql_step_templates", [])
    requested_tables = {str(x).strip() for x in allowed_tables if str(x).strip()}
    if not requested_tables:
        raise ConfigurationError("Missing Domain Template Captain allowed_sql_tables")
    invalid_names = sorted(t for t in requested_tables if not _REL_TABLE_RE.fullmatch(t))
    if invalid_names:
        raise ConfigurationError(f"Invalid Captain table name(s): {invalid_names[:5]}")
    disallowed = sorted(t for t in requested_tables if t not in DEFAULT_ALLOWED_SQL_TABLES)
    if disallowed:
        raise ConfigurationError(f"Captain table(s) outside runtime ceiling allowlist: {disallowed[:5]}")
    ALLOWED_SQL_TABLES = set(requested_tables)
    SQL_STEP_TEMPLATES = [str(x) for x in sql_templates if str(x).strip()]
    if not ALLOWED_SQL_TABLES or not SQL_STEP_TEMPLATES:
        raise ConfigurationError("Missing Domain Template Captain policy")
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


def _extract_json_block(text_value: str) -> dict[str, Any]:
    match = re.search(r"\{", text_value)
    if not match:
        raise ValueError("No JSON object found")
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(text_value[match.start() :])
    if not isinstance(obj, dict):
        raise ValueError("Top-level JSON must be object")
    return obj


def _validate_response_schema(obj: dict[str, Any]) -> None:
    required_top = {"verdict", "issues", "recommendations"}
    if set(obj.keys()) != required_top:
        raise ValueError("Top-level keys mismatch")

    if obj["verdict"] not in {"PASS", "WARN", "FAIL"}:
        raise ValueError("Invalid verdict")

    issues = obj["issues"]
    if not isinstance(issues, list):
        raise ValueError("issues must be list")

    for issue in issues:
        if not isinstance(issue, dict):
            raise ValueError("issue must be object")
        expected_keys = {"check_name", "severity", "message", "hypotheses", "verification_steps", "evidence_refs"}
        if set(issue.keys()) != expected_keys:
            raise ValueError("issue keys mismatch")
        if issue["severity"] not in {"HARD_FAIL", "WARN", "INFO"}:
            raise ValueError("invalid issue severity")
        if not isinstance(issue["check_name"], str) or not issue["check_name"].strip():
            raise ValueError("check_name must be non-empty string")
        if not isinstance(issue["message"], str):
            raise ValueError("message must be string")
        if not isinstance(issue["hypotheses"], list) or len(issue["hypotheses"]) > 2:
            raise ValueError("hypotheses must be list with max 2")
        if not isinstance(issue["verification_steps"], list) or len(issue["verification_steps"]) > 3:
            raise ValueError("verification_steps must be list with max 3")
        if not isinstance(issue["evidence_refs"], list) or len(issue["evidence_refs"]) > 5:
            raise ValueError("evidence_refs must be list with max 5")

    recs = obj["recommendations"]
    if not isinstance(recs, list) or len(recs) > 5:
        raise ValueError("recommendations must be list with max 5")


def _issue_has_evidence_refs(issue: dict[str, Any]) -> bool:
    refs = issue.get("evidence_refs", [])
    return isinstance(refs, list) and any(str(r).strip() for r in refs)


def _is_read_only_select_step(step: str, *, allow_psql: bool) -> bool:
    s = str(step or "").strip()
    if not s:
        return False
    s_lower = s.lower()
    if any(k in s_lower for k in MUTATING_SQL_KEYWORDS):
        return False
    if not any(tbl in s_lower for tbl in ALLOWED_SQL_TABLES):
        return False
    if allow_psql and s_lower.startswith("psql "):
        return True
    return s_lower.startswith("select ") or s_lower.startswith("with ")


def _issue_has_grounded_evidence(issue: dict[str, Any], *, novel_only: bool = False) -> bool:
    if not isinstance(issue, dict):
        return False
    if novel_only and not _issue_has_evidence_refs(issue):
        return False
    steps = issue.get("verification_steps", [])
    if not isinstance(steps, list):
        return False
    for step in steps:
        if _is_read_only_select_step(step, allow_psql=(not novel_only)):
            return True
    return False


def _slugify_novel_issue(text: str) -> str:
    slug = re.sub(r"[^a-z0-9_-]+", "_", str(text or "").strip().lower()).strip("_")
    if not slug:
        slug = "issue"
    if not re.match(r"^[a-z0-9]", slug):
        slug = f"n_{slug}"
    return slug[:64]


def _ensure_novel_check_name(check_name: str, fallback_source: str) -> str:
    raw = str(check_name or "").strip()
    if raw.startswith("novel::"):
        slug = raw.split("novel::", 1)[1].strip()
        if _NOVEL_SLUG_RE.fullmatch(slug):
            return f"novel::{slug}"
    slug = _slugify_novel_issue(raw or fallback_source)
    return f"novel::{slug}"


def _validate_issue_check_names(
    obj: dict[str, Any],
    allowed_check_names: set[str],
    *,
    allow_novel_issues: bool = False,
) -> None:
    if not allowed_check_names:
        return
    for issue in obj.get("issues", []):
        if not isinstance(issue, dict):
            continue
        check_name = str(issue.get("check_name", "")).strip()
        if check_name in allowed_check_names:
            continue
        if allow_novel_issues and is_novel_check_name(check_name):
            if not _issue_has_evidence_refs(issue):
                raise ValueError(f"novel issue must include evidence_refs: {check_name}")
            if _issue_has_grounded_evidence(issue, novel_only=True):
                continue
            raise ValueError(f"novel issue has invalid verification_steps: {check_name}")
        raise ValueError(f"issue check_name not allowed: {check_name}")


def _validate_verification_steps(obj: dict[str, Any]) -> None:
    for issue in obj.get("issues", []):
        if not isinstance(issue, dict):
            continue
        check_name = str(issue.get("check_name", "")).strip()
        novel_issue = is_novel_check_name(check_name)
        steps = issue.get("verification_steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            s = str(step).strip()
            if not s:
                continue
            if not _is_read_only_select_step(step, allow_psql=(not novel_issue)):
                if novel_issue:
                    raise ValueError("novel verification step must be read-only SELECT/CTE over allowed tables")
                raise ValueError("verification step must be read-only SQL/psql over allowed tables")


def _normalize_captain_candidate(
    obj: dict[str, Any],
    allowed_check_names: set[str],
    *,
    allow_novel_issues: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    repairs: list[str] = []
    verdict = str(obj.get("verdict", "WARN")).strip().upper() or "WARN"
    if verdict not in {"PASS", "WARN", "FAIL"}:
        repairs.append("normalized:verdict")
        if "FAIL" in verdict:
            verdict = "FAIL"
        elif "PASS" in verdict:
            verdict = "PASS"
        else:
            verdict = "WARN"

    rec_in = obj.get("recommendations", [])
    if not isinstance(rec_in, list):
        repairs.append("coerced:recommendations_to_list")
    recommendations = coerce_string_list(rec_in, max_items=5, max_item_len=240)

    issues_in = obj.get("issues", [])
    if isinstance(issues_in, dict):
        issues_in = [issues_in]
        repairs.append("coerced:issues_dict_to_list")
    elif not isinstance(issues_in, list):
        issues_in = []
        repairs.append("coerced:issues_to_list")

    issues_out: list[dict[str, Any]] = []
    dropped_invalid_check_names = 0
    for issue in issues_in:
        if not isinstance(issue, dict):
            repairs.append("dropped:non_dict_issue")
            continue
        d = dict(issue)
        if "hypothesis" in d and "hypotheses" not in d:
            d["hypotheses"] = d["hypothesis"]
            repairs.append("alias:hypothesis->hypotheses")
        if "verification" in d and "verification_steps" not in d:
            d["verification_steps"] = d["verification"]
            repairs.append("alias:verification->verification_steps")
        if "evidence" in d and "evidence_refs" not in d:
            d["evidence_refs"] = d["evidence"]
            repairs.append("alias:evidence->evidence_refs")
        if "evidence_ref" in d and "evidence_refs" not in d:
            d["evidence_refs"] = [d["evidence_ref"]]
            repairs.append("alias:evidence_ref->evidence_refs")

        check_name = coerce_string(d.get("check_name", ""), max_len=120)
        if check_name.startswith("checks_warn_fail"):
            dropped_invalid_check_names += 1
            repairs.append("dropped:placeholder_check_name")
            continue
        message = coerce_string(d.get("message", ""), max_len=500)
        hyp_in = d.get("hypotheses", [])
        if not isinstance(hyp_in, list):
            repairs.append("coerced:hypotheses_to_list")
        ver_in = d.get("verification_steps", [])
        if not isinstance(ver_in, list):
            repairs.append("coerced:verification_steps_to_list")
        evidence_in = d.get("evidence_refs", [])
        if isinstance(evidence_in, str):
            evidence_in = [evidence_in]
            repairs.append("coerced:evidence_refs_string_to_list")
        elif not isinstance(evidence_in, list):
            evidence_in = []
            repairs.append("coerced:evidence_refs_to_list")
        evidence_refs = coerce_string_list(evidence_in, max_items=5, max_item_len=240)
        verification_steps = coerce_string_list(ver_in, max_items=3, max_item_len=500)

        if allowed_check_names and check_name and check_name not in allowed_check_names:
            if allow_novel_issues and _issue_has_grounded_evidence(
                {"verification_steps": verification_steps, "evidence_refs": evidence_refs},
                novel_only=True,
            ):
                check_name = _ensure_novel_check_name(check_name, message)
                repairs.append("normalized:novel_check_name")
            else:
                dropped_invalid_check_names += 1
                repairs.append("dropped:unknown_check_name")
                continue
        if allowed_check_names and not check_name:
            if allow_novel_issues and _issue_has_grounded_evidence(
                {"verification_steps": verification_steps, "evidence_refs": evidence_refs},
                novel_only=True,
            ):
                check_name = _ensure_novel_check_name("", message or f"issue_{len(issues_out) + 1}")
                repairs.append("generated:novel_check_name")
            else:
                dropped_invalid_check_names += 1
                repairs.append("dropped:missing_check_name")
                continue
        if allow_novel_issues and check_name.startswith("novel::"):
            check_name = _ensure_novel_check_name(check_name, message)
            verification_steps = [
                s for s in verification_steps if _is_read_only_select_step(s, allow_psql=False)
            ]
            if not evidence_refs:
                dropped_invalid_check_names += 1
                repairs.append("dropped:novel_without_evidence_refs")
                continue
            if not verification_steps:
                dropped_invalid_check_names += 1
                repairs.append("dropped:novel_without_select_verification")
                continue

        severity = str(d.get("severity", "WARN")).strip().upper()
        if severity not in {"HARD_FAIL", "WARN", "INFO"}:
            repairs.append("normalized:issue_severity")
            if "FAIL" in severity:
                severity = "HARD_FAIL"
            elif "INFO" in severity:
                severity = "INFO"
            else:
                severity = "WARN"

        issues_out.append(
            {
                "check_name": check_name or "unknown_check",
                "severity": severity,
                "message": message,
                "hypotheses": coerce_string_list(hyp_in, max_items=2, max_item_len=200),
                "verification_steps": verification_steps,
                "evidence_refs": evidence_refs,
            }
        )

    if dropped_invalid_check_names:
        repairs.append(f"dropped_invalid_check_name_issues:{dropped_invalid_check_names}")
    return {
        "verdict": verdict,
        "issues": issues_out[:20],
        "recommendations": recommendations,
    }, repairs


def _build_prompt(dq_report: dict[str, Any]) -> str:
    rows = dq_report.get("rows", [])
    if not isinstance(rows, list):
        rows = []

    focus_rows = [
        {
            "check_name": r.get("check_name"),
            "severity": r.get("severity"),
            "status": r.get("status"),
            "actual_value": r.get("actual_value"),
            "message": r.get("message"),
        }
        for r in rows
        if str(r.get("status")) in {"WARN", "FAIL"}
    ][:40]

    allowed_check_names = sorted(
        {
            str(r.get("check_name"))
            for r in rows
            if r.get("check_name") is not None and str(r.get("check_name")).strip()
        }
    )

    payload = {
        "run_id": dq_report.get("run_id"),
        "qa_status": dq_report.get("qa_status"),
        "summary": dq_report.get("summary", {}),
        "checks_warn_fail": focus_rows,
        "allowed_check_names": allowed_check_names,
        "sql_dictionary": {
            "allowed_tables": sorted(ALLOWED_SQL_TABLES),
            "allowed_step_templates": SQL_STEP_TEMPLATES,
        },
    }

    instruction = {
        "rules": [
            "Ground every issue in input checks_warn_fail.",
            "issues[].check_name must be subset of allowed_check_names unless CAPTAIN_ALLOW_NOVEL_ISSUES=1, then use novel::<slug>.",
            "Do not invent root causes.",
            "If uncertain, use hypotheses=['unknown'].",
            "verification_steps must follow allowed SQL/psql templates and use only allowed tables.",
            "Do not output mutation SQL (DROP/DELETE/TRUNCATE/UPDATE/INSERT).",
            "For novel::<slug> issues provide non-empty evidence_refs and SELECT/CTE verification only (no psql wrapper).",
        ],
        "strict_json_schema": {
            "verdict": "PASS|WARN|FAIL",
            "issues": [
                {
                    "check_name": "string",
                    "severity": "HARD_FAIL|WARN|INFO",
                    "message": "string",
                    "hypotheses": ["max 2 strings"],
                    "verification_steps": ["max 3 SQL/psql strings"],
                    "evidence_refs": ["max 5 grounding refs"],
                }
            ],
            "recommendations": ["max 5 strings"],
        },
    }

    return (
        "INPUT_DATA:\n"
        + json.dumps(payload, ensure_ascii=False)
        + "\n\nINSTRUCTION:\n"
        + json.dumps(instruction, ensure_ascii=False)
    )


def _contains_sensitive_text(value: Any) -> bool:
    text_value = json.dumps(value, ensure_ascii=False)
    return any(p.search(text_value) for p in SAFETY_PATTERNS)


def _compute_eval_metrics(
    dq_report: dict[str, Any],
    result: dict[str, Any],
    *,
    allow_novel_issues: bool = False,
    dropped_unproven_novel: int = 0,
) -> dict[str, Any]:
    dq_rows = dq_report.get("rows", [])
    if not isinstance(dq_rows, list):
        dq_rows = []

    target_checks = {
        str(row.get("check_name"))
        for row in dq_rows
        if str(row.get("status")) in {"WARN", "FAIL"} and row.get("check_name")
    }
    issue_checks = {
        str(issue.get("check_name"))
        for issue in result.get("issues", [])
        if isinstance(issue, dict) and issue.get("check_name")
    }
    accepted_novel_checks = {
        str(issue.get("check_name"))
        for issue in result.get("issues", [])
        if isinstance(issue, dict)
        and allow_novel_issues
        and is_novel_check_name(str(issue.get("check_name", "")).strip())
        and _issue_has_grounded_evidence(issue, novel_only=True)
    }

    covered = len(target_checks & issue_checks)
    issue_coverage = covered / len(target_checks) if target_checks else 1.0

    extra_checks = sorted(
        list(
            (issue_checks - {str(row.get("check_name")) for row in dq_rows if row.get("check_name")})
            - accepted_novel_checks
        )
    )
    no_extra_issues = len(extra_checks) == 0

    issues = result.get("issues", []) if isinstance(result.get("issues"), list) else []
    actionable_count = 0
    for issue in issues:
        if isinstance(issue, dict):
            steps = issue.get("verification_steps")
            if isinstance(steps, list) and any(str(s).strip() for s in steps):
                actionable_count += 1
    actionability = actionable_count / len(issues) if issues else 1.0

    safety_ok = not _contains_sensitive_text(result)
    semantic_score, semantic_breakdown = captain_semantic_score(
        dq_report,
        result,
        dropped_unproven_novel=dropped_unproven_novel,
    )

    return {
        "issue_coverage": round(issue_coverage, 4),
        "no_extra_issues": no_extra_issues,
        "extra_issues": extra_checks,
        "actionability": round(actionability, 4),
        "safety": safety_ok,
        "semantic_score": semantic_score,
        "semantic_breakdown": semantic_breakdown,
        "novel_issues_accepted": len(accepted_novel_checks),
        "target_warn_fail_count": len(target_checks),
    }


def _build_visible_reasoning_trace(
    run_id: str,
    result: dict[str, Any],
    eval_metrics: dict[str, Any],
    enabled: bool,
) -> dict[str, Any]:
    if not enabled:
        return {"claims": [], "gates_checked": [], "unknowns": []}

    claims: list[dict[str, Any]] = []
    issues = result.get("issues", []) if isinstance(result.get("issues"), list) else []
    for idx, issue in enumerate(issues[:20], start=1):
        if not isinstance(issue, dict):
            continue
        check_name = str(issue.get("check_name", "")).strip() or f"issue_{idx}"
        message = str(issue.get("message", "")).strip() or "Issue detected."
        hypotheses = issue.get("hypotheses", [])
        alternatives = [str(x).strip() for x in hypotheses if str(x).strip()][:3]
        if not alternatives:
            alternatives = ["unknown"]
        verification_steps = issue.get("verification_steps", []) if isinstance(issue.get("verification_steps"), list) else []
        falsifiability_test = (
            str(verification_steps[0]).strip()
            if verification_steps and str(verification_steps[0]).strip()
            else f"Run allowed SQL verification for check {check_name} and compare against expected status."
        )
        severity = str(issue.get("severity", "WARN")).upper()
        decision_impact = (
            "Likely blocks PASS and pushes captain verdict toward FAIL/WARN."
            if severity in {"HARD_FAIL", "WARN"}
            else "Informational impact; does not directly block PASS."
        )
        claims.append(
            {
                "claim_id": f"captain:{run_id}:{idx}:{check_name}",
                "statement": f"{check_name}: {message}",
                "evidence_refs": [
                    f"artifact:data/dq_reports/{run_id}.json#/rows",
                    f"dq_check:{check_name}",
                ],
                "alternatives_considered": alternatives,
                "falsifiability_test": falsifiability_test,
                "decision_impact": decision_impact,
            }
        )

    gates_checked = [
        "captain_schema_validation:PASS",
        (
            "issue_coverage_min_0_60:PASS"
            if float(eval_metrics.get("issue_coverage", 0.0) or 0.0) >= 0.60
            else "issue_coverage_min_0_60:FAIL"
        ),
        (
            "no_extra_issues:PASS"
            if bool(eval_metrics.get("no_extra_issues", False))
            else "no_extra_issues:WARN"
        ),
        (
            "safety_redaction:PASS"
            if bool(eval_metrics.get("safety", False))
            else "safety_redaction:FAIL"
        ),
    ]

    unknowns: list[str] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        for hypothesis in (issue.get("hypotheses") if isinstance(issue.get("hypotheses"), list) else []):
            hyp = str(hypothesis).strip()
            if hyp.lower() == "unknown":
                unknowns.append(f"unknown root cause for check {issue.get('check_name', 'unknown_check')}")
    unknowns = sorted({u for u in unknowns if u})[:20]
    return {"claims": claims, "gates_checked": gates_checked, "unknowns": unknowns}


def _render_markdown(run_id: str, model_name: str, result: dict[str, Any], eval_metrics: dict[str, Any]) -> str:
    lines = [
        f"# Captain Sanity Report: {run_id}",
        "",
        f"- model: `{model_name}`",
        f"- verdict: `{result.get('verdict', 'UNKNOWN')}`",
        "",
        "## Eval metrics",
        f"- issue_coverage: `{eval_metrics.get('issue_coverage')}`",
        f"- no_extra_issues: `{eval_metrics.get('no_extra_issues')}`",
        f"- actionability: `{eval_metrics.get('actionability')}`",
        f"- safety: `{eval_metrics.get('safety')}`",
        f"- semantic_score: `{eval_metrics.get('semantic_score')}`",
        "",
        "## Issues",
        "| check_name | severity | message |",
        "|---|---|---|",
    ]

    issues = result.get("issues", []) if isinstance(result.get("issues"), list) else []
    if issues:
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            lines.append(
                f"| {issue.get('check_name', '')} | {issue.get('severity', '')} | {issue.get('message', '')} |"
            )
            steps = issue.get("verification_steps", [])
            if isinstance(steps, list) and steps:
                lines.append("")
                lines.append(f"Verification steps for `{issue.get('check_name', '')}`:")
                for step in steps:
                    lines.append(f"- {step}")
                lines.append("")
    else:
        lines.append("| - | - | No issues |")

    lines.append("## Recommendations")
    recs = result.get("recommendations", []) if isinstance(result.get("recommendations"), list) else []
    if recs:
        for r in recs:
            lines.append(f"- {r}")
    else:
        lines.append("- No recommendations")

    return "\n".join(lines).strip() + "\n"


def _log(log_file: Path, text_value: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as f:
        f.write(text_value + "\n")


def _build_local_mock_result(dq_report: dict[str, Any]) -> dict[str, Any]:
    rows = dq_report.get("rows", [])
    if not isinstance(rows, list):
        rows = []
    wf_rows = [r for r in rows if isinstance(r, dict) and str(r.get("status")) in {"WARN", "FAIL"}]
    issues: list[dict[str, Any]] = []
    for row in wf_rows[:3]:
        check_name = str(row.get("check_name", "")).strip() or "unknown_check"
        severity = str(row.get("severity", "WARN"))
        if severity not in {"HARD_FAIL", "WARN", "INFO"}:
            severity = "WARN"
        message = str(row.get("message", "unknown"))
        issues.append(
            {
                "check_name": check_name,
                "severity": severity,
                "message": message,
                "hypotheses": ["unknown"],
                "verification_steps": [
                    f"SELECT * FROM step1.vw_valid_orders WHERE run_id = '<run_id>' LIMIT 20; -- check {check_name}",
                    f"SELECT * FROM step1.step1_orders WHERE run_id = '<run_id>' LIMIT 20; -- fallback for {check_name}",
                ],
                "evidence_refs": [f"artifact:data/dq_reports/<run_id>.json#/rows/{check_name}"],
            }
        )
    verdict = "PASS"
    if any(str(r.get("status")) == "FAIL" and str(r.get("severity")) == "HARD_FAIL" for r in wf_rows):
        verdict = "FAIL"
    elif wf_rows:
        verdict = "WARN"
    return {
        "verdict": verdict,
        "issues": issues,
        "recommendations": [
            "Start Ollama for richer qualitative analysis.",
            "Review WARN/FAIL checks directly in dq_report before rollout.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Captain Sanity with LLM backend")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--backend", choices=["groq", "ollama", "auto"], default="auto")
    parser.add_argument("--domain-template", default="", help="Optional path to domain template JSON")
    args = parser.parse_args()
    try:
        domain_cfg = _apply_domain_template(args.domain_template)
    except ConfigurationError as exc:
        raise SystemExit(f"ConfigurationError: {exc}")

    run_id = args.run_id
    dq_path = Path(f"data/dq_reports/{run_id}.json")
    if not dq_path.exists():
        raise SystemExit(f"Missing input: {dq_path}")

    dq_report = json.loads(dq_path.read_text(encoding="utf-8"))
    prompt = _build_prompt(dq_report)
    log_file = Path(f"data/logs/captain_{run_id}.log")
    feature_flags = _active_feature_flags()
    allow_novel_issues = bool(feature_flags.get("CAPTAIN_ALLOW_NOVEL_ISSUES", 0))
    allowed_check_names = {
        str(r.get("check_name"))
        for r in dq_report.get("rows", [])
        if isinstance(r, dict) and r.get("check_name") is not None
    }

    model_override = CAPTAIN_GROQ_MODEL if args.backend in {"groq", "auto"} else None
    failover_tiers = build_runtime_failover_tiers(
        backend_requested=args.backend,
        groq_models=([model_override] if model_override else []),
        include_ollama=True,
    )
    model_name = "deterministic_local"
    selected_model_name = ""

    parsed: dict[str, Any] | None = None
    used_fallback = False
    fallback_reason: str | None = None
    fallback_stage: str | None = None
    fallback_tier_value = "none"
    provisional_local_fallback = False
    needs_cloud_reconciliation = False
    runtime_failover_attempts: list[dict[str, Any]] = []
    repair_actions_total: list[str] = []
    retry_policy: dict[str, Any] | None = None
    llm_attempted = False
    llm_success = False
    blocked_by_retry = False
    blocked_retry_reason = ""
    blocked_retry_state: dict[str, Any] = {}
    obfuscation_map_refs: list[str] = []
    try:
        retry_policy = load_retry_policy_contract()
    except Exception:
        retry_policy = None

    if retry_policy is not None:
        retry_status = get_retry_budget_status(run_id, retry_policy)
        if not bool(retry_status.get("allowed", False)):
            blocked_by_retry = True
            blocked_retry_reason = str(retry_status.get("reason", "retry_policy_blocked"))
            blocked_retry_state = retry_status.get("state") if isinstance(retry_status.get("state"), dict) else {}
            write_retry_guard_report(
                run_id,
                status="FAIL",
                reason=f"{blocked_retry_reason}:run_captain_sanity_llm",
                retry_policy=retry_policy,
                state=blocked_retry_state,
            )

    if blocked_by_retry:
        parsed = _build_local_mock_result(dq_report)
        used_fallback = True
        model_name = "deterministic_local"
        fallback_reason = f"retry_policy_blocked:{blocked_retry_reason}"
        fallback_stage = "pre_llm_budget"
        fallback_tier_value = "deterministic"
        provisional_local_fallback = True
        needs_cloud_reconciliation = True
    else:
        extra_instruction = ""
        for attempt in range(3):
            if retry_policy is not None:
                step_status = get_retry_budget_status(run_id, retry_policy)
                if not bool(step_status.get("allowed", False)):
                    blocked_by_retry = True
                    blocked_retry_reason = str(step_status.get("reason", "retry_policy_blocked"))
                    blocked_retry_state = step_status.get("state") if isinstance(step_status.get("state"), dict) else {}
                    write_retry_guard_report(
                        run_id,
                        status="FAIL",
                        reason=f"{blocked_retry_reason}:run_captain_sanity_llm",
                        retry_policy=retry_policy,
                        state=blocked_retry_state,
                    )
                    parsed = _build_local_mock_result(dq_report)
                    used_fallback = True
                    model_name = "deterministic_local"
                    fallback_reason = f"retry_policy_blocked:{blocked_retry_reason}"
                    fallback_stage = "pre_attempt_budget"
                    fallback_tier_value = "deterministic"
                    provisional_local_fallback = True
                    needs_cloud_reconciliation = True
                    break
            try:
                llm_attempted = True
                output, gen_meta = generate_with_runtime_failover(
                    run_id=run_id,
                    agent_name="captain",
                    call_name="sanity_check",
                    prompt=prompt + extra_instruction,
                    system_prompt=SYSTEM_PROMPT,
                    tiers=failover_tiers,
                    deterministic_generator=lambda: json.dumps(_build_local_mock_result(dq_report), ensure_ascii=False),
                )
                model_name = str(gen_meta.get("model", model_name) or model_name)
                if not selected_model_name:
                    selected_model_name = model_name
                fallback_tier_value = str(gen_meta.get("fallback_tier", fallback_tier_value) or fallback_tier_value)
                provisional_local_fallback = bool(gen_meta.get("provisional_local_fallback", False))
                needs_cloud_reconciliation = bool(gen_meta.get("needs_cloud_reconciliation", False))
                if bool(gen_meta.get("used_fallback", False)):
                    used_fallback = True
                    fallback_reason = str(gen_meta.get("fallback_reason", "")).strip() or "runtime_failover"
                    fallback_stage = "runtime_failover"
                if isinstance(gen_meta.get("attempts"), list):
                    runtime_failover_attempts = [x for x in gen_meta.get("attempts", []) if isinstance(x, dict)][:12]
                map_ref = str(gen_meta.get("obfuscation_map_ref", "")).strip()
                if map_ref:
                    obfuscation_map_refs.append(map_ref)
            except Exception as exc:
                _log(log_file, f"attempt={attempt+1} llm_runtime_error={exc}")
                parsed = _build_local_mock_result(dq_report)
                used_fallback = True
                model_name = "deterministic_local"
                fallback_reason = "llm_runtime_error"
                fallback_stage = "generate"
                fallback_tier_value = "deterministic"
                provisional_local_fallback = True
                needs_cloud_reconciliation = True
                break
            try:
                candidate = _extract_json_block(output)
                candidate, repair_actions = _normalize_captain_candidate(
                    candidate,
                    allowed_check_names,
                    allow_novel_issues=allow_novel_issues,
                )
                repair_actions_total.extend(repair_actions)
                _validate_response_schema(candidate)
                _validate_issue_check_names(
                    candidate,
                    allowed_check_names,
                    allow_novel_issues=allow_novel_issues,
                )
                _validate_verification_steps(candidate)
                parsed = candidate
                llm_success = True
                break
            except Exception as exc:
                _log(log_file, f"attempt={attempt+1} parse_error={exc}")
                _log(log_file, f"attempt={attempt+1} raw_output={_redact_text(output)}")
                extra_instruction = f"\n\nfix JSON to match schema exactly. Previous validation error: {str(exc)[:180]}"

    if parsed is None:
        _log(log_file, "llm_parse_failed_using_local_mock_fallback=1")
        parsed = _build_local_mock_result(dq_report)
        used_fallback = True
        model_name = "deterministic_local"
        fallback_reason = "llm_parse_failed"
        fallback_stage = "parse_validate"
        fallback_tier_value = "deterministic"
        provisional_local_fallback = True
        needs_cloud_reconciliation = True

    if retry_policy is not None and llm_attempted:
        retry_state = register_retry_outcome(
            run_id,
            retry_policy,
            success=bool(llm_success),
            failure_reason=(fallback_reason or "llm_parse_failed"),
        )
        write_retry_guard_report(
            run_id,
            status="PASS" if llm_success else "FAIL",
            reason=("ok:run_captain_sanity_llm" if llm_success else f"{fallback_reason or 'llm_failed'}:run_captain_sanity_llm"),
            retry_policy=retry_policy,
            state=retry_state,
        )

    parsed, dropped_unproven_novel = drop_unproven_novel_issues(parsed)
    if dropped_unproven_novel:
        repair_actions_total.append(f"dropped_unproven_novel_issues:{dropped_unproven_novel}")
    eval_metrics = _compute_eval_metrics(
        dq_report,
        parsed,
        allow_novel_issues=allow_novel_issues,
        dropped_unproven_novel=dropped_unproven_novel,
    )
    visible_reasoning_trace, trace_meta = build_visible_reasoning_trace_advisory(
        enabled=bool(feature_flags.get("ENABLE_VISIBLE_REASONING_TRACE", 0)),
        trace_builder=lambda: _build_visible_reasoning_trace(
            run_id=run_id,
            result=parsed,
            eval_metrics=eval_metrics,
            enabled=True,
        ),
        trace_prefix=f"captain:{run_id}",
        redact_text=_redact_text,
    )
    if not eval_metrics["safety"]:
        parsed["verdict"] = "FAIL"
    elif eval_metrics["target_warn_fail_count"] > 0:
        if eval_metrics["issue_coverage"] < 0.6 or not eval_metrics["no_extra_issues"]:
            if parsed["verdict"] == "PASS":
                parsed["verdict"] = "WARN"

    out_dir = Path("data/llm_reports")
    out_dir.mkdir(parents=True, exist_ok=True)

    enriched = {
        "generated_by": "scripts/run_captain_sanity_llm.py",
        "contract_version": "captain_sanity.v1",
        "schema_version": "captain_sanity_output.v1",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend": args.backend,
        "model": model_name,
        "fallback_used": used_fallback,
        "fallback_tier": fallback_tier_value,
        "fallback_reason": fallback_reason,
        "provisional_local_fallback": provisional_local_fallback,
        "needs_cloud_reconciliation": needs_cloud_reconciliation,
        "llm_provenance": {
            "backend_requested": args.backend,
            "remote_allowed": (os.getenv("LLM_ALLOW_REMOTE", "0") == "1"),
            "model": model_name,
            "selected_model_before_fallback": selected_model_name,
            "attempted_llm_path": bool(selected_model_name and selected_model_name not in {"local_mock", "deterministic_local"}),
            "used_fallback": used_fallback,
            "fallback_reason": fallback_reason,
            "fallback_stage": fallback_stage,
            "fallback_tier": fallback_tier_value,
            "provisional_local_fallback": provisional_local_fallback,
            "needs_cloud_reconciliation": needs_cloud_reconciliation,
            "runtime_failover_attempts": runtime_failover_attempts,
            "repair_actions": sorted({x for x in repair_actions_total if str(x).strip()})[:20],
            "feature_flags": feature_flags,
            "visible_reasoning_trace": trace_meta,
            "domain_template": {
                "template_id": domain_cfg.get("template_id"),
                "domain": domain_cfg.get("domain"),
                "source_path": domain_cfg.get("source_path"),
            },
            "obfuscation_map_refs": sorted({x for x in obfuscation_map_refs if str(x).strip()}),
        },
        "result": parsed,
        "visible_reasoning_trace": visible_reasoning_trace,
        "eval_metrics": eval_metrics,
    }

    redacted_enriched = _redact_obj(enriched)
    md = _render_markdown(run_id, model_name, parsed, eval_metrics)
    redacted_md = _redact_text(md)

    out_json = out_dir / f"{run_id}_captain.json"
    out_json.write_text(json.dumps(redacted_enriched, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out_json)
    (out_dir / f"{run_id}_captain.md").write_text(redacted_md, encoding="utf-8")


if __name__ == "__main__":
    main()
