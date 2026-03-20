from __future__ import annotations

import re
from typing import Any


_WORD_RE = re.compile(r"[a-zA-Z0-9_]+")
_HYP_RE_EN = re.compile(r"^\s*we believe that .+ will .+ because .+", re.IGNORECASE)
_HYP_RE_IF = re.compile(r"\bif\b.+\bthen\b.+\bbecause\b.+", re.IGNORECASE)
_HYP_RE_RU = re.compile(r"^\s*мы верим, что .+ потому что .+", re.IGNORECASE)
_NOVEL_CHECK_RE = re.compile(r"^novel::[a-z0-9][a-z0-9_-]{1,63}$")


def _tokens(text: str) -> set[str]:
    return {m.group(0).lower() for m in _WORD_RE.finditer(text)}


def is_novel_check_name(check_name: str) -> bool:
    return bool(_NOVEL_CHECK_RE.fullmatch(str(check_name or "").strip()))


def _has_non_empty_evidence_refs(issue: dict[str, Any]) -> bool:
    refs = issue.get("evidence_refs", [])
    if not isinstance(refs, list):
        return False
    return any(str(x).strip() for x in refs)


def drop_unproven_novel_issues(result: dict[str, Any]) -> tuple[dict[str, Any], int]:
    if not isinstance(result, dict):
        return {"verdict": "WARN", "issues": [], "recommendations": []}, 0
    issues = result.get("issues", [])
    if not isinstance(issues, list):
        issues = []
    dropped = 0
    kept: list[dict[str, Any]] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        check_name = str(issue.get("check_name", "")).strip()
        if is_novel_check_name(check_name) and not _has_non_empty_evidence_refs(issue):
            dropped += 1
            continue
        kept.append(issue)
    out = dict(result)
    out["issues"] = kept
    return out, dropped


def captain_semantic_score(
    dq_report: dict[str, Any],
    result: dict[str, Any],
    *,
    dropped_unproven_novel: int = 0,
) -> tuple[float, dict[str, float]]:
    dq_rows = dq_report.get("rows", [])
    if not isinstance(dq_rows, list):
        dq_rows = []
    msg_by_check = {
        str(r.get("check_name")): str(r.get("message", ""))
        for r in dq_rows
        if isinstance(r, dict) and r.get("check_name")
    }

    filtered_result, dropped_detected = drop_unproven_novel_issues(result)
    effective_dropped_unproven_novel = max(0, int(dropped_detected)) + max(0, int(dropped_unproven_novel or 0))
    issues = filtered_result.get("issues", [])
    if not isinstance(issues, list) or not issues:
        scores: dict[str, float] = {
            "issue_grounding_score": 0.0,
            "verification_quality_score": 0.0,
            "root_cause_specificity_score": 0.0,
            "novel_issue_proof_score": 0.0,
        }
        if effective_dropped_unproven_novel > 0:
            scores["dropped_unproven_novel_issues"] = float(effective_dropped_unproven_novel)
        return 0.0, scores

    grounded = 0
    verified = 0
    specific = 0
    proven_novel = 0
    total_novel = 0
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        check_name = str(issue.get("check_name", ""))
        msg = str(issue.get("message", ""))
        dq_msg = msg_by_check.get(check_name, "")
        overlap = len(_tokens(msg) & _tokens(dq_msg))
        if check_name in msg_by_check and overlap >= 2:
            grounded += 1
        if is_novel_check_name(check_name):
            total_novel += 1
            if _has_non_empty_evidence_refs(issue):
                grounded += 1
                proven_novel += 1
        steps = issue.get("verification_steps")
        if isinstance(steps, list):
            joined = " ".join(str(s) for s in steps).lower()
            if "select " in joined or "psql " in joined:
                verified += 1
        hypotheses = issue.get("hypotheses")
        if isinstance(hypotheses, list):
            htxt = " ".join(str(h) for h in hypotheses).lower()
            if any(k in htxt for k in ("because", "due to", "because of", "потому")):
                specific += 1

    n = max(1, len(issues))
    novel_proof_score = (proven_novel / total_novel) if total_novel else 1.0
    scores = {
        "issue_grounding_score": round(grounded / n, 4),
        "verification_quality_score": round(verified / n, 4),
        "root_cause_specificity_score": round(specific / n, 4),
        "novel_issue_proof_score": round(novel_proof_score, 4),
    }
    base = (
        0.45 * scores["issue_grounding_score"]
        + 0.25 * scores["verification_quality_score"]
        + 0.15 * scores["root_cause_specificity_score"]
        + 0.15 * scores["novel_issue_proof_score"]
    )
    if effective_dropped_unproven_novel > 0:
        # Hard penalty when unproven novel issues are produced.
        base *= 0.25
    final = round(base, 4)
    if effective_dropped_unproven_novel > 0:
        scores["dropped_unproven_novel_issues"] = float(effective_dropped_unproven_novel)
    return final, scores


def hypothesis_format_ok(statement: str) -> bool:
    s = (statement or "").strip()
    if not s:
        return False
    return bool(_HYP_RE_EN.search(s) or _HYP_RE_IF.search(s) or _HYP_RE_RU.search(s))
