#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("expected_object")
    return payload


def _as_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _compute_rates(summary: dict[str, Any]) -> dict[str, int | float]:
    records = summary.get("records")
    if not isinstance(records, list):
        records = []
    risky = _as_int(summary.get("risky_cases"), default=0)
    safe = _as_int(summary.get("safe_cases"), default=0)
    if risky <= 0:
        risky = sum(1 for r in records if isinstance(r, dict) and bool(r.get("expected_block")))
    if safe <= 0:
        safe = sum(1 for r in records if isinstance(r, dict) and not bool(r.get("expected_block")))

    fn = 0
    fp = 0
    for row in records:
        if not isinstance(row, dict):
            continue
        expected_block = bool(row.get("expected_block"))
        predicted_block = bool(row.get("predicted_block"))
        if expected_block and not predicted_block:
            fn += 1
        if (not expected_block) and predicted_block:
            fp += 1

    fnr = (fn / risky) if risky > 0 else 0.0
    fpr = (fp / safe) if safe > 0 else 0.0
    return {
        "risky": risky,
        "safe": safe,
        "fn": fn,
        "fp": fp,
        "fnr_pct": round(fnr * 100, 2),
        "fpr_pct": round(fpr * 100, 2),
    }


def _claim_candidates(md_text: str, *, metric: str, require_canonical_phrase: bool = True) -> list[str]:
    if require_canonical_phrase:
        key_pat = r"risky\s+approved" if metric == "fnr" else r"safe\s+blocked"
        pattern = re.compile(rf"\b{metric}\b.*{key_pat}", re.IGNORECASE)
    else:
        pattern = re.compile(rf"\b{metric}\b", re.IGNORECASE)
    return [line.strip() for line in md_text.splitlines() if pattern.search(line)]


def _extract_pct_and_ratio(line: str) -> tuple[float, int, int]:
    pct_match = re.search(r"(\d+(?:\.\d+)?)\s*%", line)
    ratio_match = re.search(r"(\d+)\s*/\s*(\d+)", line)
    if not ratio_match:
        ratio_match = re.search(r"(\d+)\s+of\s+(\d+)", line, flags=re.IGNORECASE)
    if not pct_match or not ratio_match:
        raise ValueError("cannot_parse_line")
    return float(pct_match.group(1)), int(ratio_match.group(1)), int(ratio_match.group(2))


def _validate_claim_block(
    *,
    doc_name: str,
    metric: str,
    md_text: str,
    expected_num: int,
    expected_den: int,
    expected_pct: float,
    issues: list[str],
    require_canonical_phrase: bool = True,
) -> None:
    lines = _claim_candidates(md_text, metric=metric, require_canonical_phrase=require_canonical_phrase)
    if not lines:
        issues.append(f"missing_claim_line:{doc_name}:{metric}")
        return

    parsed: list[tuple[str, float, int, int]] = []
    for line in lines:
        try:
            pct, num, den = _extract_pct_and_ratio(line)
        except Exception:
            continue
        parsed.append((line, pct, num, den))

    if not parsed:
        issues.append(f"ratio_mismatch:{doc_name}:{metric}:missing_or_unparseable_ratio")
        return

    exact_ratio = [item for item in parsed if item[2] == expected_num and item[3] == expected_den]
    if not exact_ratio:
        first = parsed[0]
        issues.append(
            f"ratio_mismatch:{doc_name}:{metric}:actual={first[2]}/{first[3]}:expected={expected_num}/{expected_den}"
        )
        return

    pct_actual = exact_ratio[0][1]
    if abs(pct_actual - expected_pct) > 0.01:
        issues.append(
            f"ratio_mismatch:{doc_name}:{metric}:pct_actual={pct_actual}:pct_expected={expected_pct}"
        )


def _check_readme(readme_path: Path, expected: dict[str, int | float], issues: list[str]) -> None:
    text = readme_path.read_text(encoding="utf-8")
    _validate_claim_block(
        doc_name="readme",
        metric="fnr",
        md_text=text,
        expected_num=int(expected["fn"]),
        expected_den=int(expected["risky"]),
        expected_pct=float(expected["fnr_pct"]),
        issues=issues,
    )
    _validate_claim_block(
        doc_name="readme",
        metric="fpr",
        md_text=text,
        expected_num=int(expected["fp"]),
        expected_den=int(expected["safe"]),
        expected_pct=float(expected["fpr_pct"]),
        issues=issues,
    )


def _check_agent_eval_definitions(agent_eval_path: Path, issues: list[str]) -> None:
    text = agent_eval_path.read_text(encoding="utf-8")

    has_fnr = re.search(
        r"False\s+Negative\s+Rate[^\n]*risky[^\n]*approved[^\n]*blocked",
        text,
        flags=re.IGNORECASE,
    )
    has_fpr = re.search(
        r"False\s+Positive\s+Rate[^\n]*safe[^\n]*blocked[^\n]*approved",
        text,
        flags=re.IGNORECASE,
    )
    if not has_fnr:
        issues.append("missing_claim_line:agent_eval:fnr_definition")
    if not has_fpr:
        issues.append("missing_claim_line:agent_eval:fpr_definition")

    inverted_patterns = [
        r"False\s+Positive\s+Rate[^\n]*(aggressive\s+decision\s+when\s+risk\s+was\s+present)",
        r"False\s+Negative\s+Rate[^\n]*(HOLD\s+decision\s+when\s+rollout\s+was\s+actually\s+safe)",
        r"FPR\s*\(aggressive\s+decision\s+on\s+risk",
        r"FNR\s*\(blocked\s+safe\s+iteration",
    ]
    for pat in inverted_patterns:
        if re.search(pat, text, flags=re.IGNORECASE):
            issues.append(f"definition_inverted:agent_eval:{pat}")


def _check_evaluation_report(
    report_path: Path | None,
    expected: dict[str, int | float],
    issues: list[str],
) -> str:
    if report_path is None:
        return "evaluation_report=SKIP source_missing:not_provided"
    if not report_path.exists():
        return f"evaluation_report=SKIP source_missing:{report_path}"

    text = report_path.read_text(encoding="utf-8")
    _validate_claim_block(
        doc_name="evaluation_report",
        metric="fnr",
        md_text=text,
        expected_num=int(expected["fn"]),
        expected_den=int(expected["risky"]),
        expected_pct=float(expected["fnr_pct"]),
        issues=issues,
        require_canonical_phrase=False,
    )
    _validate_claim_block(
        doc_name="evaluation_report",
        metric="fpr",
        md_text=text,
        expected_num=int(expected["fp"]),
        expected_den=int(expected["safe"]),
        expected_pct=float(expected["fpr_pct"]),
        issues=issues,
        require_canonical_phrase=False,
    )
    return "evaluation_report=CHECKED"


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed check for public metric claim consistency.")
    parser.add_argument("--batch-summary", default="examples/investor_demo/reports_for_agents/batch_summary.json")
    parser.add_argument("--readme", default="README.md")
    parser.add_argument("--agent-eval", default="AGENT_EVAL.md")
    parser.add_argument("--evaluation-report", default="EVALUATION_REPORT.md")
    args = parser.parse_args()

    summary_path = Path(args.batch_summary)
    readme_path = Path(args.readme)
    agent_eval_path = Path(args.agent_eval)
    eval_report_path = Path(args.evaluation_report) if args.evaluation_report else None

    issues: list[str] = []
    for name, path in (("batch_summary", summary_path), ("readme", readme_path), ("agent_eval", agent_eval_path)):
        if not path.exists():
            issues.append(f"source_missing:{name}:{path}")
    if issues:
        print("claim_consistency=FAIL")
        for item in issues:
            print(f"- {item}")
        raise SystemExit(1)

    try:
        summary = _load_json(summary_path)
    except Exception as exc:
        print("claim_consistency=FAIL")
        print(f"- source_missing:batch_summary:invalid_json:{summary_path}:{exc}")
        raise SystemExit(1) from exc

    expected = _compute_rates(summary)

    _check_readme(readme_path, expected, issues)
    _check_agent_eval_definitions(agent_eval_path, issues)
    eval_report_status = _check_evaluation_report(eval_report_path, expected, issues)

    if issues:
        print("claim_consistency=FAIL")
        print(eval_report_status)
        for item in issues:
            print(f"- {item}")
        raise SystemExit(1)

    print(eval_report_status)
    print(
        "claim_consistency=PASS "
        f"fnr={expected['fnr_pct']}% ({expected['fn']}/{expected['risky']}) "
        f"fpr={expected['fpr_pct']}% ({expected['fp']}/{expected['safe']})"
    )


if __name__ == "__main__":
    main()
