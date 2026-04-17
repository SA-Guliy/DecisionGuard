#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from src.batch_summary_freshness import fresh_runtime_summary_issues as _fresh_runtime_summary_issues_impl
except Exception:
    _fresh_runtime_summary_issues_impl = None
from src.security_utils import verify_sha256_sidecar

DEFAULT_POLICY_PATH = ROOT / "configs/contracts/public_claims_policy_v1.json"

ERR_BENCH_MISSING = "PUBLIC_CLAIM_BENCHMARK_MISSING"
ERR_SOURCE_MISSING = "PUBLIC_CLAIM_SOURCE_MISSING"
ERR_RATIO_MISMATCH = "PUBLIC_CLAIM_RATIO_MISMATCH"
ERR_PCT_MISMATCH = "PUBLIC_CLAIM_PCT_MISMATCH"
ERR_COVERAGE = "PUBLIC_CLAIM_COVERAGE_INCOMPLETE"
ERR_ASOF_MISMATCH = "PUBLIC_CLAIM_AS_OF_DATE_MISMATCH"
ERR_SOURCE_NOT_FRESH = "PUBLIC_CLAIM_SOURCE_NOT_FRESH_RUNTIME"

ERR_POLICY_XY = "PUBLIC_CLAIM_POLICY_REQUIRE_X_OVER_Y"
ERR_POLICY_BENCH = "PUBLIC_CLAIM_POLICY_REQUIRE_BENCHMARK_REFERENCE"
ERR_POLICY_ASOF = "PUBLIC_CLAIM_POLICY_REQUIRE_AS_OF_DATE"
ERR_POLICY_BARE = "PUBLIC_CLAIM_POLICY_BARE_PERCENTAGE_FORBIDDEN"
ERR_DEFINITION_INVERTED = "METRIC_DEFINITION_INVERTED"


@dataclass
class Claim:
    doc_name: str
    benchmark_id: str | None
    metric: str
    as_of_date: str | None
    pct: float | None
    num: int | None
    den: int | None
    is_na: bool
    line_no: int


@dataclass
class ExpectedBenchmark:
    benchmark_id: str
    source_summary: str
    as_of_date: str
    risky: int
    safe: int
    fn: int
    fp_non_go: int
    fp_stop_only: int
    fnr_pct: float
    fpr_non_go_pct: float | None
    fpr_stop_only_pct: float | None


def _resolve(path_like: str | Path) -> Path:
    p = Path(path_like)
    return p if p.is_absolute() else (ROOT / p)


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"invalid_json_object:{path}")
    return payload


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _date_from_iso(value: Any, fallback: str) -> str:
    text = str(value or "").strip()
    m = re.match(r"(\d{4}-\d{2}-\d{2})", text)
    return m.group(1) if m else fallback


def _extract_claim_metadata(text: str) -> tuple[str | None, str | None]:
    benchmark_m = re.search(r"benchmark_id\s*=\s*([A-Za-z0-9_\-]+)", text)
    asof_m = re.search(r"as_of_date\s*=\s*(\d{4}-\d{2}-\d{2})", text)
    return (benchmark_m.group(1) if benchmark_m else None, asof_m.group(1) if asof_m else None)


def _compute_rates(payload: dict[str, Any]) -> dict[str, Any]:
    records = payload.get("records")
    if not isinstance(records, list):
        records = []

    risky = _as_int(payload.get("risky_cases"), 0)
    safe = _as_int(payload.get("safe_cases"), 0)
    if risky <= 0:
        risky = sum(1 for r in records if isinstance(r, dict) and bool(r.get("expected_block")))
    if safe <= 0:
        safe = sum(1 for r in records if isinstance(r, dict) and not bool(r.get("expected_block")))

    fn = 0
    fp_non_go = 0
    fp_stop_only = 0
    for row in records:
        if not isinstance(row, dict):
            continue
        expected_block = bool(row.get("expected_block"))
        decision = str(row.get("decision", "")).strip().upper()
        predicted_block = bool(row.get("predicted_block")) if "predicted_block" in row else (decision != "GO")
        if expected_block and not predicted_block:
            fn += 1
        if (not expected_block) and predicted_block:
            fp_non_go += 1
        if (not expected_block) and decision == "STOP_ROLLOUT":
            fp_stop_only += 1

    return {
        "risky": risky,
        "safe": safe,
        "fn": fn,
        "fp_non_go": fp_non_go,
        "fp_stop_only": fp_stop_only,
        "fnr_pct": _pct(fn, risky),
        "fpr_non_go_pct": _pct(fp_non_go, safe),
        "fpr_stop_only_pct": _pct(fp_stop_only, safe),
    }


def _compute_from_records(payload: dict[str, Any], *, fallback_date: str) -> tuple[str, int, int, int, int, int]:
    rates = _compute_rates(payload)
    as_of = _date_from_iso(payload.get("generated_at"), fallback_date)
    return (
        as_of,
        int(rates["risky"]),
        int(rates["safe"]),
        int(rates["fn"]),
        int(rates["fp_non_go"]),
        int(rates["fp_stop_only"]),
    )


def _compute_from_adversarial(
    payload: dict[str, Any],
    *,
    fallback_date: str,
    registry_n_risky: int,
    registry_n_safe: int,
) -> tuple[str, int, int, int, int, int]:
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list):
        scenarios = []

    risky = registry_n_risky if registry_n_risky > 0 else len(scenarios)
    safe = registry_n_safe if registry_n_safe > 0 else 0

    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    fn = _as_int(summary.get("fail_count"), -1)
    if fn < 0:
        fn = sum(1 for s in scenarios if isinstance(s, dict) and str(s.get("status", "")).upper() == "FAIL")

    fp_non_go = 0
    fp_stop_only = 0
    as_of = _date_from_iso(payload.get("generated_at"), fallback_date)
    return as_of, risky, safe, fn, fp_non_go, fp_stop_only


def _pct(num: int, den: int) -> float | None:
    if den <= 0:
        return None
    return round((num / den) * 100.0, 2)


def _builtin_strict_policy() -> dict[str, Any]:
    return {
        "require_x_over_y": True,
        "require_benchmark_reference": True,
        "require_as_of_date": True,
        "allow_bare_percentages": False,
    }


def _is_git_tracked(path: Path) -> bool:
    try:
        rel = path.resolve().relative_to(ROOT.resolve())
    except Exception:
        return False
    proc = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(rel)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def _load_policy(path: Path) -> tuple[dict[str, Any], str]:
    strict = _builtin_strict_policy()
    if not path.exists():
        return strict, "builtin_strict:policy_missing"
    if not _is_git_tracked(path):
        return strict, "builtin_strict:policy_untracked"
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        return strict, f"builtin_strict:policy_integrity:{reason}"
    try:
        payload = _load_json(path)
    except Exception as exc:
        return strict, f"builtin_strict:policy_invalid_json:{exc}"
    policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
    if not policy:
        return strict, "builtin_strict:policy_missing_policy_object"
    return policy, "file_policy"


def _load_expected_from_prd_sot(prd_sot_path: Path, issues: list[str]) -> dict[str, ExpectedBenchmark]:
    ok, reason = verify_sha256_sidecar(prd_sot_path, required=True)
    if not ok:
        issues.append(f"{ERR_SOURCE_MISSING}:prd_sot_integrity:{reason}")
        return {}
    try:
        sot = _load_json(prd_sot_path)
    except Exception:
        issues.append(f"{ERR_SOURCE_MISSING}:prd_sot_invalid_json:{prd_sot_path}")
        return {}

    fallback_date = str(sot.get("as_of_date", "")).strip() or "1970-01-01"
    registry = sot.get("benchmark_registry")
    if not isinstance(registry, list) or not registry:
        issues.append(f"{ERR_SOURCE_MISSING}:benchmark_registry_missing:{prd_sot_path}")
        return {}

    out: dict[str, ExpectedBenchmark] = {}
    for row in registry:
        if not isinstance(row, dict):
            continue
        benchmark_id = str(row.get("benchmark_id", "")).strip()
        source_rel = str(row.get("source_summary", "")).strip()
        if not benchmark_id:
            continue
        if not source_rel:
            issues.append(f"{ERR_SOURCE_MISSING}:{benchmark_id}:source_summary_empty")
            continue

        source_path = _resolve(source_rel)
        if not source_path.exists():
            issues.append(f"{ERR_SOURCE_MISSING}:{benchmark_id}:{source_rel}")
            continue
        ok_source, reason_source = verify_sha256_sidecar(source_path, required=True)
        if not ok_source:
            issues.append(f"{ERR_SOURCE_MISSING}:{benchmark_id}:integrity:{reason_source}:{source_rel}")
            continue

        try:
            payload = _load_json(source_path)
        except Exception:
            issues.append(f"{ERR_SOURCE_MISSING}:{benchmark_id}:invalid_json:{source_rel}")
            continue

        if isinstance(payload.get("records"), list):
            require_fresh_runtime = bool(row.get("requires_fresh_runtime", False)) or benchmark_id.startswith("mass_")
            if require_fresh_runtime:
                freshness_issues = _fresh_runtime_summary_issues(payload)
                if freshness_issues:
                    for reason in freshness_issues:
                        issues.append(f"{ERR_SOURCE_NOT_FRESH}:{benchmark_id}:{reason}:{source_rel}")
                    continue
            as_of, risky, safe, fn, fp_non_go, fp_stop_only = _compute_from_records(payload, fallback_date=fallback_date)
        elif isinstance(payload.get("scenarios"), list):
            as_of, risky, safe, fn, fp_non_go, fp_stop_only = _compute_from_adversarial(
                payload,
                fallback_date=fallback_date,
                registry_n_risky=_as_int(row.get("n_risky"), 0),
                registry_n_safe=_as_int(row.get("n_safe"), 0),
            )
        else:
            issues.append(f"{ERR_SOURCE_MISSING}:{benchmark_id}:unsupported_source_shape:{source_rel}")
            continue

        out[benchmark_id] = ExpectedBenchmark(
            benchmark_id=benchmark_id,
            source_summary=source_rel,
            as_of_date=as_of,
            risky=risky,
            safe=safe,
            fn=fn,
            fp_non_go=fp_non_go,
            fp_stop_only=fp_stop_only,
            fnr_pct=_pct(fn, risky) or 0.0,
            fpr_non_go_pct=_pct(fp_non_go, safe),
            fpr_stop_only_pct=_pct(fp_stop_only, safe),
        )

    return out


def _fresh_runtime_summary_issues(payload: dict[str, Any]) -> list[str]:
    if _fresh_runtime_summary_issues_impl is not None:
        return _fresh_runtime_summary_issues_impl(payload)

    # Local fail-closed fallback for branches where src/batch_summary_freshness.py is not tracked.
    issues: list[str] = []
    if str(payload.get("benchmark_origin", "")).strip() != "fresh_runtime":
        issues.append("benchmark_origin_not_fresh_runtime")
    if str(payload.get("generated_by", "")).strip() != "scripts/run_batch_eval.py":
        issues.append("generated_by_not_run_batch_eval")
    if bool(payload.get("legacy_upgraded", False)):
        issues.append("legacy_upgraded_true")
    if not bool(payload.get("records_quality_complete", False)):
        issues.append("records_quality_computed_false")
    return issues


def _load_expected_from_batch_override(path: Path, issues: list[str]) -> dict[str, ExpectedBenchmark]:
    if not path.exists():
        issues.append(f"{ERR_SOURCE_MISSING}:batch_override:{path}")
        return {}
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        issues.append(f"{ERR_SOURCE_MISSING}:batch_override_integrity:{reason}:{path}")
        return {}
    try:
        payload = _load_json(path)
    except Exception:
        issues.append(f"{ERR_SOURCE_MISSING}:batch_override_invalid_json:{path}")
        return {}

    benchmark_id = str(payload.get("batch_id", "")).strip() or "batch_override"
    if isinstance(payload.get("records"), list):
        freshness_issues = _fresh_runtime_summary_issues(payload)
        if freshness_issues:
            for reason in freshness_issues:
                issues.append(f"{ERR_SOURCE_NOT_FRESH}:{benchmark_id}:{reason}:{path}")
            return {}
    as_of, risky, safe, fn, fp_non_go, fp_stop_only = _compute_from_records(payload, fallback_date="1970-01-01")
    return {
        benchmark_id: ExpectedBenchmark(
            benchmark_id=benchmark_id,
            source_summary=str(path),
            as_of_date=as_of,
            risky=risky,
            safe=safe,
            fn=fn,
            fp_non_go=fp_non_go,
            fp_stop_only=fp_stop_only,
            fnr_pct=_pct(fn, risky) or 0.0,
            fpr_non_go_pct=_pct(fp_non_go, safe),
            fpr_stop_only_pct=_pct(fp_stop_only, safe),
        )
    }


def _metric_kind(line: str) -> str | None:
    upper = line.upper()
    if "FNR" in upper:
        return "fnr"
    if "FPR" in upper:
        if re.search(r"stop[-_ ]?only", line, flags=re.IGNORECASE):
            return "fpr_stop_only"
        return "fpr_non_go"
    return None


def _iter_claim_segments(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped:
        return []
    if "|" not in stripped:
        return [stripped]
    if re.fullmatch(r"[\|\-:\s]+", stripped):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|") if cell.strip()]


def _iter_metric_parts(text: str) -> list[tuple[str, str]]:
    tokens = list(re.finditer(r"(?i)\b(?:FNR|FPR)\b", text))
    if not tokens:
        return []
    out: list[tuple[str, str]] = []
    for idx, match in enumerate(tokens):
        start = match.start()
        end = tokens[idx + 1].start() if idx + 1 < len(tokens) else len(text)
        fragment = text[start:end].strip(" ,;")
        kind = _metric_kind(fragment)
        if kind:
            out.append((kind, fragment))
    return out


def _parse_claims(doc_name: str, path: Path, policy: dict[str, Any], issues: list[str]) -> list[Claim]:
    text = path.read_text(encoding="utf-8")
    claims: list[Claim] = []

    require_xy = bool(policy.get("require_x_over_y", False))
    require_bench = bool(policy.get("require_benchmark_reference", False))
    require_asof = bool(policy.get("require_as_of_date", False))
    allow_bare_pct = bool(policy.get("allow_bare_percentages", True))

    for idx, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        line_norm = line.replace("`", "").replace("**", "")
        line_bench, line_asof = _extract_claim_metadata(line_norm)
        segments = _iter_claim_segments(raw_line)

        for seg in segments:
            normalized = seg.replace("`", "").replace("**", "")
            metric_parts = _iter_metric_parts(normalized)
            if not metric_parts:
                continue
            seg_bench, seg_asof = _extract_claim_metadata(normalized)
            benchmark_fallback = seg_bench or line_bench
            asof_fallback = seg_asof or line_asof
            if not benchmark_fallback and not asof_fallback:
                # Ignore narrative mentions (e.g., glossary text) and only govern explicit machine-claims.
                continue

            for kind, fragment in metric_parts:
                ratio_m = re.search(r"(\d+)\s*/\s*(\d+)", fragment)
                pct_m = re.search(r"(\d+(?:\.\d+)?)\s*%", fragment)
                na_m = re.search(r"\bN/?A\b", fragment, flags=re.IGNORECASE)
                if not ratio_m and not pct_m and not na_m:
                    continue

                num = int(ratio_m.group(1)) if ratio_m else None
                den = int(ratio_m.group(2)) if ratio_m else None
                pct = float(pct_m.group(1)) if pct_m else None
                is_na = bool(na_m)

                if require_bench and not benchmark_fallback:
                    issues.append(f"{ERR_POLICY_BENCH}:{doc_name}:{kind}:line={idx}")
                    issues.append(f"{ERR_BENCH_MISSING}:{doc_name}:{kind}:line={idx}")
                if require_asof and not asof_fallback:
                    issues.append(f"{ERR_POLICY_ASOF}:{doc_name}:{kind}:line={idx}")
                if require_xy and not ratio_m and not is_na:
                    issues.append(f"{ERR_POLICY_XY}:{doc_name}:{kind}:line={idx}")
                if (not allow_bare_pct) and pct_m and not ratio_m and not is_na:
                    issues.append(f"{ERR_POLICY_BARE}:{doc_name}:{kind}:line={idx}")

                claims.append(
                    Claim(
                        doc_name=doc_name,
                        benchmark_id=benchmark_fallback,
                        metric=kind,
                        as_of_date=asof_fallback,
                        pct=pct,
                        num=num,
                        den=den,
                        is_na=is_na,
                        line_no=idx,
                    )
                )

    return claims


def _detect_metric_definition_inversion(*, doc_name: str, path: Path, issues: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if re.search(
        r"\bFPR\b\s*(?:\(|:|—|-)\s*(?:risky approved|aggressive on risk)\b",
        text,
        flags=re.IGNORECASE,
    ):
        issues.append(f"{ERR_DEFINITION_INVERTED}:{doc_name}:fpr_points_to_risky_approved")
    if re.search(
        r"\bFNR\b\s*(?:\(|:|—|-)\s*(?:blocked safe|safe blocked)\b",
        text,
        flags=re.IGNORECASE,
    ):
        issues.append(f"{ERR_DEFINITION_INVERTED}:{doc_name}:fnr_points_to_safe_blocked")


def _select_claim(claims: list[Claim], benchmark_id: str, metric: str) -> Claim | None:
    for claim in claims:
        if claim.benchmark_id == benchmark_id and claim.metric == metric:
            return claim
    return None


def _validate_doc_claims(
    *,
    doc_name: str,
    claims: list[Claim],
    expected: dict[str, ExpectedBenchmark],
    issues: list[str],
    require_full_coverage: bool,
    allow_unknown_benchmark_claims: bool = False,
) -> None:
    def _check_as_of(claim: Claim, exp: ExpectedBenchmark) -> None:
        if claim.as_of_date is not None and claim.as_of_date != exp.as_of_date:
            issues.append(
                f"{ERR_ASOF_MISMATCH}:{doc_name}:{exp.benchmark_id}:{claim.metric}:actual={claim.as_of_date}:expected={exp.as_of_date}"
            )

    if require_full_coverage:
        for benchmark_id, exp in expected.items():
            fnr_claim = _select_claim(claims, benchmark_id, "fnr")
            if not fnr_claim:
                issues.append(f"{ERR_COVERAGE}:{doc_name}:{benchmark_id}:fnr")
            else:
                _check_as_of(fnr_claim, exp)
                if fnr_claim.num is None or fnr_claim.den is None:
                    issues.append(f"{ERR_RATIO_MISMATCH}:{doc_name}:{benchmark_id}:fnr:missing_ratio")
                else:
                    if fnr_claim.num != exp.fn or fnr_claim.den != exp.risky:
                        issues.append(
                            f"{ERR_RATIO_MISMATCH}:{doc_name}:{benchmark_id}:fnr:actual={fnr_claim.num}/{fnr_claim.den}:expected={exp.fn}/{exp.risky}"
                        )
                if fnr_claim.pct is None:
                    issues.append(f"{ERR_PCT_MISMATCH}:{doc_name}:{benchmark_id}:fnr:missing_pct")
                elif abs(fnr_claim.pct - exp.fnr_pct) > 0.01:
                    issues.append(
                        f"{ERR_PCT_MISMATCH}:{doc_name}:{benchmark_id}:fnr:actual={fnr_claim.pct}:expected={exp.fnr_pct}"
                    )

            fpr_claim = _select_claim(claims, benchmark_id, "fpr_non_go")
            if exp.safe <= 0:
                if not fpr_claim:
                    issues.append(f"{ERR_COVERAGE}:{doc_name}:{benchmark_id}:fpr_non_go_na")
                else:
                    _check_as_of(fpr_claim, exp)
                    if not fpr_claim.is_na:
                        issues.append(f"{ERR_RATIO_MISMATCH}:{doc_name}:{benchmark_id}:fpr_non_go:expected=NA")
            else:
                if not fpr_claim:
                    issues.append(f"{ERR_COVERAGE}:{doc_name}:{benchmark_id}:fpr_non_go")
                else:
                    _check_as_of(fpr_claim, exp)
                    if fpr_claim.num is None or fpr_claim.den is None:
                        issues.append(f"{ERR_RATIO_MISMATCH}:{doc_name}:{benchmark_id}:fpr_non_go:missing_ratio")
                    elif fpr_claim.num != exp.fp_non_go or fpr_claim.den != exp.safe:
                        issues.append(
                            f"{ERR_RATIO_MISMATCH}:{doc_name}:{benchmark_id}:fpr_non_go:actual={fpr_claim.num}/{fpr_claim.den}:expected={exp.fp_non_go}/{exp.safe}"
                        )
                    if fpr_claim.pct is None:
                        issues.append(f"{ERR_PCT_MISMATCH}:{doc_name}:{benchmark_id}:fpr_non_go:missing_pct")
                    elif exp.fpr_non_go_pct is not None and abs(fpr_claim.pct - exp.fpr_non_go_pct) > 0.01:
                        issues.append(
                            f"{ERR_PCT_MISMATCH}:{doc_name}:{benchmark_id}:fpr_non_go:actual={fpr_claim.pct}:expected={exp.fpr_non_go_pct}"
                        )
    else:
        # For non-coverage docs (scorecard), validate any declared benchmark claims against expected.
        for claim in claims:
            if not claim.benchmark_id:
                continue
            exp = expected.get(claim.benchmark_id)
            if not exp:
                if allow_unknown_benchmark_claims:
                    continue
                issues.append(f"{ERR_BENCH_MISSING}:{doc_name}:{claim.metric}:{claim.benchmark_id}")
                continue
            _check_as_of(claim, exp)
            if claim.metric == "fnr":
                if claim.num is None or claim.den is None:
                    issues.append(f"{ERR_RATIO_MISMATCH}:{doc_name}:{exp.benchmark_id}:fnr:missing_ratio")
                elif claim.num != exp.fn or claim.den != exp.risky:
                    issues.append(
                        f"{ERR_RATIO_MISMATCH}:{doc_name}:{exp.benchmark_id}:fnr:actual={claim.num}/{claim.den}:expected={exp.fn}/{exp.risky}"
                    )
                if claim.pct is None or abs(claim.pct - exp.fnr_pct) > 0.01:
                    issues.append(
                        f"{ERR_PCT_MISMATCH}:{doc_name}:{exp.benchmark_id}:fnr:actual={claim.pct}:expected={exp.fnr_pct}"
                    )
            elif claim.metric == "fpr_non_go":
                if exp.safe <= 0:
                    if not claim.is_na:
                        issues.append(f"{ERR_RATIO_MISMATCH}:{doc_name}:{exp.benchmark_id}:fpr_non_go:expected=NA")
                else:
                    if claim.num is None or claim.den is None:
                        issues.append(f"{ERR_RATIO_MISMATCH}:{doc_name}:{exp.benchmark_id}:fpr_non_go:missing_ratio")
                    elif claim.num != exp.fp_non_go or claim.den != exp.safe:
                        issues.append(
                            f"{ERR_RATIO_MISMATCH}:{doc_name}:{exp.benchmark_id}:fpr_non_go:actual={claim.num}/{claim.den}:expected={exp.fp_non_go}/{exp.safe}"
                        )
                    if claim.pct is None or (exp.fpr_non_go_pct is not None and abs(claim.pct - exp.fpr_non_go_pct) > 0.01):
                        issues.append(
                            f"{ERR_PCT_MISMATCH}:{doc_name}:{exp.benchmark_id}:fpr_non_go:actual={claim.pct}:expected={exp.fpr_non_go_pct}"
                        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed check for public metric claim consistency.")
    parser.add_argument("--prd", default="PRD.md")
    parser.add_argument("--prd-sot", default="data/public_sot/prd_sot_v1.json")
    parser.add_argument("--batch-summary", default="", help="Backward-compatible single-summary override for tests.")
    parser.add_argument("--readme", default="README.md")
    parser.add_argument("--agent-eval", default="AGENT_EVAL.md")
    parser.add_argument("--evaluation-report", default="EVALUATION_REPORT.md")
    parser.add_argument("--scorecard", default="examples/investor_demo/reports_for_humans/executive_roi_scorecard.md")
    parser.add_argument("--strict-evaluation-report", type=int, choices=[0, 1], default=1)
    parser.add_argument("--policy", default=str(DEFAULT_POLICY_PATH))
    args = parser.parse_args()

    prd_sot_path = _resolve(args.prd_sot)
    policy_path = _resolve(args.policy)
    using_batch_override = bool(args.batch_summary.strip())

    issues: list[str] = []

    policy, policy_source = _load_policy(policy_path)
    print(f"policy_source={policy_source}")

    if using_batch_override:
        expected = _load_expected_from_batch_override(_resolve(args.batch_summary.strip()), issues)
    else:
        expected = _load_expected_from_prd_sot(prd_sot_path, issues)

    if not expected:
        if using_batch_override:
            has_primary_override_issue = any(
                issue.startswith(f"{ERR_SOURCE_MISSING}:batch_override")
                or issue.startswith(f"{ERR_SOURCE_NOT_FRESH}:")
                for issue in issues
            )
            if not has_primary_override_issue:
                issues.append(f"{ERR_SOURCE_MISSING}:expected_benchmarks_empty")
        else:
            issues.append(f"{ERR_SOURCE_MISSING}:expected_benchmarks_empty")

    readme_path = _resolve(args.readme)
    agent_eval_path = _resolve(args.agent_eval)
    scorecard_path = _resolve(args.scorecard)
    eval_report_path = _resolve(args.evaluation_report) if args.evaluation_report else None

    for name, path in (("readme", readme_path), ("agent_eval", agent_eval_path), ("scorecard", scorecard_path)):
        if not path.exists():
            issues.append(f"{ERR_SOURCE_MISSING}:{name}:{path}")

    if args.strict_evaluation_report == 1:
        if not eval_report_path or not eval_report_path.exists():
            issues.append(f"{ERR_SOURCE_MISSING}:evaluation_report:{eval_report_path}")

    if issues:
        print("claim_consistency=FAIL")
        for issue in issues:
            print(f"- {issue}")
        raise SystemExit(1)

    _detect_metric_definition_inversion(doc_name="readme", path=readme_path, issues=issues)
    _detect_metric_definition_inversion(doc_name="agent_eval", path=agent_eval_path, issues=issues)
    _detect_metric_definition_inversion(doc_name="scorecard", path=scorecard_path, issues=issues)
    if eval_report_path and eval_report_path.exists():
        _detect_metric_definition_inversion(doc_name="evaluation_report", path=eval_report_path, issues=issues)

    readme_claims = _parse_claims("readme", readme_path, policy, issues)
    agent_eval_claims = _parse_claims("agent_eval", agent_eval_path, policy, issues)
    scorecard_claims = _parse_claims("scorecard", scorecard_path, policy, issues)

    eval_report_claims: list[Claim] = []
    eval_report_status = "evaluation_report=SKIP"
    if eval_report_path and eval_report_path.exists():
        eval_report_claims = _parse_claims("evaluation_report", eval_report_path, policy, issues)
        eval_report_status = "evaluation_report=CHECKED"
    elif args.strict_evaluation_report == 0:
        eval_report_status = "evaluation_report=SKIP"

    _validate_doc_claims(
        doc_name="readme",
        claims=readme_claims,
        expected=expected,
        issues=issues,
        require_full_coverage=True,
    )
    _validate_doc_claims(
        doc_name="agent_eval",
        claims=agent_eval_claims,
        expected=expected,
        issues=issues,
        require_full_coverage=True,
    )
    if eval_report_claims:
        _validate_doc_claims(
            doc_name="evaluation_report",
            claims=eval_report_claims,
            expected=expected,
            issues=issues,
            require_full_coverage=True,
        )
    _validate_doc_claims(
        doc_name="scorecard",
        claims=scorecard_claims,
        expected=expected,
        issues=issues,
        require_full_coverage=False,
        allow_unknown_benchmark_claims=using_batch_override,
    )

    if issues:
        print("claim_consistency=FAIL")
        print(eval_report_status)
        for issue in issues:
            print(f"- {issue}")
        raise SystemExit(1)

    print(eval_report_status)
    for bench_id in sorted(expected):
        exp = expected[bench_id]
        fpr_non_go = (
            f"{exp.fpr_non_go_pct}% ({exp.fp_non_go}/{exp.safe})"
            if exp.fpr_non_go_pct is not None
            else "N/A"
        )
        print(
            f"benchmark={bench_id} fnr={exp.fnr_pct}% ({exp.fn}/{exp.risky}) "
            f"fpr_non_go={fpr_non_go} as_of_date={exp.as_of_date}"
        )
    print("claim_consistency=PASS")


if __name__ == "__main__":
    main()
