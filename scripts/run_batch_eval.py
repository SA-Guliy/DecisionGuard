#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.generate_synthetic_history import build_batch_eval_cases
from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar


TRANSPORT_POLICY_PATH = ROOT / "configs/contracts/batch_record_transport_policy_v2.json"
BATCH_RECORD_CONTRACT_PATH = ROOT / "configs/contracts/batch_record_v2.json"
_TYPE_MAP: dict[str, type] = {
    "str": str,
    "bool": bool,
    "int": int,
    "float": (int, float),
    "dict": dict,
    "list": list,
}


def _ensure_groq_secrets() -> Path:
    secrets_path = Path(os.path.expanduser("~/.groq_secrets"))
    if not secrets_path.exists() or not secrets_path.is_file():
        raise SystemExit("ConfigurationError: Missing ~/.groq_secrets")
    values = dotenv_values(secrets_path)
    key = str(values.get("GROQ_API_KEY", "")).strip()
    if not key:
        raise SystemExit("ConfigurationError: GROQ_API_KEY is missing in ~/.groq_secrets")
    if not (key.startswith("gsk_") and len(key) >= 20):
        raise SystemExit("ConfigurationError: Invalid GROQ_API_KEY format in ~/.groq_secrets")
    return secrets_path


def _is_rate_limit_error(text: str) -> bool:
    t = str(text or "").lower()
    return (" 429" in t) or ("too many requests" in t) or ("rate limit" in t)


def _load_transport_policy_contract() -> dict[str, Any]:
    if not TRANSPORT_POLICY_PATH.exists():
        raise SystemExit(f"Missing transport policy contract: {TRANSPORT_POLICY_PATH}")
    ok, reason = verify_sha256_sidecar(TRANSPORT_POLICY_PATH, required=True)
    if not ok:
        raise SystemExit(f"Transport policy integrity error: {reason}")
    try:
        payload = json.loads(TRANSPORT_POLICY_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Invalid transport policy JSON: {TRANSPORT_POLICY_PATH}: {exc}") from exc
    policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
    if not bool(policy.get("batch_record_out_required", False)):
        raise SystemExit("Transport policy violation: batch_record_out_required must be true")
    if not bool(policy.get("stdout_ingest_forbidden", False)):
        raise SystemExit("Transport policy violation: stdout_ingest_forbidden must be true")
    return payload


def _load_batch_record_contract() -> dict[str, Any]:
    if not BATCH_RECORD_CONTRACT_PATH.exists():
        raise SystemExit(f"Missing batch record contract: {BATCH_RECORD_CONTRACT_PATH}")
    ok, reason = verify_sha256_sidecar(BATCH_RECORD_CONTRACT_PATH, required=True)
    if not ok:
        raise SystemExit(f"Batch record contract integrity error: {reason}")
    try:
        payload = json.loads(BATCH_RECORD_CONTRACT_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Invalid batch record contract JSON: {BATCH_RECORD_CONTRACT_PATH}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid batch record contract payload: {BATCH_RECORD_CONTRACT_PATH}")
    return payload


def _get_path_value(payload: dict[str, Any], path: str) -> Any:
    cur: Any = payload
    for key in str(path).split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _validate_batch_record_payload(record: dict[str, Any], contract: dict[str, Any]) -> None:
    expected_version = str(contract.get("record_version", "")).strip()
    if expected_version and str(record.get("version", "")).strip() != expected_version:
        raise RuntimeError(
            f"Batch record schema error: version mismatch expected={expected_version} actual={record.get('version')}"
        )
    required_top = contract.get("required_top_level", [])
    if isinstance(required_top, list):
        missing = [k for k in required_top if k not in record]
        if missing:
            raise RuntimeError(f"Batch record schema error: missing_top_level={','.join(missing)}")
    required_nested = contract.get("required_nested", {})
    if isinstance(required_nested, dict):
        for parent, fields in required_nested.items():
            node = record.get(parent)
            if not isinstance(node, dict):
                raise RuntimeError(f"Batch record schema error: nested_parent_not_dict={parent}")
            if isinstance(fields, list):
                missing_nested = [k for k in fields if k not in node]
                if missing_nested:
                    raise RuntimeError(
                        f"Batch record schema error: missing_nested={parent}:{','.join(missing_nested)}"
                    )
    typed_fields = contract.get("typed_fields", {})
    if isinstance(typed_fields, dict):
        for field_path, typ_name in typed_fields.items():
            expected_type = _TYPE_MAP.get(str(typ_name).strip())
            if expected_type is None:
                continue
            value = _get_path_value(record, str(field_path))
            if value is None:
                raise RuntimeError(f"Batch record schema error: missing_typed_field={field_path}")
            if not isinstance(value, expected_type):
                raise RuntimeError(
                    f"Batch record schema error: type_mismatch={field_path} expected={typ_name} actual={type(value).__name__}"
                )


def _staging_record_path(batch_id: str, run_id: str, staging_root: str, record_suffix: str) -> Path:
    root = ROOT / str(staging_root).strip()
    return root / batch_id / f"{run_id}{record_suffix}"


def _classify_artifact_api_failure(payload: dict[str, Any], *, backend: str) -> tuple[bool, bool, str]:
    flags = payload.get("runtime_flags") if isinstance(payload.get("runtime_flags"), dict) else {}
    captain_backend_error = bool(flags.get("captain_backend_error"))
    captain_cloud_error = bool(flags.get("captain_cloud_error"))
    backend_error = bool(flags.get("backend_error"))
    retryable = bool(flags.get("retryable_api_error"))
    provisional_local = bool(flags.get("provisional_local_fallback"))
    provisional_review_required = bool(flags.get("provisional_review_required"))
    fallback_agents = flags.get("fallback_agents") if isinstance(flags.get("fallback_agents"), list) else []
    reason = str(flags.get("captain_error_reason") or "")

    usage_nodes: list[dict[str, Any]] = []
    for key in ("captain_usage", "doctor_usage", "commander_usage"):
        node = payload.get(key)
        if isinstance(node, dict):
            usage_nodes.append(node)
    all_tokens_zero = (
        str(backend).lower() == "groq"
        and bool(usage_nodes)
        and all(int(node.get("total_tokens") or 0) == 0 for node in usage_nodes)
    )

    # Treat as API failure only when chain could not produce a valid completed run.
    # Provisional local fallback runs are completed and should not be counted as FAILED_API.
    failed_api = bool(
        (captain_backend_error and not provisional_local and not provisional_review_required)
        or (
            all_tokens_zero
            and not provisional_local
            and not provisional_review_required
            and backend_error
            and not bool(fallback_agents)
        )
    )
    retryable_api = bool(retryable or _is_rate_limit_error(reason))
    if all_tokens_zero and not reason:
        reason = "all_usage_tokens_zero"
    if not reason and captain_cloud_error and provisional_local:
        reason = "cloud_error_recovered_via_provisional_fallback"
    return failed_api, retryable_api, reason


def _run_chain_once(
    *,
    run_id: str,
    query: str,
    backend: str,
    top_k: int,
    batch_record_out: Path,
) -> tuple[int, str, str, float]:
    cmd = [
        sys.executable,
        "scripts/run_poc_e2e.py",
        "--run-id",
        run_id,
        "--backend",
        backend,
        "--top-k",
        str(top_k),
        "--query",
        query,
        "--write-card",
        "0",
        "--batch-record-out",
        str(batch_record_out),
    ]
    env = dict(os.environ)
    env["LLM_ALLOW_REMOTE"] = "1"
    started = time.perf_counter()
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, env=env)
    elapsed = time.perf_counter() - started
    return proc.returncode, proc.stdout, proc.stderr, elapsed


def _load_artifact(path: Path, *, batch_record_contract: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"Missing artifact: {path}")
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        raise RuntimeError(f"Artifact integrity error ({path}): {reason}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid artifact payload type: {path}")
    _validate_batch_record_payload(payload, batch_record_contract)
    return payload


def _case_cost(payload: dict[str, Any]) -> float:
    total = 0.0
    for key in ("captain_usage", "doctor_usage", "commander_usage"):
        node = payload.get(key) if isinstance(payload.get(key), dict) else {}
        total += float(node.get("cost_usd_estimate") or 0.0)
    return round(total, 6)


def _case_cloud_path_used(payload: dict[str, Any]) -> bool:
    for key in ("captain_usage", "doctor_usage", "commander_usage"):
        node = payload.get(key)
        if not isinstance(node, dict):
            continue
        if bool(node.get("cloud_path")):
            return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch evaluation for Sprint-2 E2E chain with rate-limited Groq calls.")
    parser.add_argument("--batch-id", default=f"batch_eval_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
    parser.add_argument("--backend", choices=["groq", "auto"], default="groq")
    parser.add_argument("--dataset", choices=["baseline", "ood"], default="baseline")
    parser.add_argument("--max-cases", type=int, default=20)
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--sleep-seconds", type=float, default=1.5, help="Rate-limit pause between chain runs.")
    parser.add_argument("--max-retries", type=int, default=3, help="Retries on HTTP 429 / rate-limit.")
    parser.add_argument("--backoff-base-seconds", type=float, default=2.0, help="Base for exponential backoff.")
    parser.add_argument("--max-total-cost-usd", type=float, default=3.0, help="Budget guardrail for full batch.")
    parser.add_argument(
        "--require-cloud-path-min",
        type=int,
        default=0,
        help="Fail run if fewer than this number of completed cases used real cloud LLM path.",
    )
    args = parser.parse_args()
    transport_contract = _load_transport_policy_contract()
    transport_policy = transport_contract.get("policy") if isinstance(transport_contract.get("policy"), dict) else {}
    staging_root = str(transport_policy.get("staging_root", "data/batch_eval/staging")).strip() or "data/batch_eval/staging"
    record_suffix = str(transport_policy.get("record_suffix", "_batch_record_v2.json")).strip() or "_batch_record_v2.json"
    if record_suffix.endswith("_poc_sprint2.json"):
        raise SystemExit("Transport policy violation: staging record suffix must not be *_poc_sprint2.json")
    if "batch_record_v2" not in record_suffix:
        raise SystemExit("Transport policy violation: record_suffix must include batch_record_v2")
    batch_record_contract = _load_batch_record_contract()

    secrets_path = _ensure_groq_secrets()
    # Ensure SoT/index exists and is up to date.
    gen_cmd = [
        sys.executable,
        "scripts/generate_synthetic_history.py",
        "--run-demo",
        "0",
        "--out-sot",
        "data/poc/history_sot_v1.json",
        "--out-index",
        "data/poc/history_vector_index_v1.json",
    ]
    gen_proc = subprocess.run(gen_cmd, cwd=ROOT, text=True, capture_output=True)
    if gen_proc.returncode != 0:
        raise SystemExit(f"Synthetic history generation failed:\n{gen_proc.stdout}\n{gen_proc.stderr}")

    cases = build_batch_eval_cases(count=max(1, int(args.max_cases)), dataset=args.dataset)
    total_cost = 0.0
    total_elapsed = 0.0
    completed = 0
    failed = 0
    failed_api = 0

    safe_total = 0
    risky_total = 0
    false_positive = 0
    false_negative = 0
    provisional_completed = 0
    cloud_path_completed = 0
    review_supported_total = 0
    review_refuted_total = 0
    review_untestable_total = 0
    review_quality_score_sum = 0.0
    review_quality_score_count = 0
    review_unavailable_cases = 0

    records: list[dict[str, Any]] = []
    print(f"batch_id={args.batch_id} cases={len(cases)} secrets={secrets_path}")
    for i, case in enumerate(cases, start=1):
        if total_cost >= float(args.max_total_cost_usd):
            print(f"[stop] budget limit reached total_cost={total_cost}")
            break

        case_id = str(case.get("case_id") or f"case_{i:03d}")
        query = str(case.get("query") or "").strip()
        expected_block = bool(case.get("expected_block"))
        run_id = f"{args.batch_id}_{case_id}"
        attempts = 0
        case_error = ""
        case_payload: dict[str, Any] | None = None
        case_elapsed = 0.0

        while attempts <= int(args.max_retries):
            attempts += 1
            case_record_path = _staging_record_path(args.batch_id, run_id, staging_root, record_suffix)
            case_record_path.parent.mkdir(parents=True, exist_ok=True)
            rc, out, err, elapsed = _run_chain_once(
                run_id=run_id,
                query=query,
                backend=args.backend,
                top_k=args.top_k,
                batch_record_out=case_record_path,
            )
            case_elapsed += elapsed
            if rc == 0:
                try:
                    case_payload = _load_artifact(case_record_path, batch_record_contract=batch_record_contract)
                except Exception as exc:
                    failed += 1
                    records.append(
                        {
                            "run_id": run_id,
                            "case_id": case_id,
                            "status": "FAILED_RECORD",
                            "attempts": attempts,
                            "elapsed_sec": round(case_elapsed, 3),
                            "error_tail": str(exc)[:500],
                            "record_path": str(case_record_path),
                        }
                    )
                    print(f"[fail_record] {run_id} attempts={attempts} reason={str(exc)[:160]}")
                    case_payload = None
                    break
                is_api_failed, is_retryable_api, api_reason = _classify_artifact_api_failure(
                    case_payload, backend=args.backend
                )
                if is_api_failed and is_retryable_api and attempts <= int(args.max_retries):
                    wait_s = float(args.backoff_base_seconds) * (2 ** (attempts - 1))
                    print(f"[retry] {run_id} artifact_api_error attempt={attempts} wait={wait_s:.1f}s")
                    time.sleep(wait_s)
                    case_payload = None
                    continue
                if is_api_failed:
                    failed += 1
                    failed_api += 1
                    records.append(
                        {
                            "run_id": run_id,
                            "case_id": case_id,
                            "status": "FAILED_API",
                            "attempts": attempts,
                            "elapsed_sec": round(case_elapsed, 3),
                            "error_tail": api_reason[:500],
                        }
                    )
                    print(f"[fail_api] {run_id} attempts={attempts} reason={api_reason[:160]}")
                    case_payload = None
                break

            merged = f"{out}\n{err}"
            if _is_rate_limit_error(merged) and attempts <= int(args.max_retries):
                wait_s = float(args.backoff_base_seconds) * (2 ** (attempts - 1))
                print(f"[retry] {run_id} rate-limited attempt={attempts} wait={wait_s:.1f}s")
                time.sleep(wait_s)
                continue
            case_error = merged.strip()[-500:]
            break

        if case_payload is None:
            if records and records[-1].get("run_id") == run_id and str(records[-1].get("status", "")) in {"FAILED_API", "FAILED_RECORD"}:
                if i < len(cases):
                    time.sleep(max(0.0, float(args.sleep_seconds)))
                continue
            failed += 1
            records.append(
                {
                    "run_id": run_id,
                    "case_id": case_id,
                    "status": "FAILED_RUNTIME",
                    "attempts": attempts,
                    "elapsed_sec": round(case_elapsed, 3),
                    "error_tail": case_error,
                }
            )
            print(f"[fail] {run_id} attempts={attempts}")
        else:
            completed += 1
            total_elapsed += case_elapsed
            decision = str(((case_payload.get("commander") or {}).get("decision") or "HOLD_NEED_DATA")).upper()
            predicted_block = decision != "GO"
            runtime_flags = case_payload.get("runtime_flags") if isinstance(case_payload.get("runtime_flags"), dict) else {}
            provisional_local = bool(runtime_flags.get("provisional_local_fallback"))
            if provisional_local:
                provisional_completed += 1
            cloud_path_used = _case_cloud_path_used(case_payload)
            if cloud_path_used:
                cloud_path_completed += 1
            review_unavailable = bool(case_payload.get("verification_unavailable", False))
            review_supported = int(case_payload.get("supported_count", 0) or 0)
            review_refuted = int(case_payload.get("refuted_count", 0) or 0)
            review_untestable = int(case_payload.get("untestable_count", 0) or 0)
            try:
                review_quality_score = float(case_payload.get("verification_quality_score", 0.0) or 0.0)
            except Exception:
                review_quality_score = 0.0
            review_quality_score = max(0.0, min(1.0, review_quality_score))
            if review_unavailable:
                review_unavailable_cases += 1
            else:
                review_supported_total += review_supported
                review_refuted_total += review_refuted
                review_untestable_total += review_untestable
                review_quality_score_sum += review_quality_score
                review_quality_score_count += 1
            cost = _case_cost(case_payload)
            total_cost = round(total_cost + cost, 6)

            profile = str(case.get("profile") or "").lower()
            reasoning = case_payload.get("reasoning") if isinstance(case_payload.get("reasoning"), dict) else {}
            confidence = reasoning.get("confidence") if isinstance(reasoning.get("confidence"), dict) else {}
            evidence_quality = (
                reasoning.get("evidence_quality") if isinstance(reasoning.get("evidence_quality"), dict) else {}
            )
            if expected_block:
                risky_total += 1
                if not predicted_block:
                    false_negative += 1
            else:
                safe_total += 1
                if predicted_block:
                    false_positive += 1

            records.append(
                {
                    "run_id": run_id,
                    "case_id": case_id,
                    "profile": profile,
                    "query": query,
                    "expected_block": expected_block,
                    "decision": decision,
                    "executive_summary": str(((case_payload.get("commander") or {}).get("executive_summary") or "")).strip(),
                    "go_no_go_rationale": list((case_payload.get("commander") or {}).get("rationale_bullets") or []),
                    "risk_signals": list((case_payload.get("doctor") or {}).get("risk_signals") or []),
                    "recommended_actions": list((case_payload.get("doctor") or {}).get("recommended_actions") or []),
                    "commander_next_steps": list((case_payload.get("commander") or {}).get("next_steps") or []),
                    "top_match": case_payload.get("top_match") if isinstance(case_payload.get("top_match"), dict) else {},
                    "reasoning_observed_facts": list(reasoning.get("observed_facts") or []),
                    "reasoning_causal_interpretation": str(reasoning.get("causal_interpretation") or "").strip(),
                    "reasoning_why_not_opposite_decision": str(
                        reasoning.get("why_not_opposite_decision") or ""
                    ).strip(),
                    "reasoning_confidence": confidence if isinstance(confidence, dict) else {},
                    "reasoning_evidence_quality": evidence_quality if isinstance(evidence_quality, dict) else {},
                    "reasoning_decision_tradeoffs": list(reasoning.get("decision_tradeoffs") or []),
                    "reasoning_mitigations": list(reasoning.get("mitigations") or []),
                    "reasoning_uncertainty_gaps": list(reasoning.get("uncertainty_gaps") or []),
                    "predicted_block": predicted_block,
                    "provisional_local_fallback": provisional_local,
                    "cloud_path_used": cloud_path_used,
                    "supported_count": review_supported,
                    "refuted_count": review_refuted,
                    "untestable_count": review_untestable,
                    "verification_quality_score": round(review_quality_score, 4),
                    "verification_unavailable": review_unavailable,
                    "attempts": attempts,
                    "elapsed_sec": round(case_elapsed, 3),
                    "cost_usd_estimate": cost,
                }
            )
            print(
                f"[ok] {run_id} decision={decision} expected_block={expected_block} "
                f"cost={cost} elapsed={case_elapsed:.2f}s attempts={attempts} provisional={provisional_local}"
            )

        if i < len(cases):
            time.sleep(max(0.0, float(args.sleep_seconds)))

    avg_time = (total_elapsed / completed) if completed > 0 else 0.0
    fpr = (false_positive / safe_total) if safe_total > 0 else None
    fnr = (false_negative / risky_total) if risky_total > 0 else None
    availability = (completed / (completed + failed_api)) if (completed + failed_api) > 0 else None
    verification_quality_score = (
        round(review_quality_score_sum / review_quality_score_count, 4)
        if review_quality_score_count > 0
        else None
    )

    summary = {
        "batch_id": args.batch_id,
        "dataset": args.dataset,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "max_cases_requested": len(cases),
        "completed_cases": completed,
        "failed_cases": failed,
        "failed_api_cases": failed_api,
        "total_cost_usd_estimate": round(total_cost, 6),
        "average_time_sec": round(avg_time, 3),
        "false_positive_rate": (round(fpr, 4) if fpr is not None else None),
        "false_negative_rate": (round(fnr, 4) if fnr is not None else None),
        "availability_kpi": (round(availability, 4) if availability is not None else None),
        "provisional_completed_cases": provisional_completed,
        "cloud_path_completed_cases": cloud_path_completed,
        "supported_count": review_supported_total,
        "refuted_count": review_refuted_total,
        "untestable_count": review_untestable_total,
        "verification_quality_score": verification_quality_score,
        "verification_quality_cases": review_quality_score_count,
        "verification_unavailable_cases": review_unavailable_cases,
        "safe_cases": safe_total,
        "risky_cases": risky_total,
        "record_format": "batch_record_v2",
        "record_suffix": record_suffix,
        "records_source": "summary.records_from_staging",
        "summary_source_of_truth": f"data/batch_eval/{args.batch_id}_summary.json",
        "staging_root": f"{staging_root}/{args.batch_id}",
        "records": records,
    }

    out_path = ROOT / f"data/batch_eval/{args.batch_id}_summary.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out_path)

    print("\n=== Batch Eval Summary ===")
    print(f"batch_id                : {args.batch_id}")
    print(f"dataset                 : {args.dataset}")
    print(f"completed / failed      : {completed} / {failed}")
    print(f"failed_api_cases        : {failed_api}")
    print(f"Total Cost (USD)        : {summary['total_cost_usd_estimate']}")
    print(f"Average Time (sec)      : {summary['average_time_sec']}")
    fpr_text = f"{summary['false_positive_rate']} ({false_positive}/{safe_total})" if safe_total > 0 else "N/A (0/0)"
    fnr_text = f"{summary['false_negative_rate']} ({false_negative}/{risky_total})" if risky_total > 0 else "N/A (0/0)"
    availability_text = (
        f"{summary['availability_kpi']} ({completed}/{completed + failed_api})"
        if (completed + failed_api) > 0
        else "N/A (0/0)"
    )
    print(f"False Positive Rate     : {fpr_text}")
    print(f"False Negative Rate     : {fnr_text}")
    print(f"Availability KPI        : {availability_text}")
    print(f"provisional_completed   : {provisional_completed}")
    print(f"cloud_path_completed   : {cloud_path_completed}")
    print(f"summary_artifact        : {out_path}")
    print(f"summary_artifact_sidecar: {out_path}.sha256")

    required_cloud_min = max(0, int(args.require_cloud_path_min))
    if required_cloud_min > 0 and cloud_path_completed < required_cloud_min:
        raise SystemExit(
            f"CloudPathVerificationError: required>={required_cloud_min} "
            f"but observed={cloud_path_completed}. Prompt tuning not verified on real cloud path."
        )


if __name__ == "__main__":
    main()
