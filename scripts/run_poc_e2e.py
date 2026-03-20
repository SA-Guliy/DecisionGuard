#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import dotenv_values, load_dotenv

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.retrieval_v1 import RetrievalMatch, retrieve_similar_experiments
from src.llm_secure_gateway import gateway_chat_completion, get_llm_backend
from src.llm_contract_utils import coerce_string, coerce_string_list, parse_json_object_loose
from src.config import OLLAMA_MODEL_DEFAULT
from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar
from src.model_policy import (
    CAPTAIN_GROQ_MODEL,
    COMMANDER_GROQ_FALLBACK_MODEL,
    COMMANDER_GROQ_PRIMARY_MODEL,
    DOCTOR_GROQ_PRIMARY_MODEL,
    doctor_reasoning_model_chain,
)
import re


TRACE_PATH = Path("data/logs/reasoning_trace.jsonl")
RECONCILIATION_EVENTS_PATH = Path("data/reconciliation/reconciliation_events.jsonl")
RECONCILIATION_SUMMARY_PATH = Path("data/reconciliation/reconciliation_accuracy_summary.json")
BATCH_RECORD_CONTRACT_PATH = ROOT / "configs/contracts/batch_record_v2.json"

# Approximate USD pricing per 1K tokens for observability in POC mode.
# Values are deliberately labeled as estimate for Sprint-2 demo accounting.
MODEL_PRICING_USD_PER_1K: dict[str, dict[str, float]] = {
    "llama-3.1-8b-instant": {"in": 0.0002, "out": 0.0002},
    "qwen/qwen3-32b": {"in": 0.0005, "out": 0.0005},
    "llama-3.3-70b-versatile": {"in": 0.0008, "out": 0.0008},
    "openai/gpt-oss-120b": {"in": 0.0009, "out": 0.0009},
    "openai/gpt-oss-20b": {"in": 0.0003, "out": 0.0003},
}
INTERACTIVE_MAX_TURNS = 5
THINK_BLOCK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL | re.IGNORECASE)
PROVISIONAL_LOCAL_TAG = "[PROVISIONAL - LOCAL EDGE FALLBACK]"
RUNTIME_GROQ_API_KEY = ""


_TYPE_MAP: dict[str, type] = {
    "str": str,
    "bool": bool,
    "int": int,
    "float": (int, float),
    "dict": dict,
    "list": list,
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _get_path_value(payload: dict[str, Any], path: str) -> Any:
    cur: Any = payload
    for key in str(path).split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


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


def _validate_batch_record_payload(record: dict[str, Any], contract: dict[str, Any]) -> None:
    expected_version = str(contract.get("record_version", "")).strip()
    if expected_version and str(record.get("version", "")).strip() != expected_version:
        raise SystemExit(
            f"Batch record schema error: version mismatch expected={expected_version} actual={record.get('version')}"
        )

    required_top = contract.get("required_top_level", [])
    if isinstance(required_top, list):
        missing = [k for k in required_top if k not in record]
        if missing:
            raise SystemExit(f"Batch record schema error: missing_top_level={','.join(missing)}")

    required_nested = contract.get("required_nested", {})
    if isinstance(required_nested, dict):
        for parent, fields in required_nested.items():
            node = record.get(parent)
            if not isinstance(node, dict):
                raise SystemExit(f"Batch record schema error: nested_parent_not_dict={parent}")
            if not isinstance(fields, list):
                continue
            missing_nested = [k for k in fields if k not in node]
            if missing_nested:
                raise SystemExit(
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
                raise SystemExit(f"Batch record schema error: missing_typed_field={field_path}")
            if not isinstance(value, expected_type):
                raise SystemExit(
                    f"Batch record schema error: type_mismatch={field_path} expected={typ_name} actual={type(value).__name__}"
                )


def _build_batch_record_v2(
    *,
    run_id: str,
    query: str,
    generated_at: str,
    captain: dict[str, Any],
    doctor: dict[str, Any],
    commander: dict[str, Any],
    captain_usage: dict[str, Any],
    doctor_usage: dict[str, Any],
    commander_usage: dict[str, Any],
    runtime_flags: dict[str, Any],
    retrieval_top_k: int,
    top_matches: list[dict[str, Any]],
    needs_cloud_reconciliation: bool,
    reconciliation: dict[str, Any] | None,
) -> dict[str, Any]:
    top_match = top_matches[0] if top_matches and isinstance(top_matches[0], dict) else {}
    primary = top_match.get("primary_metric_outcome") if isinstance(top_match.get("primary_metric_outcome"), dict) else {}
    breach = top_match.get("guardrail_breach") if isinstance(top_match.get("guardrail_breach"), dict) else {}
    similarity = 0.0
    try:
        similarity = float(top_match.get("similarity") or 0.0)
    except Exception:
        similarity = 0.0

    observed_facts: list[str] = []
    if top_match:
        observed_facts.append(
            f"Top historical match similarity={round(similarity, 4)} (experiment_id={str(top_match.get('experiment_id') or 'unknown')})."
        )
    p_metric = str(primary.get("metric_id") or "").strip()
    p_delta = primary.get("delta_pct")
    if p_metric and p_delta is not None:
        observed_facts.append(f"Primary historical outcome: {p_metric} delta_pct={p_delta}.")
    g_metric = str(breach.get("metric_id") or "").strip()
    g_delta = breach.get("delta_pct")
    if g_metric and g_delta is not None:
        observed_facts.append(f"Guardrail historical signal: {g_metric} delta_pct={g_delta}.")
    observed_facts.append(f"Doctor suggested_decision={str(doctor.get('suggested_decision') or 'HOLD_NEED_DATA').upper()}.")
    observed_facts.append(f"Commander final decision={str(commander.get('decision') or 'HOLD_NEED_DATA').upper()}.")

    decision = str(commander.get("decision") or "HOLD_NEED_DATA").upper()
    causal_interpretation = str(doctor.get("causal_story") or doctor.get("analysis_note") or "").strip()
    if not causal_interpretation:
        causal_interpretation = "Causal link is weak or incomplete; defensive governance defaults were applied."

    if decision == "GO":
        why_not_opposite = (
            "STOP/HOLD was rejected because available evidence did not confirm material guardrail harm "
            "and potential upside remained actionable with monitoring."
        )
    elif decision in {"STOP", "STOP_ROLLOUT"}:
        why_not_opposite = (
            "GO was rejected because risk signals and historical analogs indicated material downside risk "
            "that could not be safely mitigated in current evidence state."
        )
    else:
        why_not_opposite = (
            "GO was rejected due to insufficient/contradictory evidence; STOP was not forced because hard harm evidence "
            "was not fully conclusive."
        )

    confidence_basis: list[str] = []
    confidence_score = 0.72
    if similarity < 0.2:
        confidence_score -= 0.22
        confidence_basis.append("low_historical_similarity")
    elif similarity >= 0.6:
        confidence_score += 0.08
        confidence_basis.append("strong_historical_similarity")
    if bool(runtime_flags.get("provisional_local_fallback")):
        confidence_score -= 0.18
        confidence_basis.append("provisional_local_fallback")
    if bool(runtime_flags.get("backend_error")):
        confidence_score -= 0.12
        confidence_basis.append("backend_error_present")
    if not top_match:
        confidence_score -= 0.2
        confidence_basis.append("missing_top_match")
    confidence_score = max(0.05, min(0.95, confidence_score))
    confidence_label = "HIGH" if confidence_score >= 0.75 else ("MEDIUM" if confidence_score >= 0.5 else "LOW")

    missing_evidence: list[str] = []
    if not top_match:
        missing_evidence.append("historical_match_absent")
    if needs_cloud_reconciliation:
        missing_evidence.append("cloud_reconciliation_pending")
    if decision.startswith("HOLD"):
        missing_evidence.append("critical_evidence_incomplete")
    evidence_count = len(top_matches) + len([x for x in observed_facts if str(x).strip()])
    evidence_score = 0.78
    if len(top_matches) == 0:
        evidence_score -= 0.35
    elif len(top_matches) == 1:
        evidence_score -= 0.15
    if missing_evidence:
        evidence_score -= 0.1
    evidence_score = max(0.05, min(0.95, evidence_score))
    evidence_label = "HIGH" if evidence_score >= 0.75 else ("MEDIUM" if evidence_score >= 0.5 else "LOW")

    decision_tradeoffs = [str(x).strip() for x in (commander.get("rationale_bullets") or []) if str(x).strip()]
    mitigations = [str(x).strip() for x in (doctor.get("recommended_actions") or []) if str(x).strip()]
    mitigations.extend([str(x).strip() for x in (commander.get("next_steps") or []) if str(x).strip()])
    uncertainty_gaps = [str(x).strip() for x in missing_evidence if str(x).strip()]
    review_rows = (
        commander.get("doctor_hypothesis_review", [])
        if isinstance(commander.get("doctor_hypothesis_review"), list)
        else []
    )
    review_summary = (
        commander.get("hypothesis_review_summary", {})
        if isinstance(commander.get("hypothesis_review_summary"), dict)
        else {}
    )
    verification_unavailable = not (isinstance(review_rows, list) and isinstance(review_summary, dict) and "verification_quality_score" in review_summary)
    if verification_unavailable:
        supported_count = 0
        refuted_count = 0
        untestable_count = 0
        verification_quality_score = 0.0
    else:
        supported_count = int(review_summary.get("supported_count", 0) or 0)
        refuted_count = int(review_summary.get("refuted_count", 0) or 0)
        untestable_count = int(review_summary.get("untestable_count", 0) or 0)
        try:
            verification_quality_score = float(review_summary.get("verification_quality_score", 0.0) or 0.0)
        except Exception:
            verification_quality_score = 0.0
        verification_quality_score = max(0.0, min(1.0, verification_quality_score))

    total_cost = float(captain_usage.get("cost_usd_estimate") or 0.0)
    total_cost += float(doctor_usage.get("cost_usd_estimate") or 0.0)
    total_cost += float(commander_usage.get("cost_usd_estimate") or 0.0)
    return {
        "version": "batch_record_v2",
        "run_id": run_id,
        "query": query,
        "generated_at": generated_at,
        "retrieval_top_k": retrieval_top_k,
        "top_match": top_match,
        "captain": captain,
        "doctor": doctor,
        "commander": commander,
        "captain_usage": captain_usage,
        "doctor_usage": doctor_usage,
        "commander_usage": commander_usage,
        "runtime_flags": runtime_flags,
        "cost_usd_estimate_total": round(total_cost, 6),
        "supported_count": supported_count,
        "refuted_count": refuted_count,
        "untestable_count": untestable_count,
        "verification_quality_score": round(verification_quality_score, 4),
        "verification_unavailable": bool(verification_unavailable),
        "needs_cloud_reconciliation": bool(needs_cloud_reconciliation),
        "reconciliation_status": str((reconciliation or {}).get("status", "")).strip() if isinstance(reconciliation, dict) else "",
        "reasoning": {
            "observed_facts": observed_facts,
            "causal_interpretation": causal_interpretation,
            "why_not_opposite_decision": why_not_opposite,
            "confidence": {
                "score": round(float(confidence_score), 4),
                "label": confidence_label,
                "basis": confidence_basis or ["default_reasoning_confidence"],
            },
            "evidence_quality": {
                "score": round(float(evidence_score), 4),
                "label": evidence_label,
                "evidence_count": int(evidence_count),
                "missing_evidence": uncertainty_gaps,
            },
            "decision_tradeoffs": decision_tradeoffs,
            "mitigations": mitigations,
            "uncertainty_gaps": uncertainty_gaps,
        },
    }


def _sanitize_model_text(text: str) -> str:
    t = str(text or "")
    t = THINK_BLOCK_RE.sub("", t)
    return t.strip()


def _approx_tokens(text: str) -> int:
    # Lightweight approximation: ~4 chars/token.
    txt = str(text or "")
    if not txt:
        return 0
    return max(1, int(len(txt) / 4))


def _estimate_cost_usd(model_name: str, prompt_tokens: int, completion_tokens: int) -> float:
    price = MODEL_PRICING_USD_PER_1K.get(model_name, None)
    if not price:
        return 0.0
    return round((prompt_tokens / 1000.0) * price["in"] + (completion_tokens / 1000.0) * price["out"], 6)


def _append_trace(event: dict[str, Any]) -> None:
    TRACE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with TRACE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def _append_synthetic_trace(
    *,
    run_id: str,
    agent: str,
    backend: str,
    model: str,
    reason: str,
) -> dict[str, Any]:
    event = {
        "run_id": run_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "agent": agent,
        "backend": backend,
        "model": model,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cost_usd_estimate": 0.0,
        "cost_basis": "estimated_per_1k_tokens",
        "latency_ms": 0,
        "reason": reason,
        "trace_kind": "synthetic",
    }
    _append_trace(event)
    return event


def _looks_like_api_error(text: str) -> bool:
    t = str(text or "").lower()
    markers = (
        "api",
        "connection error",
        "apiconnectionerror",
        "timeout",
        "timed out",
        "too many requests",
        "rate limit",
        " 429",
        "http 429",
        "service unavailable",
        "temporarily unavailable",
        "unavailable",
    )
    return any(m in t for m in markers)


def _looks_like_retryable_api_error(text: str) -> bool:
    t = str(text or "").lower()
    markers = (
        "too many requests",
        "rate limit",
        " 429",
        "http 429",
        "apiconnectionerror",
        "connection error",
        "timeout",
        "timed out",
        "service unavailable",
    )
    return any(m in t for m in markers)


def _load_groq_secrets_conditional(*, need_cloud: bool, strict: bool) -> tuple[bool, str, str]:
    if not need_cloud:
        return False, "not_required", ""

    # Priority: explicit env -> local .env -> ~/.groq_secrets
    env_key = str(os.getenv("GROQ_API_KEY", "")).strip()
    if env_key:
        if env_key.startswith("gsk_") and len(env_key) >= 20:
            return True, "env:GROQ_API_KEY", env_key
        if strict:
            raise SystemExit("ConfigurationError: Invalid GROQ_API_KEY format in env")

    env_path = ROOT / ".env"
    if env_path.exists() and env_path.is_file():
        load_dotenv(env_path, override=False)
        env_file_key = str(os.getenv("GROQ_API_KEY", "")).strip()
        if env_file_key:
            if env_file_key.startswith("gsk_") and len(env_file_key) >= 20:
                return True, f"file:{env_path}", env_file_key
            if strict:
                raise SystemExit("ConfigurationError: Invalid GROQ_API_KEY format in .env")

    secrets_path = Path(os.path.expanduser("~/.groq_secrets"))
    if not secrets_path.exists() or not secrets_path.is_file():
        if strict:
            raise SystemExit("ConfigurationError: Missing ~/.groq_secrets")
        return False, "missing_file", ""
    if not os.access(secrets_path, os.R_OK):
        if strict:
            raise SystemExit("ConfigurationError: ~/.groq_secrets is not readable")
        return False, "not_readable", ""

    values = dotenv_values(secrets_path)
    file_key_raw = values.get("GROQ_API_KEY")
    if not isinstance(file_key_raw, str) or not file_key_raw.strip():
        if strict:
            raise SystemExit("ConfigurationError: GROQ_API_KEY is missing in ~/.groq_secrets")
        return False, "missing_key", ""
    file_key = file_key_raw.strip()
    if not (file_key.startswith("gsk_") and len(file_key) >= 20):
        if strict:
            raise SystemExit("ConfigurationError: Invalid GROQ_API_KEY format in ~/.groq_secrets")
        return False, "invalid_key_format", ""

    # Force explicit value from ~/.groq_secrets when using that source.
    load_dotenv(secrets_path, override=True)
    loaded_key = str(os.getenv("GROQ_API_KEY", "")).strip()
    if loaded_key != file_key:
        if strict:
            raise SystemExit("ConfigurationError: Failed to load GROQ_API_KEY from ~/.groq_secrets")
        return False, "env_load_mismatch", ""
    return True, str(secrets_path), loaded_key


def _ensure_sanitization_kms_master_key() -> tuple[bool, str]:
    # Priority: explicit env -> local .env -> local demo fallback.
    env_secret = str(os.getenv("SANITIZATION_KMS_MASTER_KEY", "")).strip()
    if env_secret:
        return True, "env:SANITIZATION_KMS_MASTER_KEY"

    env_path = ROOT / ".env"
    if env_path.exists() and env_path.is_file():
        load_dotenv(env_path, override=False)
        env_file_secret = str(os.getenv("SANITIZATION_KMS_MASTER_KEY", "")).strip()
        if env_file_secret:
            return True, f"file:{env_path}"

    # Local development safety default for POC runs.
    fallback_secret = str(os.getenv("SANITIZATION_LOCAL_DEMO_KEY", "local_demo_key_123")).strip()
    if not fallback_secret:
        fallback_secret = "local_demo_key_123"
    os.environ["SANITIZATION_KMS_MASTER_KEY"] = fallback_secret
    return False, "default:local_demo_key_123"


def _cloud_path_requested(backend_name: str) -> bool:
    b = str(backend_name or "").strip().lower()
    if b == "groq":
        return True
    if b == "auto":
        return os.getenv("LLM_ALLOW_REMOTE", "0") == "1"
    return False


def _call_llm_with_observability(
    *,
    run_id: str,
    agent_name: str,
    backend_name: str,
    model_name: str,
    system_prompt: str,
    user_prompt: str,
) -> tuple[str, dict[str, Any]]:
    started = time.perf_counter()
    backend = get_llm_backend(
        backend_name,
        model_name=model_name,
        api_key=(RUNTIME_GROQ_API_KEY if str(backend_name or "").strip().lower() in {"groq", "auto"} else None),
    )
    selected_model = backend.get_model_name()

    output = ""
    prompt_tokens = 0
    completion_tokens = 0
    total_tokens = 0

    output, usage = gateway_chat_completion(
        backend=backend,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0.2,
        run_id=run_id,
        agent_name=agent_name,
        call_name="poc_chat_completion",
    )
    prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
    completion_tokens = int(usage.get("completion_tokens", 0) or 0)
    total_tokens = int(usage.get("total_tokens", prompt_tokens + completion_tokens) or (prompt_tokens + completion_tokens))

    latency_ms = int((time.perf_counter() - started) * 1000)
    cost_usd = _estimate_cost_usd(selected_model, prompt_tokens, completion_tokens)
    meta = {
        "run_id": run_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "agent": agent_name,
        "backend": backend_name,
        "model": selected_model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "cost_usd_estimate": cost_usd,
        "cost_basis": "estimated_per_1k_tokens",
        "latency_ms": latency_ms,
        "obfuscation_map_ref": str(usage.get("obfuscation_map_ref", "") or ""),
        "cloud_path": bool(int(usage.get("cloud_path", 0) or 0)),
    }
    _append_trace(meta)
    return _sanitize_model_text(output), meta


def _build_historical_context_pack(matches: list[RetrievalMatch]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in matches:
        out.append(
            {
                "experiment_id": m.experiment_id,
                "similarity": m.score,
                "hypothesis": m.hypothesis,
                "primary_metric_outcome": m.primary_metric_outcome,
                "guardrail_breach": m.guardrail_breach,
                "reasoning_decision": m.reasoning_decision,
            }
        )
    return out


def _infer_binary_decision_from_context(
    *,
    historical_context_pack: list[dict[str, Any]],
    doctor_decision_hint: str = "",
    hypothesis_text: str = "",
) -> str:
    if str(doctor_decision_hint or "").upper() == "STOP_ROLLOUT":
        return "STOP_ROLLOUT"
    txt = str(hypothesis_text or "").lower()
    risk_keywords = (
        "discount",
        "coupon",
        "flash",
        "aggressive",
        "aggressively",
        "waive delivery",
        "waive",
        "broaden promotional",
        "promotional depth",
        "shorten stock cover",
        "stock cover",
        "demand spikes",
        "high-ticket",
        "high ticket",
        "compress picking buffers",
        "dispatch windows",
        "boost gmv",
        "raise gmv",
        "free-shipping",
        "free shipping",
        "maximize throughput",
        "peak hours",
    )
    safe_keywords = (
        "no discount change",
        "without changing promo",
        "preserving current",
        "monitoring",
        "clarity",
        "reduce returns",
        "reorder cadence",
        "checkout ux copy",
    )
    safe_signal = any(k in txt for k in safe_keywords)
    risk_signal = any(k in txt for k in risk_keywords) and not safe_signal

    if not historical_context_pack:
        return "STOP_ROLLOUT" if risk_signal else "GO"
    top = historical_context_pack[0]
    hist_dec = str(((top.get("reasoning_decision") or {}).get("decision") or "")).upper()
    similarity = float(top.get("similarity") or 0.0)
    if hist_dec in {"STOP_ROLLOUT", "STOP"} and similarity >= 0.55:
        return "STOP_ROLLOUT"
    breach_metric = str(((top.get("guardrail_breach") or {}).get("metric_id") or "")).strip()

    # Calculated-risk fallback:
    # block only on strong evidence; allow safe-pattern hypotheses under weak/medium similarity.
    if breach_metric and risk_signal and similarity >= 0.15:
        return "STOP_ROLLOUT"
    if breach_metric and similarity >= 0.35 and not safe_signal:
        return "HOLD_NEED_DATA"
    if safe_signal and similarity < 0.45:
        return "GO"
    return "GO"


def _captain_heuristic_sanity(hypothesis: str) -> tuple[str, list[str], bool]:
    txt = str(hypothesis or "").strip()
    if len(txt) < 12:
        return ("FAIL", ["captain_edge_heuristic_short_hypothesis"], False)
    return ("PASS", ["captain_edge_heuristic_continuity_mode"], True)


def _captain_sanity_check(
    *,
    run_id: str,
    hypothesis: str,
    backend_name: str,
    model_name: str,
    edge_backend_name: str,
    edge_model_name: str,
    simulate_cloud_outage: bool = False,
    allow_heuristic_edge_fallback: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    system_prompt = (
        "You are Captain, a fast sanity-check gate for experiment proposals. "
        "Apply Calculated Risk: default to PASS for plausible hypotheses. "
        "FAIL only for clearly nonsensical, self-contradictory, or non-actionable input."
    )
    user_prompt = (
        "Return ONLY one JSON object with keys exactly:\n"
        "sanity_status, issues, pass_to_doctor.\n"
        "Rules:\n"
        "- sanity_status must be PASS or FAIL.\n"
        "- issues must be an array of short strings.\n"
        "- pass_to_doctor must be true only when sanity_status is PASS.\n\n"
        "- If the hypothesis is understandable and testable, choose PASS.\n"
        "- Uncertainty alone is NOT a reason to FAIL; add issue='needs_clarification' and still PASS.\n"
        "- FAIL only when the request is gibberish, mutually contradictory, or missing a testable action.\n\n"
        f"Incoming hypothesis:\n{hypothesis}\n"
    )
    raw = ""
    meta: dict[str, Any] = {}
    cloud_failures: list[str] = []
    edge_fallback_used = False
    captain_backend_error = False
    try:
        if simulate_cloud_outage and backend_name in {"groq", "auto"}:
            raise RuntimeError("simulated_cloud_outage_captain")
        raw, meta = _call_llm_with_observability(
            run_id=run_id,
            agent_name="captain",
            backend_name=backend_name,
            model_name=model_name,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
    except Exception as exc:
        captain_backend_error = True
        print(f"[DEBUG CLOUD ERROR] Model {model_name} failed: {repr(exc)}")
        cloud_failures.append(str(exc).splitlines()[0][:220])
        if edge_backend_name:
            try:
                raw, meta = _call_llm_with_observability(
                    run_id=run_id,
                    agent_name="captain",
                    backend_name=edge_backend_name,
                    model_name=edge_model_name,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
                edge_fallback_used = True
            except Exception as edge_exc:
                cloud_failures.append(str(edge_exc).splitlines()[0][:220])
                if not allow_heuristic_edge_fallback:
                    raise edge_exc
                status, issues, pass_to_doctor = _captain_heuristic_sanity(hypothesis)
                meta = _append_synthetic_trace(
                    run_id=run_id,
                    agent="captain_edge_heuristic",
                    backend=edge_backend_name or backend_name,
                    model=edge_model_name or "edge_heuristic",
                    reason=f"captain_backend_error:{str(edge_exc).splitlines()[0][:220]}",
                )
                meta["edge_fallback_used"] = True
                meta["cloud_failures"] = cloud_failures
                meta["captain_backend_error"] = captain_backend_error
                result = {
                    "sanity_status": status,
                    "issues": issues,
                    "pass_to_doctor": pass_to_doctor,
                    "provisional_local_edge_fallback": True,
                    "raw_output": "",
                }
                return result, meta
        else:
            if not allow_heuristic_edge_fallback:
                raise
            status, issues, pass_to_doctor = _captain_heuristic_sanity(hypothesis)
            meta = _append_synthetic_trace(
                run_id=run_id,
                agent="captain_edge_heuristic",
                backend=backend_name,
                model="edge_heuristic",
                reason=f"captain_backend_error:{str(exc).splitlines()[0][:220]}",
            )
            meta["edge_fallback_used"] = True
            meta["cloud_failures"] = cloud_failures
            meta["captain_backend_error"] = captain_backend_error
            result = {
                "sanity_status": status,
                "issues": issues,
                "pass_to_doctor": pass_to_doctor,
                "provisional_local_edge_fallback": True,
                "raw_output": "",
            }
            return result, meta
    obj = parse_json_object_loose(raw) or {}

    status = coerce_string(obj.get("sanity_status"), max_len=16).upper()
    if status not in {"PASS", "FAIL"}:
        lowered = raw.lower()
        status = "FAIL" if "fail" in lowered else "PASS"

    issues = coerce_string_list(obj.get("issues"), max_items=8, max_item_len=180)
    if not issues and not obj:
        issues = ["captain_json_parse_fallback"]

    # Routing safety:
    # status is the source-of-truth for gate result. If status is PASS, the chain must continue.
    # This prevents accidental short-circuit when model emits inconsistent pass_to_doctor=false.
    pass_flag_raw = obj.get("pass_to_doctor") if obj else None
    pass_to_doctor = status == "PASS"
    if status == "FAIL":
        pass_to_doctor = False
    elif pass_flag_raw is False:
        issues = ["captain_contract_violation_autofix_pass_to_doctor", *issues]

    if edge_fallback_used and status == "FAIL":
        # Safety gate must remain FAIL on edge fallback; no implicit PASS conversion.
        issues = ["captain_edge_fallback_review_required", *issues]

    result = {
        "sanity_status": status,
        "issues": issues,
        "pass_to_doctor": pass_to_doctor,
        "provisional_local_edge_fallback": edge_fallback_used,
        "raw_output": raw,
    }
    meta["edge_fallback_used"] = edge_fallback_used
    meta["cloud_failures"] = cloud_failures
    meta["captain_backend_error"] = captain_backend_error
    if edge_fallback_used:
        meta["edge_backend"] = edge_backend_name
        meta["edge_model"] = edge_model_name
    return result, meta


def _normalize_captain_gate(captain: dict[str, Any]) -> tuple[bool, bool, bool]:
    captain_status_norm = str(captain.get("sanity_status", "")).strip().upper()
    captain_pass_by_status = ("PASS" in captain_status_norm) and ("FAIL" not in captain_status_norm)
    captain_pass_to_doctor = bool(captain.get("pass_to_doctor"))
    if captain_pass_by_status and not captain_pass_to_doctor:
        # Keep runtime consistent with Captain PASS status.
        captain["pass_to_doctor"] = True
        captain_issues = captain.get("issues", []) if isinstance(captain.get("issues"), list) else []
        captain["issues"] = ["captain_routing_autofix_pass_status", *captain_issues]
        captain_pass_to_doctor = True
    captain_failed = not (captain_pass_by_status or captain_pass_to_doctor)
    return captain_failed, captain_pass_by_status, captain_pass_to_doctor


def _doctor_analysis(
    *,
    run_id: str,
    hypothesis: str,
    historical_context_pack: list[dict[str, Any]],
    backend_name: str,
    model_chain: tuple[str, ...],
    edge_backend_name: str,
    edge_model_name: str,
    simulate_cloud_outage: bool = False,
    allow_heuristic_edge_fallback: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    system_prompt = (
        "You are Doctor, a causal analyst for A/B governance. "
        "You detect false-success patterns where local wins hide systemic losses, "
        "but you must balance protection with innovation speed using Calculated Risk."
    )
    user_prompt = (
        "Return ONLY one JSON object with keys exactly:\n"
        "analysis_note, causal_story, risk_signals, suggested_decision, recommended_actions.\n"
        "Rules:\n"
        "- suggested_decision must be STOP_ROLLOUT or HOLD_NEED_DATA or GO.\n"
        "- Use STOP_ROLLOUT only with strong, concrete evidence of material guardrail harm.\n"
        "- A single weak or low-similarity historical analog is NOT enough for STOP.\n"
        "- If risk is theoretical/minor and primary upside is clear, choose GO with monitoring actions.\n"
        "- Use HOLD_NEED_DATA only when critical evidence is missing or contradictory.\n"
        "- risk_signals and recommended_actions must be arrays of short strings.\n\n"
        f"Incoming hypothesis:\n{hypothesis}\n\n"
        f"Historical context pack:\n{json.dumps(historical_context_pack, ensure_ascii=False, indent=2)}\n"
    )
    raw = ""
    meta: dict[str, Any] = {}
    attempted_models: list[str] = []
    last_exc: Exception | None = None
    cloud_failures: list[str] = []
    for model_name in model_chain:
        attempted_models.append(model_name)
        try:
            if simulate_cloud_outage and backend_name in {"groq", "auto"}:
                raise RuntimeError("simulated_cloud_outage_doctor")
            raw, meta = _call_llm_with_observability(
                run_id=run_id,
                agent_name="doctor",
                backend_name=backend_name,
                model_name=model_name,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            break
        except Exception as exc:
            print(f"[DEBUG CLOUD ERROR] Model {model_name} failed: {repr(exc)}")
            last_exc = exc
            cloud_failures.append(str(exc).splitlines()[0][:220])
            continue
    edge_fallback_used = False
    if not raw and edge_backend_name:
        try:
            raw, meta = _call_llm_with_observability(
                run_id=run_id,
                agent_name="doctor",
                backend_name=edge_backend_name,
                model_name=edge_model_name,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            edge_fallback_used = True
        except Exception as exc:
            last_exc = exc
    if not raw:
        if not allow_heuristic_edge_fallback:
            if last_exc:
                raise last_exc
            raise RuntimeError("Doctor cloud call failed and heuristic fallback disabled")
        reason = str(last_exc).splitlines()[0][:220] if last_exc else "doctor_edge_unavailable"
        top_breach_metric = ""
        top_similarity = 0.0
        if historical_context_pack:
            top = historical_context_pack[0] if isinstance(historical_context_pack[0], dict) else {}
            if isinstance(top, dict):
                top_breach_metric = str(((top.get("guardrail_breach") or {}).get("metric_id") or "")).strip()
                top_similarity = float(top.get("similarity") or 0.0)
        heuristic_risk_signals = ["cloud_unavailable", "edge_model_unavailable"]
        if top_breach_metric:
            heuristic_risk_signals.append(f"historical_guardrail_breach:{top_breach_metric}")
        if top_similarity > 0:
            heuristic_risk_signals.append(f"historical_similarity:{round(top_similarity,4)}")
        meta = _append_synthetic_trace(
            run_id=run_id,
            agent="doctor_edge_heuristic",
            backend=edge_backend_name or backend_name,
            model=edge_model_name or "edge_heuristic",
            reason=reason,
        )
        meta["attempted_models"] = attempted_models
        meta["cloud_failures"] = cloud_failures
        meta["edge_fallback_used"] = True
        meta["edge_backend"] = edge_backend_name or "edge_heuristic"
        meta["edge_model"] = edge_model_name or "edge_heuristic"
        result = {
            "analysis_note": "Cloud and local model unavailable; using deterministic edge heuristic.",
            "causal_story": "Decision inferred from historical analog guardrail patterns under degraded LLM availability.",
            "risk_signals": heuristic_risk_signals,
            "suggested_decision": _infer_binary_decision_from_context(
                historical_context_pack=historical_context_pack,
                hypothesis_text=hypothesis,
            ),
            "recommended_actions": [
                "Proceed with provisional decision.",
                "Queue mandatory cloud reconciliation once API recovers.",
            ],
            "provisional_local_edge_fallback": True,
            "raw_output": "",
        }
        return result, meta
    meta["attempted_models"] = attempted_models
    meta["cloud_failures"] = cloud_failures
    meta["edge_fallback_used"] = edge_fallback_used
    meta["edge_backend"] = edge_backend_name if edge_fallback_used else ""
    meta["edge_model"] = edge_model_name if edge_fallback_used else ""
    obj = parse_json_object_loose(raw) or {}
    if not obj:
        obj = {
            "analysis_note": coerce_string(raw, max_len=1200),
            "causal_story": "Unable to parse strict JSON from Doctor output.",
            "risk_signals": ["llm_json_parse_failed"],
            "suggested_decision": "HOLD_NEED_DATA",
            "recommended_actions": ["Retry Doctor analysis with stricter response contract."],
        }

    result = {
        "analysis_note": coerce_string(obj.get("analysis_note"), max_len=2000),
        "causal_story": coerce_string(obj.get("causal_story"), max_len=2000),
        "risk_signals": coerce_string_list(obj.get("risk_signals"), max_items=10, max_item_len=220),
        "suggested_decision": coerce_string(obj.get("suggested_decision"), default="HOLD_NEED_DATA", max_len=32).upper(),
        "recommended_actions": coerce_string_list(obj.get("recommended_actions"), max_items=10, max_item_len=220),
        "provisional_local_edge_fallback": edge_fallback_used,
        "raw_output": raw,
    }
    if result["suggested_decision"] not in {"STOP_ROLLOUT", "HOLD_NEED_DATA", "GO"}:
        result["suggested_decision"] = "HOLD_NEED_DATA"
    if edge_fallback_used and result["suggested_decision"] == "HOLD_NEED_DATA":
        result["suggested_decision"] = _infer_binary_decision_from_context(
            historical_context_pack=historical_context_pack,
            hypothesis_text=hypothesis,
        )
        result["recommended_actions"] = list(result.get("recommended_actions") or [])
        result["recommended_actions"].insert(0, "Mark as provisional and queue cloud reconciliation.")
    return result, meta


def _commander_decision(
    *,
    run_id: str,
    hypothesis: str,
    guardrails: dict[str, Any],
    historical_context_pack: list[dict[str, Any]],
    doctor: dict[str, Any],
    backend_name: str,
    primary_model: str,
    fallback_model: str,
    edge_backend_name: str,
    edge_model_name: str,
    simulate_cloud_outage: bool = False,
    allow_heuristic_edge_fallback: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    system_prompt = (
        "You are Commander, final decision authority for experiment governance. "
        "Produce executive-level concise output with strict JSON. "
        "Apply Calculated Risk: protect business from material harm without blocking safe iteration."
    )
    user_prompt = (
        "Return ONLY one JSON object with keys exactly:\n"
        "decision, executive_summary, rationale_bullets, next_steps.\n"
        "Rules:\n"
        "- decision must be STOP_ROLLOUT or HOLD_NEED_DATA or GO.\n"
        "- STOP_ROLLOUT only when there is clear evidence of material guardrail breach risk.\n"
        "- HOLD_NEED_DATA only when critical evidence is missing/contradictory.\n"
        "- If the risk to guardrail metrics is theoretical or minor, and the primary business metric lift is clear, you MUST choose GO.\n"
        "- Do not block safe iterations.\n"
        "- Quantitative claims must come strictly from provided inputs (especially historical_context_pack.*.delta_pct).\n"
        "- Do not invent percentages or monetary values.\n"
        "- If numeric evidence is unavailable, write [Needs Data].\n"
        "- In executive_summary or rationale_bullets, include estimated metric impact and risk exposure when supported by input data.\n"
        "- rationale_bullets and next_steps are arrays of short strings.\n\n"
        f"Incoming hypothesis:\n{hypothesis}\n\n"
        f"Guardrails:\n{json.dumps(guardrails, ensure_ascii=False, indent=2)}\n\n"
        f"Doctor analysis:\n{json.dumps(doctor, ensure_ascii=False, indent=2)}\n\n"
        f"Historical context pack:\n{json.dumps(historical_context_pack, ensure_ascii=False, indent=2)}\n"
    )

    raw = ""
    meta: dict[str, Any] = {}
    cloud_failures: list[str] = []
    try:
        if simulate_cloud_outage and backend_name in {"groq", "auto"}:
            raise RuntimeError("simulated_cloud_outage_commander")
        raw, meta = _call_llm_with_observability(
            run_id=run_id,
            agent_name="commander",
            backend_name=backend_name,
            model_name=primary_model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
    except Exception as exc_primary:
        print(f"[DEBUG CLOUD ERROR] Model {primary_model} failed: {repr(exc_primary)}")
        cloud_failures.append(str(exc_primary).splitlines()[0][:220])
        try:
            if simulate_cloud_outage and backend_name in {"groq", "auto"}:
                raise RuntimeError("simulated_cloud_outage_commander_fallback")
            raw, meta = _call_llm_with_observability(
                run_id=run_id,
                agent_name="commander",
                backend_name=backend_name,
                model_name=fallback_model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        except Exception as exc_fallback:
            print(f"[DEBUG CLOUD ERROR] Model {fallback_model} failed: {repr(exc_fallback)}")
            cloud_failures.append(str(exc_fallback).splitlines()[0][:220])
            raw = ""
            if edge_backend_name:
                try:
                    raw, meta = _call_llm_with_observability(
                        run_id=run_id,
                        agent_name="commander",
                        backend_name=edge_backend_name,
                        model_name=edge_model_name,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                    )
                    meta["edge_fallback_used"] = True
                    meta["edge_backend"] = edge_backend_name
                    meta["edge_model"] = edge_model_name
                except Exception as exc_edge:
                    if not allow_heuristic_edge_fallback:
                        raise exc_edge
                    reason = str(exc_edge).splitlines()[0][:220]
                    meta = _append_synthetic_trace(
                        run_id=run_id,
                        agent="commander_edge_heuristic",
                        backend=edge_backend_name or backend_name,
                        model=edge_model_name or "edge_heuristic",
                        reason=reason,
                    )
                    heuristic_decision = _infer_binary_decision_from_context(
                        historical_context_pack=historical_context_pack,
                        doctor_decision_hint=str(doctor.get("suggested_decision") or ""),
                        hypothesis_text=hypothesis,
                    )
                    result = {
                        "decision": heuristic_decision,
                        "executive_summary": "Cloud and local model unavailable; using deterministic edge heuristic.",
                        "rationale_bullets": [
                            "No cloud model available during runtime window.",
                            "Local edge model unavailable; fallback to deterministic policy.",
                            "Mandatory cloud reconciliation required.",
                        ],
                        "next_steps": [
                            "Reconcile with cloud model when API recovers.",
                            "Review provisional decision before irreversible rollout.",
                        ],
                        "provisional_local_edge_fallback": True,
                        "raw_output": "",
                    }
                    meta["edge_fallback_used"] = True
                    meta["edge_backend"] = edge_backend_name or "edge_heuristic"
                    meta["edge_model"] = edge_model_name or "edge_heuristic"
                    meta["cloud_failures"] = cloud_failures
                    return result, meta
            else:
                raise exc_fallback
    if "edge_fallback_used" not in meta:
        meta["edge_fallback_used"] = False
        meta["edge_backend"] = ""
        meta["edge_model"] = ""
    meta["cloud_failures"] = cloud_failures

    obj = parse_json_object_loose(raw) or {}
    if not obj:
        obj = {
            "decision": "HOLD_NEED_DATA",
            "executive_summary": "Commander could not return strict JSON output.",
            "rationale_bullets": ["llm_json_parse_failed"],
            "next_steps": ["Retry Commander call with stricter JSON response contract."],
        }

    result = {
        "decision": coerce_string(obj.get("decision"), default="HOLD_NEED_DATA", max_len=32).upper(),
        "executive_summary": coerce_string(obj.get("executive_summary"), max_len=2000),
        "rationale_bullets": coerce_string_list(obj.get("rationale_bullets"), max_items=8, max_item_len=220),
        "next_steps": coerce_string_list(obj.get("next_steps"), max_items=8, max_item_len=220),
        "provisional_local_edge_fallback": bool(meta.get("edge_fallback_used")),
        "raw_output": raw,
    }
    if result["decision"] not in {"STOP_ROLLOUT", "HOLD_NEED_DATA", "GO"}:
        result["decision"] = "HOLD_NEED_DATA"
    if bool(meta.get("edge_fallback_used")) and result["decision"] == "HOLD_NEED_DATA":
        result["decision"] = _infer_binary_decision_from_context(
            historical_context_pack=historical_context_pack,
            doctor_decision_hint=str(doctor.get("suggested_decision") or ""),
            hypothesis_text=hypothesis,
        )
        result["rationale_bullets"] = list(result.get("rationale_bullets") or [])
        result["rationale_bullets"].insert(0, "Decision generated on local edge fallback.")
    return result, meta


def _build_one_page_card(
    *,
    run_id: str,
    hypothesis: str,
    captain: dict[str, Any],
    doctor: dict[str, Any],
    commander: dict[str, Any],
    historical_context_pack: list[dict[str, Any]],
    provisional_local_fallback: bool,
    reconciliation: dict[str, Any] | None,
    out_path: Path,
) -> str:
    lines: list[str] = []
    title_prefix = f"{PROVISIONAL_LOCAL_TAG} " if provisional_local_fallback else ""
    lines.append(f"# {title_prefix}One-Page Decision Card (Sprint-2 POC) — {run_id}")
    lines.append("")
    lines.append(f"- Generated at: `{datetime.now(timezone.utc).isoformat()}`")
    lines.append(f"- Hypothesis: `{hypothesis}`")
    lines.append(f"- Final Decision: `{commander.get('decision')}`")
    lines.append(f"- Provisional local fallback: `{str(provisional_local_fallback).lower()}`")
    lines.append("")
    lines.append("## Captain Sanity Check")
    lines.append(f"- Sanity status: {captain.get('sanity_status')}")
    captain_issues = captain.get("issues", [])
    if isinstance(captain_issues, list) and captain_issues:
        for issue in captain_issues[:8]:
            lines.append(f"- {issue}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(str(commander.get("executive_summary", "")).strip() or "No summary.")
    lines.append("")
    lines.append("## Doctor Causal Analysis")
    lines.append(f"- Analysis note: {doctor.get('analysis_note')}")
    lines.append(f"- Causal story: {doctor.get('causal_story')}")
    risk_signals = doctor.get("risk_signals", [])
    if isinstance(risk_signals, list) and risk_signals:
        lines.append("- Risk signals:")
        for r in risk_signals[:8]:
            lines.append(f"  - {r}")
    lines.append("")
    lines.append("## Retrieved Historical Evidence")
    for row in historical_context_pack[:5]:
        lines.append(
            f"- `{row.get('experiment_id')}` similarity=`{row.get('similarity')}` "
            f"primary_metric=`{(row.get('primary_metric_outcome') or {}).get('metric_id')}` "
            f"guardrail_breach=`{(row.get('guardrail_breach') or {}).get('metric_id')}`"
        )
    lines.append("")
    lines.append("## Commander Rationale")
    rationale = commander.get("rationale_bullets", [])
    if isinstance(rationale, list) and rationale:
        for b in rationale[:8]:
            lines.append(f"- {b}")
    else:
        lines.append("- No rationale bullets.")
    lines.append("")
    lines.append("## Next Steps")
    next_steps = commander.get("next_steps", [])
    if isinstance(next_steps, list) and next_steps:
        for s in next_steps[:8]:
            lines.append(f"- {s}")
    else:
        lines.append("- No next steps.")
    if reconciliation:
        lines.append("")
        lines.append("## Cloud Reconciliation")
        lines.append(f"- Status: {reconciliation.get('status')}")
        lines.append(f"- Cloud decision: {reconciliation.get('cloud_decision')}")
        lines.append(f"- Agreement with provisional: {reconciliation.get('decision_match')}")
        notes = reconciliation.get("notes")
        if notes:
            lines.append(f"- Notes: {notes}")

    md = "\n".join(lines)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    return md


def _run_cloud_reconciliation(
    *,
    run_id: str,
    hypothesis: str,
    guardrails: dict[str, Any],
    historical_context_pack: list[dict[str, Any]],
    provisional_decision: str,
    doctor_model_chain: tuple[str, ...],
    commander_primary_model: str,
    commander_fallback_model: str,
) -> dict[str, Any]:
    try:
        doctor_cloud, _ = _doctor_analysis(
            run_id=run_id,
            hypothesis=hypothesis,
            historical_context_pack=historical_context_pack,
            backend_name="groq",
            model_chain=doctor_model_chain,
            edge_backend_name="",
            edge_model_name="",
            simulate_cloud_outage=False,
            allow_heuristic_edge_fallback=False,
        )
        commander_cloud, _ = _commander_decision(
            run_id=run_id,
            hypothesis=hypothesis,
            guardrails=guardrails,
            historical_context_pack=historical_context_pack,
            doctor=doctor_cloud,
            backend_name="groq",
            primary_model=commander_primary_model,
            fallback_model=commander_fallback_model,
            edge_backend_name="",
            edge_model_name="",
            simulate_cloud_outage=False,
            allow_heuristic_edge_fallback=False,
        )
        cloud_decision = str(commander_cloud.get("decision") or "HOLD_NEED_DATA")
        return {
            "status": "COMPLETED",
            "cloud_decision": cloud_decision,
            "provisional_decision": provisional_decision,
            "decision_match": bool(cloud_decision == provisional_decision),
            "notes": "",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        print(f"[DEBUG CLOUD ERROR] Model reconciliation_chain failed: {repr(exc)}")
        return {
            "status": "FAILED",
            "cloud_decision": "UNAVAILABLE",
            "provisional_decision": provisional_decision,
            "decision_match": False,
            "notes": str(exc).splitlines()[0][:260],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


def _update_reconciliation_accuracy(*, run_id: str, reconciliation: dict[str, Any]) -> dict[str, Any]:
    event = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": str(reconciliation.get("status") or "UNKNOWN"),
        "decision_match": bool(reconciliation.get("decision_match")),
        "cloud_decision": str(reconciliation.get("cloud_decision") or "UNAVAILABLE"),
        "provisional_decision": str(reconciliation.get("provisional_decision") or "UNKNOWN"),
    }
    RECONCILIATION_EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RECONCILIATION_EVENTS_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

    total_events = 0
    completed_events = 0
    matched_events = 0
    failed_events = 0
    with RECONCILIATION_EVENTS_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            total_events += 1
            status = str(row.get("status") or "").upper()
            if status == "COMPLETED":
                completed_events += 1
                if bool(row.get("decision_match")):
                    matched_events += 1
            elif status == "FAILED":
                failed_events += 1

    match_rate = (matched_events / completed_events) if completed_events > 0 else None
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": total_events,
        "completed_events": completed_events,
        "failed_events": failed_events,
        "matched_events": matched_events,
        "match_rate": (round(match_rate, 4) if match_rate is not None else None),
        "source_events_path": str(RECONCILIATION_EVENTS_PATH),
    }
    RECONCILIATION_SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    RECONCILIATION_SUMMARY_PATH.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return summary


def _commander_interactive_reply(
    *,
    run_id: str,
    turn_index: int,
    question: str,
    hypothesis: str,
    guardrails: dict[str, Any],
    historical_context_pack: list[dict[str, Any]],
    doctor: dict[str, Any],
    commander: dict[str, Any],
    backend_name: str,
    primary_model: str,
    fallback_model: str,
) -> tuple[str, dict[str, Any]]:
    compact_context = {
        "hypothesis": hypothesis,
        "guardrails": guardrails,
        "history": [
            {
                "experiment_id": row.get("experiment_id"),
                "similarity": row.get("similarity"),
                "primary_metric": (row.get("primary_metric_outcome") or {}).get("metric_id"),
                "guardrail_breach": (row.get("guardrail_breach") or {}).get("metric_id"),
                "historical_decision": (row.get("reasoning_decision") or {}).get("decision"),
            }
            for row in historical_context_pack[:3]
        ],
        "doctor_summary": {
            "analysis_note": doctor.get("analysis_note"),
            "causal_story": doctor.get("causal_story"),
            "risk_signals": doctor.get("risk_signals"),
            "suggested_decision": doctor.get("suggested_decision"),
        },
        "commander_summary": {
            "decision": commander.get("decision"),
            "executive_summary": commander.get("executive_summary"),
            "rationale_bullets": commander.get("rationale_bullets"),
            "next_steps": commander.get("next_steps"),
        },
    }
    system_prompt = (
        "You are Commander in Interactive Audit mode. "
        "You must answer ONLY using current run context and prior decision artifacts. "
        "If user asks unrelated topics, refuse briefly and redirect to audit scope. "
        "Keep answers concise, business-focused, and safety-oriented. "
        "Use Calculated Risk framing: distinguish material evidence from theoretical risk."
    )
    user_prompt = (
        f"Turn: {turn_index}/{INTERACTIVE_MAX_TURNS}\n"
        "Current audit context JSON:\n"
        f"{json.dumps(compact_context, ensure_ascii=False, indent=2)}\n\n"
        "User question:\n"
        f"{question}\n\n"
        "Answer in plain text with 2-6 short bullet points. "
        "Do not invent data beyond provided context."
    )
    try:
        return _call_llm_with_observability(
            run_id=run_id,
            agent_name="commander_interactive",
            backend_name=backend_name,
            model_name=primary_model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
    except Exception as exc_primary:
        print(f"[DEBUG CLOUD ERROR] Model {primary_model} failed: {repr(exc_primary)}")
        try:
            return _call_llm_with_observability(
                run_id=run_id,
                agent_name="commander_interactive",
                backend_name=backend_name,
                model_name=fallback_model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        except Exception as exc_fallback:
            print(f"[DEBUG CLOUD ERROR] Model {fallback_model} failed: {repr(exc_fallback)}")
            raise


def _interactive_audit_loop(
    *,
    run_id: str,
    hypothesis: str,
    guardrails: dict[str, Any],
    historical_context_pack: list[dict[str, Any]],
    doctor: dict[str, Any],
    commander: dict[str, Any],
    backend_name: str,
    primary_model: str,
    fallback_model: str,
) -> None:
    print("")
    print(f"=== Interactive Audit (max {INTERACTIVE_MAX_TURNS} turns) ===")
    print("Type your question, or `exit`/`quit` to stop.")
    turns_used = 0
    while turns_used < INTERACTIVE_MAX_TURNS:
        raw = input("audit> ").strip()
        if not raw:
            continue
        if raw.lower() in {"exit", "quit"}:
            print("Interactive audit closed.")
            return
        turns_used += 1
        try:
            answer, meta = _commander_interactive_reply(
                run_id=run_id,
                turn_index=turns_used,
                question=raw,
                hypothesis=hypothesis,
                guardrails=guardrails,
                historical_context_pack=historical_context_pack,
                doctor=doctor,
                commander=commander,
                backend_name=backend_name,
                primary_model=primary_model,
                fallback_model=fallback_model,
            )
        except Exception as exc:
            reason = f"interactive_backend_error:{str(exc).splitlines()[0][:220]}"
            _append_synthetic_trace(
                run_id=run_id,
                agent="commander_interactive_failed",
                backend=backend_name,
                model=primary_model,
                reason=reason,
            )
            print("commander> HOLD_NEED_DATA: Interactive audit unavailable due to backend error.")
            print("Interactive audit closed (fail-closed).")
            return
        print(f"commander[{turns_used}]> {answer}")
        print(
            f"usage model={meta.get('model')} tokens={meta.get('total_tokens')} "
            f"cost_usd_estimate={meta.get('cost_usd_estimate')}"
        )
    print("Interactive audit closed: max turns reached (5).")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sprint-2 POC: RAG + Doctor + Commander (Groq API) + reasoning trace.")
    parser.add_argument("--run-id", default="sprint2_poc")
    parser.add_argument(
        "--query",
        required=True,
        help="Incoming high-risk guardrail scenario hypothesis text",
    )
    parser.add_argument("--sot-path", default="data/poc/history_sot_v1.json")
    parser.add_argument("--index-path", default="data/poc/history_vector_index_v1.json")
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--backend", choices=["groq", "auto", "ollama"], default="groq")
    parser.add_argument("--captain-model", default=CAPTAIN_GROQ_MODEL)
    parser.add_argument("--doctor-model", default=DOCTOR_GROQ_PRIMARY_MODEL)
    parser.add_argument("--doctor-fallback-model", default="")
    parser.add_argument("--commander-model", default=COMMANDER_GROQ_PRIMARY_MODEL)
    parser.add_argument("--commander-fallback-model", default=COMMANDER_GROQ_FALLBACK_MODEL)
    parser.add_argument("--edge-backend", choices=["ollama"], default="ollama")
    parser.add_argument("--edge-model", default=OLLAMA_MODEL_DEFAULT)
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--simulate-cloud-outage", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument(
        "--write-card",
        type=int,
        default=1,
        choices=(0, 1),
        help="Write per-run markdown decision card (default: 1). Set 0 for batch runs.",
    )
    parser.add_argument(
        "--batch-record-out",
        default="",
        help="Optional explicit artifact path for batch transport (policy: no stdout-ingest).",
    )
    args = parser.parse_args()

    sanitization_kms_loaded, sanitization_kms_source = _ensure_sanitization_kms_master_key()
    need_cloud = _cloud_path_requested(args.backend) or bool(args.reconcile)
    cloud_credentials_loaded, cloud_secret_source, cloud_api_key = _load_groq_secrets_conditional(
        need_cloud=need_cloud,
        strict=bool(args.reconcile),
    )
    global RUNTIME_GROQ_API_KEY
    RUNTIME_GROQ_API_KEY = str(cloud_api_key or "").strip()

    sot_path = Path(args.sot_path)
    index_path = Path(args.index_path)
    if not sot_path.exists():
        raise SystemExit(f"Missing SoT file: {sot_path}")
    if not index_path.exists():
        raise SystemExit(f"Missing index file: {index_path}")

    sot = _load_json(sot_path)
    index = _load_json(index_path)
    matches = retrieve_similar_experiments(query_text=args.query, sot=sot, vector_index=index, top_k=args.top_k)
    context_pack = _build_historical_context_pack(matches)

    guardrails = {
        "margin_floor": 0.0,
        "fill_rate_units_min": 0.90,
        "oos_lost_gmv_rate_max": 0.10,
    }

    captain, captain_meta = _captain_sanity_check(
        run_id=args.run_id,
        hypothesis=args.query,
        backend_name=args.backend,
        model_name=args.captain_model,
        edge_backend_name=args.edge_backend,
        edge_model_name=args.edge_model,
        simulate_cloud_outage=args.simulate_cloud_outage,
    )
    captain_failed, captain_pass_by_status, captain_pass_to_doctor = _normalize_captain_gate(captain)
    captain_failed_on_edge = captain_failed and bool(captain_meta.get("edge_fallback_used"))
    captain_provisional_review_required = captain_failed_on_edge

    if captain_failed and not captain_failed_on_edge:
        doctor = {
            "analysis_note": "Skipped because Captain failed sanity check.",
            "causal_story": "",
            "risk_signals": ["captain_failed_sanity_check"],
            "suggested_decision": "HOLD_NEED_DATA",
            "recommended_actions": ["Fix malformed hypothesis and rerun."],
            "raw_output": "",
        }
        doctor_meta = {
            "run_id": args.run_id,
            "agent": "doctor",
            "model": args.doctor_model,
            "attempted_models": [],
            "backend": args.backend,
            "total_tokens": 0,
            "cost_usd_estimate": 0.0,
            "reason": "captain_failed_sanity_check",
        }
        _append_synthetic_trace(
            run_id=args.run_id,
            agent="doctor_skipped",
            backend=args.backend,
            model=args.doctor_model,
            reason="captain_failed_sanity_check",
        )
        commander = {
            "decision": "HOLD_NEED_DATA",
            "executive_summary": "Run blocked by Captain sanity check before deep analysis.",
            "rationale_bullets": ["captain_failed_sanity_check"],
            "next_steps": ["Correct input hypothesis and rerun Captain."],
            "raw_output": "",
        }
        commander_meta = {
            "run_id": args.run_id,
            "agent": "commander",
            "model": args.commander_model,
            "backend": args.backend,
            "total_tokens": 0,
            "cost_usd_estimate": 0.0,
            "reason": "captain_failed_sanity_check",
        }
        _append_synthetic_trace(
            run_id=args.run_id,
            agent="commander_skipped",
            backend=args.backend,
            model=args.commander_model,
            reason="captain_failed_sanity_check",
        )
    else:
        if captain_provisional_review_required:
            _append_synthetic_trace(
                run_id=args.run_id,
                agent="captain_provisional_review_required",
                backend=args.edge_backend if bool(captain_meta.get("edge_fallback_used")) else args.backend,
                model=str(captain_meta.get("model") or args.captain_model),
                reason="captain_failed_sanity_check_on_edge_fallback",
            )
        doctor_model_chain = doctor_reasoning_model_chain(
            primary_override=args.doctor_model,
            fallback_override=args.doctor_fallback_model,
        )
        doctor, doctor_meta = _doctor_analysis(
            run_id=args.run_id,
            hypothesis=args.query,
            historical_context_pack=context_pack,
            backend_name=args.backend,
            model_chain=doctor_model_chain,
            edge_backend_name=args.edge_backend,
            edge_model_name=args.edge_model,
            simulate_cloud_outage=args.simulate_cloud_outage,
        )
        commander, commander_meta = _commander_decision(
            run_id=args.run_id,
            hypothesis=args.query,
            guardrails=guardrails,
            historical_context_pack=context_pack,
            doctor=doctor,
            backend_name=args.backend,
            primary_model=args.commander_model,
            fallback_model=args.commander_fallback_model,
            edge_backend_name=args.edge_backend,
            edge_model_name=args.edge_model,
            simulate_cloud_outage=args.simulate_cloud_outage,
        )
        if captain_provisional_review_required:
            commander_decision_raw = str(commander.get("decision") or "HOLD_NEED_DATA").upper()
            commander["pre_ceiling_decision"] = commander_decision_raw
            commander["decision"] = "HOLD_NEED_DATA"
            commander["review_reason"] = "captain_failed_sanity_check_on_edge_fallback"
            commander["decision_ceiling"] = "HOLD_NEED_DATA"
            commander["rationale_bullets"] = list(commander.get("rationale_bullets") or [])
            commander["rationale_bullets"].insert(
                0, "Captain sanity failed under edge fallback; manual review required."
            )

    provisional_local_fallback = bool(
        captain_meta.get("edge_fallback_used")
        or doctor_meta.get("edge_fallback_used")
        or commander_meta.get("edge_fallback_used")
    )
    fallback_agents: list[str] = []
    if bool(captain_meta.get("edge_fallback_used")):
        fallback_agents.append("captain")
    if bool(doctor_meta.get("edge_fallback_used")):
        fallback_agents.append("doctor")
    if bool(commander_meta.get("edge_fallback_used")):
        fallback_agents.append("commander")
    needs_cloud_reconciliation = provisional_local_fallback
    reconciliation: dict[str, Any] | None = None
    reconciliation_accuracy_summary: dict[str, Any] | None = None
    if provisional_local_fallback:
        _append_synthetic_trace(
            run_id=args.run_id,
            agent="provisional_local_edge_fallback",
            backend=args.edge_backend,
            model=args.edge_model,
            reason=f"agents={','.join(fallback_agents)}",
        )
    if args.reconcile and needs_cloud_reconciliation:
        reconciliation = _run_cloud_reconciliation(
            run_id=f"{args.run_id}_reconcile",
            hypothesis=args.query,
            guardrails=guardrails,
            historical_context_pack=context_pack,
            provisional_decision=str(commander.get("decision") or "HOLD_NEED_DATA"),
            doctor_model_chain=doctor_model_chain if captain.get("pass_to_doctor") else doctor_reasoning_model_chain(
                primary_override=args.doctor_model,
                fallback_override=args.doctor_fallback_model,
            ),
            commander_primary_model=args.commander_model,
            commander_fallback_model=args.commander_fallback_model,
        )
        reconciliation_accuracy_summary = _update_reconciliation_accuracy(
            run_id=args.run_id,
            reconciliation=reconciliation,
        )

    out_dir = Path(f"reports/L1_ops/{args.run_id}")
    out_card = out_dir / "POC_DECISION_CARD_SPRINT2.md"
    full_payload_path = Path(f"data/agent_reports/{args.run_id}_poc_sprint2.json")
    batch_record_out_path = Path(str(args.batch_record_out).strip()) if str(args.batch_record_out or "").strip() else None
    card = ""
    if bool(args.write_card):
        card = _build_one_page_card(
            run_id=args.run_id,
            hypothesis=args.query,
            captain=captain,
            doctor=doctor,
            commander=commander,
            historical_context_pack=context_pack,
            provisional_local_fallback=provisional_local_fallback,
            reconciliation=reconciliation,
            out_path=out_card,
        )

    generated_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "run_id": args.run_id,
        "query": args.query,
        "generated_at": generated_at,
        "groq_secrets_source": cloud_secret_source,
        "cloud_credentials_loaded": cloud_credentials_loaded,
        "sanitization_kms_loaded": sanitization_kms_loaded,
        "sanitization_kms_source": sanitization_kms_source,
        "retrieval_top_k": args.top_k,
        "top_matches": context_pack,
        "captain": captain,
        "captain_usage": captain_meta,
        "doctor": doctor,
        "doctor_usage": doctor_meta,
        "commander": commander,
        "commander_usage": commander_meta,
        "trace_path": str(TRACE_PATH),
        "version": "poc_sprint2.v1",
        "needs_cloud_reconciliation": needs_cloud_reconciliation,
        "reconciliation": reconciliation,
        "reconciliation_accuracy_summary": reconciliation_accuracy_summary,
        "transport": {
            "batch_record_out_used": bool(batch_record_out_path),
            "artifact_path": str(batch_record_out_path or full_payload_path),
        },
    }
    captain_reason = str((captain_meta.get("reason") if isinstance(captain_meta, dict) else "") or "")
    captain_issues = captain.get("issues", []) if isinstance(captain, dict) else []
    captain_edge_fallback_used = bool(captain_meta.get("edge_fallback_used"))
    captain_cloud_error = bool(captain_meta.get("captain_backend_error"))
    captain_backend_error = bool(
        captain_cloud_error
        and not captain_edge_fallback_used
        and (
            any(str(x).strip().lower() == "captain_backend_error" for x in captain_issues)
            or ("captain_backend_error" in captain_reason.lower())
        )
    )
    backend_error = captain_backend_error or _looks_like_api_error(captain_reason)
    captain_cloud_failures = captain_meta.get("cloud_failures", []) if isinstance(captain_meta, dict) else []
    doctor_cloud_failures = doctor_meta.get("cloud_failures", []) if isinstance(doctor_meta, dict) else []
    commander_cloud_failures = commander_meta.get("cloud_failures", []) if isinstance(commander_meta, dict) else []
    cloud_failure_notes = [str(x) for x in [*captain_cloud_failures, *doctor_cloud_failures, *commander_cloud_failures] if str(x).strip()]
    cloud_backend_error = bool(cloud_failure_notes)
    payload["runtime_flags"] = {
        "backend_error": backend_error or cloud_backend_error,
        "captain_backend_error": captain_backend_error,
        "captain_cloud_error": captain_cloud_error,
        "captain_edge_fallback_used": captain_edge_fallback_used,
        "cloud_backend_error": cloud_backend_error,
        "provisional_local_fallback": provisional_local_fallback,
        "fallback_agents": fallback_agents,
        "needs_cloud_reconciliation": needs_cloud_reconciliation,
        "provisional_review_required": captain_provisional_review_required,
        "retryable_api_error": _looks_like_retryable_api_error(
            "\n".join([captain_reason, *cloud_failure_notes])
        ),
        "captain_error_reason": captain_reason[:300],
        "cloud_failure_notes": cloud_failure_notes[:8],
    }
    written_artifact_path = full_payload_path
    if batch_record_out_path:
        batch_record = _build_batch_record_v2(
            run_id=args.run_id,
            query=args.query,
            generated_at=generated_at,
            captain=captain,
            doctor=doctor,
            commander=commander,
            captain_usage=captain_meta,
            doctor_usage=doctor_meta,
            commander_usage=commander_meta,
            runtime_flags=payload["runtime_flags"],
            retrieval_top_k=args.top_k,
            top_matches=context_pack,
            needs_cloud_reconciliation=needs_cloud_reconciliation,
            reconciliation=reconciliation,
        )
        batch_record_contract = _load_batch_record_contract()
        _validate_batch_record_payload(batch_record, batch_record_contract)
        batch_record_out_path.parent.mkdir(parents=True, exist_ok=True)
        batch_record_out_path.write_text(json.dumps(batch_record, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(batch_record_out_path)
        written_artifact_path = batch_record_out_path
    else:
        full_payload_path.parent.mkdir(parents=True, exist_ok=True)
        full_payload_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(full_payload_path)

    print("=== Sprint-2 POC E2E ===")
    print(f"run_id={args.run_id}")
    print(f"query={args.query}")
    if matches:
        top = matches[0]
        print(
            f"top_match={top.experiment_id} similarity={top.score} "
            f"primary_metric={top.primary_metric_outcome.get('metric_id')} "
            f"guardrail_breach={top.guardrail_breach.get('metric_id')}"
        )
    else:
        print("top_match=none")
    print(
        f"captain_model={captain_meta.get('model')} captain_tokens={captain_meta.get('total_tokens')} "
        f"captain_cost_usd_estimate={captain_meta.get('cost_usd_estimate')} captain_status={captain.get('sanity_status')}"
    )
    print(
        f"doctor_model={doctor_meta.get('model')} doctor_tokens={doctor_meta.get('total_tokens')} "
        f"doctor_cost_usd_estimate={doctor_meta.get('cost_usd_estimate')}"
    )
    attempted = doctor_meta.get("attempted_models")
    if isinstance(attempted, list) and attempted:
        print(f"doctor_attempted_models={','.join(str(x) for x in attempted)}")
    print(
        f"commander_model={commander_meta.get('model')} commander_tokens={commander_meta.get('total_tokens')} "
        f"commander_cost_usd_estimate={commander_meta.get('cost_usd_estimate')}"
    )
    print(f"provisional_local_fallback={str(provisional_local_fallback).lower()} fallback_agents={','.join(fallback_agents) if fallback_agents else 'none'}")
    print(f"needs_cloud_reconciliation={str(needs_cloud_reconciliation).lower()}")
    if reconciliation:
        print(
            f"reconciliation_status={reconciliation.get('status')} "
            f"cloud_decision={reconciliation.get('cloud_decision')} "
            f"decision_match={reconciliation.get('decision_match')}"
        )
    if reconciliation_accuracy_summary:
        print(
            f"reconciliation_match_rate={reconciliation_accuracy_summary.get('match_rate')} "
            f"completed_events={reconciliation_accuracy_summary.get('completed_events')} "
            f"total_events={reconciliation_accuracy_summary.get('total_events')}"
        )
    print(f"final_decision={commander.get('decision')}")
    print(f"decision_card={(str(out_card) if bool(args.write_card) else 'disabled')}")
    print(f"artifact_json={written_artifact_path}")
    print(f"artifact_json_sidecar={written_artifact_path}.sha256")
    print(f"reasoning_trace={TRACE_PATH}")
    if bool(args.write_card):
        print("")
        print(card)

    if args.interactive:
        _interactive_audit_loop(
            run_id=args.run_id,
            hypothesis=args.query,
            guardrails=guardrails,
            historical_context_pack=context_pack,
            doctor=doctor,
            commander=commander,
            backend_name=args.backend,
            primary_model=args.commander_model,
            fallback_model=args.commander_fallback_model,
        )


if __name__ == "__main__":
    main()
