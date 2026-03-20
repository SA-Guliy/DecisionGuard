from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from src.llm_secure_gateway import gateway_generate, get_llm_backend
from src.model_policy import (
    CAPTAIN_GROQ_MODEL,
    COMMANDER_GROQ_FALLBACK_MODEL,
    COMMANDER_GROQ_PRIMARY_MODEL,
    DOCTOR_GROQ_REASONING_CHAIN,
)


@dataclass
class FailoverTier:
    name: str
    backend_name: str
    model_name: str | None = None


ACTIVE_GROQ_MODELS: tuple[str, ...] = (
    CAPTAIN_GROQ_MODEL,
    *DOCTOR_GROQ_REASONING_CHAIN,
    COMMANDER_GROQ_PRIMARY_MODEL,
    COMMANDER_GROQ_FALLBACK_MODEL,
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "qwen/qwen3-32b",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
)

DECOMMISSIONED_GROQ_MODELS: tuple[str, ...] = (
    "deepseek-r1-distill-qwen-32b",
    "mixtral-8x7b-32768",
    "llama-3.1-70b-versatile",
)


def _clean_groq_model_ids(models: list[str] | tuple[str, ...]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    allow = {str(x).strip() for x in ACTIVE_GROQ_MODELS if str(x).strip()}
    deprecated = {str(x).strip() for x in DECOMMISSIONED_GROQ_MODELS if str(x).strip()}
    for raw in models:
        model = str(raw or "").strip()
        if not model or model in seen:
            continue
        seen.add(model)
        if model in deprecated:
            print(f"[DEBUG CLOUD ERROR] Model {model} failed: RuntimeError('model_decommissioned')")
            continue
        if model not in allow:
            print(f"[DEBUG CLOUD ERROR] Model {model} failed: RuntimeError('model_not_in_active_allowlist')")
            continue
        out.append(model)
    return out


def build_runtime_failover_tiers(
    *,
    backend_requested: str,
    groq_models: list[str] | tuple[str, ...] | None = None,
    include_ollama: bool = True,
) -> list[FailoverTier]:
    requested = str(backend_requested or "auto").strip().lower()
    tiers: list[FailoverTier] = []
    seen: set[tuple[str, str]] = set()

    def _add(name: str, backend_name: str, model_name: str | None) -> None:
        key = (str(backend_name), str(model_name or ""))
        if key in seen:
            return
        seen.add(key)
        tiers.append(FailoverTier(name=name, backend_name=backend_name, model_name=model_name))

    if requested in {"groq", "auto"}:
        preferred_models = [str(x).strip() for x in (groq_models or ACTIVE_GROQ_MODELS) if str(x).strip()]
        for model in _clean_groq_model_ids(preferred_models):
            _add(name=f"groq:{model}", backend_name="groq", model_name=model)
    if requested == "ollama":
        _add(name="ollama", backend_name="ollama", model_name=None)
    elif include_ollama:
        _add(name="ollama", backend_name="ollama", model_name=None)
    return tiers


def generate_with_runtime_failover(
    *,
    run_id: str,
    agent_name: str,
    call_name: str,
    prompt: str,
    system_prompt: str,
    tiers: list[FailoverTier],
    deterministic_generator: Callable[[], str] | None,
    groq_api_key: str | None = None,
) -> tuple[str, dict[str, Any]]:
    attempts: list[dict[str, Any]] = []

    for idx, tier in enumerate(tiers):
        try:
            backend = get_llm_backend(
                tier.backend_name,
                model_name=tier.model_name,
                api_key=groq_api_key,
            )
            model = str(getattr(backend, "get_model_name", lambda: "unknown")() or "unknown")
            if model == "local_mock":
                raise RuntimeError("local_mock_disallowed_by_failover_policy")
            output, meta = gateway_generate(
                backend=backend,
                run_id=run_id,
                agent_name=agent_name,
                call_name=call_name,
                prompt=prompt,
                system_prompt=system_prompt,
            )
            attempts.append(
                {
                    "tier": tier.name,
                    "backend": tier.backend_name,
                    "model": model,
                    "status": "PASS",
                }
            )
            return str(output or ""), {
                "selected_backend": tier.backend_name,
                "backend_requested": tier.backend_name,
                "selected_tier": tier.name,
                "selected_tier_index": idx,
                "fallback_tier": ("none" if idx == 0 else tier.name),
                "used_fallback": bool(idx > 0),
                "fallback_reason": (None if idx == 0 else "prior_tier_failed"),
                "provisional_local_fallback": bool(idx > 0 and tier.backend_name != "groq"),
                "needs_cloud_reconciliation": bool(idx > 0 and tier.backend_name != "groq"),
                "model": model,
                "obfuscation_map_ref": str(meta.get("obfuscation_map_ref", "")).strip(),
                "attempts": attempts,
                "sanitization_vectorization_applied": bool(meta.get("sanitization_vectorization_applied", False)),
                "response_deobfuscation_applied": bool(meta.get("response_deobfuscation_applied", False)),
                "response_deobfuscation_applied_actual": bool(meta.get("response_deobfuscation_applied_actual", False)),
                "response_deobfuscation_required": bool(meta.get("response_deobfuscation_required", False)),
            }
        except Exception as exc:
            if str(tier.backend_name or "").strip().lower() == "groq":
                print(f"[DEBUG CLOUD ERROR] Model {tier.model_name or 'unknown'} failed: {repr(exc)}")
            attempts.append(
                {
                    "tier": tier.name,
                    "backend": tier.backend_name,
                    "model": tier.model_name,
                    "status": "FAIL",
                    "reason": str(exc).splitlines()[0][:220],
                }
            )

    if deterministic_generator is None:
        raise RuntimeError(
            "runtime_failover_exhausted_without_deterministic:"
            + " | ".join(f"{a.get('tier')}:{a.get('reason', a.get('status'))}" for a in attempts)
        )

    output = str(deterministic_generator() or "")
    return output, {
        "backend_requested": "deterministic",
        "selected_tier": "deterministic",
        "selected_tier_index": len(tiers),
        "fallback_tier": "deterministic",
        "used_fallback": True,
        "fallback_reason": (
            "runtime_failover_exhausted:"
            + " | ".join(f"{a.get('tier')}:{a.get('reason', a.get('status'))}" for a in attempts)
        ),
        "provisional_local_fallback": True,
        "needs_cloud_reconciliation": True,
        "model": "deterministic_local",
        "obfuscation_map_ref": "",
        "attempts": attempts,
        "sanitization_vectorization_applied": False,
        "response_deobfuscation_applied": False,
        "response_deobfuscation_applied_actual": False,
        "response_deobfuscation_required": False,
    }
