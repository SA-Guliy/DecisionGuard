from __future__ import annotations

from src.config import GROQ_MODEL_DEFAULT

# Active agent model policy (single source of truth for role->model mapping).
# Keep "intent" models explicit even if provider-side availability changes;
# fallbacks should be surfaced in provenance, not hidden.

# Agent 1 (Captain): fast, cheap QA/sanity checks.
CAPTAIN_GROQ_MODEL = GROQ_MODEL_DEFAULT

# Agent 2 (Doctor): reasoning-first active Groq models.
# Keep only currently active provider IDs (deprecated models are excluded).
DOCTOR_GROQ_PRIMARY_MODEL = "qwen/qwen3-32b"
DOCTOR_GROQ_FALLBACK_MODEL = "openai/gpt-oss-120b"
DOCTOR_GROQ_SECONDARY_FALLBACK_MODEL = "llama-3.3-70b-versatile"
DOCTOR_GROQ_TERTIARY_FALLBACK_MODEL = "openai/gpt-oss-20b"

DOCTOR_GROQ_REASONING_CHAIN = (
    DOCTOR_GROQ_PRIMARY_MODEL,
    DOCTOR_GROQ_FALLBACK_MODEL,
    DOCTOR_GROQ_SECONDARY_FALLBACK_MODEL,
    DOCTOR_GROQ_TERTIARY_FALLBACK_MODEL,
)

# Agent 3 (Commander): final decision reasoning + causal trade-off analysis.
COMMANDER_GROQ_PRIMARY_MODEL = "qwen/qwen3-32b"
COMMANDER_GROQ_FALLBACK_MODEL = "llama-3.3-70b-versatile"


def groq_model_for_agent(agent: str, *, fallback: bool = False) -> str:
    a = str(agent or "").strip().lower()
    if a == "captain":
        return CAPTAIN_GROQ_MODEL
    if a == "doctor":
        return DOCTOR_GROQ_FALLBACK_MODEL if fallback else DOCTOR_GROQ_PRIMARY_MODEL
    if a == "commander":
        return COMMANDER_GROQ_FALLBACK_MODEL if fallback else COMMANDER_GROQ_PRIMARY_MODEL
    return GROQ_MODEL_DEFAULT


def doctor_reasoning_model_chain(
    *,
    primary_override: str | None = None,
    fallback_override: str | None = None,
) -> tuple[str, ...]:
    chain: list[str] = []
    if primary_override and str(primary_override).strip():
        chain.append(str(primary_override).strip())
    if fallback_override and str(fallback_override).strip():
        chain.append(str(fallback_override).strip())
    chain.extend(DOCTOR_GROQ_REASONING_CHAIN)

    out: list[str] = []
    seen: set[str] = set()
    for model in chain:
        m = str(model).strip()
        if not m or m in seen:
            continue
        out.append(m)
        seen.add(m)
    return tuple(out)
