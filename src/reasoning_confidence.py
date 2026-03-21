from __future__ import annotations

from typing import Any

from src.architecture_v3 import CONTRACTS_DIR, load_json_with_integrity

_POLICY_PATH = CONTRACTS_DIR / "reasoning_confidence_policy_v1.json"


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def load_reasoning_confidence_policy() -> dict[str, Any]:
    payload = load_json_with_integrity(_POLICY_PATH)
    if not isinstance(payload, dict):
        raise RuntimeError("invalid_reasoning_confidence_policy_payload")
    return payload


def compute_reasoning_confidence(
    layers_present: dict[str, Any],
    p_value: float | None,
    best_analog_similarity: float | None,
    guardrail_data_complete: bool,
    n_min: int,
    srm_pass: bool,
    *,
    mode: str = "single",
    paired_status: str = "SINGLE",
    has_live_evidence: bool = False,
) -> tuple[float, list[str]]:
    policy = load_reasoning_confidence_policy()
    basis: list[str] = []
    score = _to_float(policy.get("base_score"), 0.55)
    significant_max = _to_float(policy.get("significant_p_value_max"), 0.05)
    analog_weight = _to_float(policy.get("analog_similarity_weight"), 0.20)
    min_n = int(_to_float(policy.get("min_sample_size_n"), 30))
    penalties = policy.get("penalties", {}) if isinstance(policy.get("penalties"), dict) else {}
    caps = policy.get("caps", {}) if isinstance(policy.get("caps"), dict) else {}
    bounds = policy.get("score_bounds", {}) if isinstance(policy.get("score_bounds"), dict) else {}
    bound_min = _to_float(bounds.get("min"), 0.0)
    bound_max = _to_float(bounds.get("max"), 1.0)

    layer1 = bool(layers_present.get("layer1_live_stats", False))
    layer2 = bool(layers_present.get("layer2_guardrail_check", False))
    if not layer1:
        score -= _to_float(penalties.get("layer1_missing"), 0.20)
        basis.append("penalty:layer1_missing")
    if not layer2:
        score -= _to_float(penalties.get("layer2_missing"), 0.15)
        basis.append("penalty:layer2_missing")

    if not guardrail_data_complete:
        score -= _to_float(penalties.get("guardrail_data_incomplete"), 0.15)
        basis.append("penalty:guardrail_data_incomplete")

    if not srm_pass:
        score -= _to_float(penalties.get("srm_failed"), 0.12)
        basis.append("penalty:srm_failed")

    n_min_runtime = max(1, int(n_min or 0))
    if n_min_runtime < min_n:
        score -= _to_float(penalties.get("underpowered_or_no_data"), 0.18)
        basis.append("penalty:underpowered_sample_size")

    if p_value is not None:
        p = _to_float(p_value, 1.0)
        if p <= significant_max:
            score += 0.08
            basis.append("bonus:statistically_significant")
        else:
            basis.append("no_bonus:p_value_not_significant")
    else:
        score -= _to_float(penalties.get("underpowered_or_no_data"), 0.18)
        basis.append("penalty:missing_p_value")

    if best_analog_similarity is not None:
        sim = _clamp(_to_float(best_analog_similarity), 0.0, 1.0)
        score += analog_weight * sim
        basis.append(f"analog_similarity:{round(sim, 4)}")
    else:
        basis.append("analog_similarity:missing")

    mode_norm = str(mode or "single").strip().lower()
    paired_norm = str(paired_status or "SINGLE").strip().upper()
    if mode_norm == "single" and not has_live_evidence:
        cap = _to_float(caps.get("single_mode_no_live_evidence"), 0.64)
        score = min(score, cap)
        basis.append("cap:single_mode_no_live_evidence")
    if paired_norm in {"PARTIAL", "TREATMENT_FAILED", "CTRL_FAILED"}:
        cap = _to_float(caps.get("partial_or_failed_paired_status"), 0.60)
        score = min(score, cap)
        basis.append("cap:partial_or_failed_paired_status")
    if not layer1 or not layer2:
        cap = _to_float(caps.get("missing_layers12"), 0.62)
        score = min(score, cap)
        basis.append("cap:missing_layers12")

    score = _clamp(score, bound_min, bound_max)
    return round(score, 4), basis[:24]
