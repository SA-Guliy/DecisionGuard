"""
Formats a StatEvidenceBundle dict into a compact text block for LLM prompts.

Shared by Doctor (run_doctor_variance.py) and Commander (run_commander_priority.py).
Never raises — safe to call unconditionally. Returns empty string when bundle
is absent, empty, or in FAIL state.
"""
from __future__ import annotations

from typing import Any


def format_stat_evidence_for_prompt(stat_bundle: dict[str, Any] | None) -> str:
    """
    Convert a StatEvidenceBundle dict into a concise, LLM-readable text section.

    Returns empty string if:
    - stat_bundle is None or not a dict
    - stat_bundle is empty
    - status is FAIL (gate already blocks; no point surfacing partial data)

    Otherwise returns a text block starting with a header line and containing:
    - SRM check result + sample sizes
    - Per-metric: metric_id, method, p-value, CI, verdict, guardrail breach flag
    - Guardrail summary: which metrics are in breach and block rollout
    """
    if not isinstance(stat_bundle, dict) or not stat_bundle:
        return ""

    status = str(stat_bundle.get("status", "")).strip().upper()
    if status == "FAIL":
        return ""

    lines: list[str] = []
    lines.append("## Statistical Evidence")

    # --- SRM + paired status ---
    srm_flag = bool(stat_bundle.get("srm_flag", False))
    paired_status = str(stat_bundle.get("paired_status", "SINGLE")).strip().upper()
    layers = stat_bundle.get("layers_present", {}) if isinstance(stat_bundle.get("layers_present"), dict) else {}
    layer1 = bool(layers.get("layer1_live_stats", False))
    layer2 = bool(layers.get("layer2_guardrail_check", False))

    lines.append(f"Status: {status} | Paired: {paired_status} | L1:{layer1} L2:{layer2}")

    srm_line = "SRM: FAIL — audience split is unreliable, treat results with caution" if srm_flag else "SRM: PASS"
    lines.append(srm_line)

    # --- Per-metric evidence ---
    metrics = stat_bundle.get("metrics", [])
    if isinstance(metrics, list) and metrics:
        lines.append("Metrics:")
        for row in metrics[:10]:  # cap at 10 to avoid bloating prompt
            if not isinstance(row, dict):
                continue
            mid = str(row.get("metric_id", "?"))
            method = str(row.get("method", "?"))
            verdict = str(row.get("verdict", "NO_DATA")).strip().upper()
            p_val = row.get("p_value")
            ci_lo = row.get("ci_lower")
            ci_hi = row.get("ci_upper")
            delta = row.get("delta")
            is_breach = bool(row.get("is_guardrail_breach", False))
            n_ctrl = row.get("n_ctrl", "?")
            n_trt = row.get("n_trt", "?")

            p_str = f"p={p_val:.4f}" if isinstance(p_val, (int, float)) else "p=n/a"
            ci_str = (
                f"CI=[{ci_lo:+.3f},{ci_hi:+.3f}]"
                if isinstance(ci_lo, (int, float)) and isinstance(ci_hi, (int, float))
                else "CI=n/a"
            )
            delta_str = f"delta={delta:+.4f}" if isinstance(delta, (int, float)) else ""
            breach_str = " ⚠ GUARDRAIL BREACH" if is_breach else ""
            n_str = f"n=({n_ctrl},{n_trt})" if isinstance(n_ctrl, int) and isinstance(n_trt, int) else ""

            # aggregate_only metrics have no p-value by design — note that explicitly
            if method == "aggregate_only":
                lines.append(
                    f"  {mid}: method=aggregate_only (no p-value — ratio metric) | {delta_str} | verdict={verdict}{breach_str}"
                )
            else:
                lines.append(
                    f"  {mid}: {p_str} {ci_str} {delta_str} {n_str} | verdict={verdict}{breach_str}"
                )

    # --- Guardrail summary ---
    guardrails = stat_bundle.get("guardrail_status_check", [])
    if isinstance(guardrails, list) and guardrails:
        blocking = [g for g in guardrails if isinstance(g, dict) and bool(g.get("blocks_rollout", False))]
        passing = [g for g in guardrails if isinstance(g, dict) and not bool(g.get("blocks_rollout", False))]
        if blocking:
            breach_ids = ", ".join(str(g.get("metric_id", "?")) for g in blocking)
            lines.append(f"Guardrail BREACH (blocks rollout): {breach_ids}")
        if passing:
            ok_ids = ", ".join(str(g.get("metric_id", "?")) for g in passing)
            lines.append(f"Guardrail OK: {ok_ids}")

    return "\n".join(lines)
