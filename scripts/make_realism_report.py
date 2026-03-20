#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Build human realism report")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--base-run-id", default="")
    args = parser.parse_args()

    run_id = args.run_id
    dq = _load(Path(f"data/dq_reports/{run_id}.json")) or {}
    snap = _load(Path(f"data/metrics_snapshots/{run_id}.json")) or {}

    rows = dq.get("rows", []) if isinstance(dq.get("rows"), list) else []
    metrics = snap.get("metrics", {}) if isinstance(snap.get("metrics"), dict) else {}
    run_cfg = snap.get("run_config", {}) if isinstance(snap.get("run_config"), dict) else {}

    anti_rows = [
        r
        for r in rows
        if isinstance(r, dict)
        and str(r.get("check_name", "")).startswith("anti_gaming_")
        and str(r.get("status", "")) in {"WARN", "FAIL"}
    ]
    fill_tail_row = next(
        (
            r for r in rows
            if isinstance(r, dict) and str(r.get("check_name", "")) in {"fill_rate_realism_bounds", "anti_gaming_fill_rate_tail_sanity"}
        ),
        {},
    )

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "realism_flags": {
            "enable_supply_realism": run_cfg.get("enable_supply_realism"),
            "enable_ops_noise": run_cfg.get("enable_ops_noise"),
            "enable_demand_shocks": run_cfg.get("enable_demand_shocks"),
            "enable_competitor_prices": run_cfg.get("enable_competitor_prices"),
            "perishable_remove_buffer_days": run_cfg.get("perishable_remove_buffer_days"),
        },
        "sterility_signals": {
            "fill_rate_mean": metrics.get("fill_rate_mean"),
            "fill_rate_units": metrics.get("fill_rate_units"),
            "full_order_share_from_dq": fill_tail_row.get("actual_value"),
            "shock_days_share": metrics.get("shock_days_share"),
            "shrink_units_rate": metrics.get("shrink_units_rate"),
            "supplier_fill_rate_mean": metrics.get("supplier_fill_rate_mean"),
        },
        "anti_gaming_signals": [
            {
                "check_name": r.get("check_name"),
                "status": r.get("status"),
                "severity": r.get("severity"),
                "actual_value": r.get("actual_value"),
                "message": r.get("message"),
            }
            for r in anti_rows
        ],
        "what_could_be_hacked": [
            "Tuning synthetic demand multipliers to force uplift without causal plausibility",
            "Reducing writeoff by starving availability instead of improving operations",
            "Overfitting to a single random seed",
        ],
        "mitigations_present": [
            "DQ anti-gaming checks with FAIL/WARN signaling",
            "Deterministic assignment + AB status gate",
            "Ensemble seed stability report (if available)",
        ],
    }

    out_json = Path(f"data/realism_reports/{run_id}_realism.json")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        f"# Synthetic Realism — {run_id}",
        "",
        "## Realism flags",
        f"- supply_realism: `{payload['realism_flags']['enable_supply_realism']}`",
        f"- ops_noise: `{payload['realism_flags']['enable_ops_noise']}`",
        f"- demand_shocks: `{payload['realism_flags']['enable_demand_shocks']}`",
        f"- competitor_prices: `{payload['realism_flags']['enable_competitor_prices']}`",
        f"- remove_buffer_days: `{payload['realism_flags']['perishable_remove_buffer_days']}`",
        "",
        "## Sterility signals",
        f"- fill_rate_mean: `{payload['sterility_signals']['fill_rate_mean']}`",
        f"- fill_rate_units: `{payload['sterility_signals']['fill_rate_units']}`",
        f"- full_order_share (dq): `{payload['sterility_signals']['full_order_share_from_dq']}`",
        f"- shock_days_share: `{payload['sterility_signals']['shock_days_share']}`",
        f"- shrink_units_rate: `{payload['sterility_signals']['shrink_units_rate']}`",
        f"- supplier_fill_rate_mean: `{payload['sterility_signals']['supplier_fill_rate_mean']}`",
        "",
        "## Anti-gaming signals",
    ]
    if payload["anti_gaming_signals"]:
        for s in payload["anti_gaming_signals"]:
            lines.append(f"- {s['check_name']}: {s['status']} ({s['severity']})")
    else:
        lines.append("- none")

    lines.extend(["", "## What could be hacked"])
    lines.extend([f"- {x}" for x in payload["what_could_be_hacked"]])
    lines.extend(["", "## Mitigations present"])
    lines.extend([f"- {x}" for x in payload["mitigations_present"]])

    out_md = Path(f"reports/L1_ops/{run_id}/synthetic_realism.md")
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"ok: realism report written for run_id={run_id}")


if __name__ == "__main__":
    main()
