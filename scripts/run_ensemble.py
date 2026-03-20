#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


def _percentile(sorted_vals: list[float], q: float) -> float | None:
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = q * (len(sorted_vals) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    w = pos - lo
    return sorted_vals[lo] * (1 - w) + sorted_vals[hi] * w


def _summary(vals: list[float]) -> dict[str, float | None]:
    s = sorted(vals)
    return {
        "median": _percentile(s, 0.5),
        "p25": _percentile(s, 0.25),
        "p75": _percentile(s, 0.75),
    }


def _run(cmd: list[str], label: str, log_file: Path) -> int:
    env = dict(**__import__("os").environ)
    if "run_all.py" in " ".join(cmd):
        env["BASE_RUN_ID"] = label.rsplit("_s", 1)[0] if "_s" in label else label
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as f:
        f.write(f"\n=== {label} rc={res.returncode} ===\n")
        if res.stdout:
            f.write(res.stdout)
        if res.stderr:
            f.write(res.stderr)
    return res.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ensemble seeds for stability")
    parser.add_argument("--base-run-id", required=True)
    parser.add_argument("--seeds", default="101,202,303")
    parser.add_argument("--horizon-days", type=int, default=14)
    parser.add_argument("--backend", choices=["groq", "ollama", "auto"], default="auto")
    parser.add_argument("--mode-tag", default="default")
    parser.add_argument("--enable-customer-dynamics", type=int, default=1, choices=[0, 1])
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--experiment-unit", choices=["customer", "store"], default="customer")
    parser.add_argument("--experiment-treat-pct", type=int, default=50)
    parser.add_argument("--allow-overwrite-run", type=int, default=0, choices=[0, 1])
    parser.add_argument("--overwrite-reason", default="ensemble rerun")
    parser.add_argument("--enable-supply-realism", type=int, default=1, choices=[0, 1])
    parser.add_argument("--enable-ops-noise", type=int, default=1, choices=[0, 1])
    parser.add_argument("--enable-demand-shocks", type=int, default=1, choices=[0, 1])
    parser.add_argument("--enable-competitor-prices", type=int, default=0, choices=[0, 1])
    parser.add_argument("--perishable-remove-buffer-days", type=int, default=1)
    args = parser.parse_args()

    seeds = [int(x.strip()) for x in args.seeds.split(",") if x.strip()]
    log_file = Path(f"data/logs/ensemble_{args.base_run_id}.log")

    run_ids: list[str] = []
    failed: list[str] = []
    for seed in seeds:
        rid = f"{args.base_run_id}_s{seed}"
        run_ids.append(rid)
        cmd = [
            "python3",
            "scripts/run_all.py",
            "--run-id",
            rid,
            "--mode-tag",
            args.mode_tag,
            "--enable-customer-dynamics",
            str(args.enable_customer_dynamics),
            "--backend",
            args.backend,
            "--horizon-days",
            str(args.horizon_days),
            "--seed",
            str(seed),
            "--enable-supply-realism",
            str(args.enable_supply_realism),
            "--enable-ops-noise",
            str(args.enable_ops_noise),
            "--enable-demand-shocks",
            str(args.enable_demand_shocks),
            "--enable-competitor-prices",
            str(args.enable_competitor_prices),
            "--perishable-remove-buffer-days",
            str(args.perishable_remove_buffer_days),
        ]
        if args.allow_overwrite_run == 1:
            cmd.extend(["--allow-overwrite-run", "1", "--overwrite-reason", args.overwrite_reason])
        if args.experiment_id.strip():
            cmd.extend([
                "--experiment-id",
                args.experiment_id.strip(),
                "--experiment-unit",
                args.experiment_unit,
                "--experiment-treat-pct",
                str(args.experiment_treat_pct),
            ])
        rc = _run(cmd, rid, log_file)
        if rc != 0:
            failed.append(rid)

    keys = [
        "writeoff_rate_vs_requested_units",
        "gp_margin",
        "aov",
        "active_buyers_avg",
        "fill_rate_units",
        "oos_lost_gmv_rate",
    ]
    values: dict[str, list[float]] = {k: [] for k in keys}
    for rid in run_ids:
        p = Path(f"data/metrics_snapshots/{rid}.json")
        if not p.exists():
            continue
        try:
            m = json.loads(p.read_text(encoding="utf-8")).get("metrics", {})
        except Exception:
            continue
        if not isinstance(m, dict):
            continue
        for k in keys:
            try:
                values[k].append(float(m.get(k)))
            except Exception:
                pass

    metric_summary = {k: _summary(v) for k, v in values.items()}

    # Simple stability heuristic: sign consistency for (metric - first_seed_metric)
    sign_consistent = True
    for k in keys:
        arr = values[k]
        if len(arr) < 3:
            continue
        base = arr[0]
        signs = [1 if x - base > 0 else (-1 if x - base < 0 else 0) for x in arr[1:]]
        non_zero = [s for s in signs if s != 0]
        if non_zero:
            pos = sum(1 for s in non_zero if s > 0)
            neg = sum(1 for s in non_zero if s < 0)
            if max(pos, neg) < (2 * len(non_zero) / 3):
                sign_consistent = False

    iqr_ok = True
    for k, s in metric_summary.items():
        if s["p25"] is None or s["p75"] is None or s["median"] in {None, 0}:
            continue
        iqr = float(s["p75"]) - float(s["p25"])
        if abs(iqr) > abs(float(s["median"])) * 0.5:
            iqr_ok = False

    stability_pass = sign_consistent and iqr_ok and len(failed) == 0

    payload = {
        "base_run_id": args.base_run_id,
        "run_ids": run_ids,
        "failed_runs": failed,
        "seeds": seeds,
        "metrics": metric_summary,
        "stability_pass": stability_pass,
    }

    out_json = Path(f"data/ensemble_reports/{args.base_run_id}_ensemble.json")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    out_md = Path(f"reports/L1_ops/{args.base_run_id}/ensemble_summary.md")
    out_md.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Ensemble Summary — {args.base_run_id}",
        "",
        f"- seeds: `{seeds}`",
        f"- run_ids: `{run_ids}`",
        f"- failed_runs: `{failed}`",
        f"- stability_pass: `{stability_pass}`",
        "",
        "## Metrics (median / p25 / p75)",
    ]
    for k, s in metric_summary.items():
        lines.append(f"- {k}: median={s['median']} p25={s['p25']} p75={s['p75']}")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"ok: ensemble summary written for base_run_id={args.base_run_id}")


if __name__ == "__main__":
    main()
