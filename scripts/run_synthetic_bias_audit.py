#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]


def _redact_text(value: str) -> str:
    out = value
    for pattern, repl in REDACTION_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _safe_load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _base_run_id(run_id: str) -> str:
    return re.sub(r"_s\d+$", "", run_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic bias audit (non-fatal)")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--fill-rate-floor", type=float, default=0.85)
    parser.add_argument("--gp-margin-drop-threshold", type=float, default=0.02)
    args = parser.parse_args()

    run_id = args.run_id
    snapshot_path = Path(f"data/metrics_snapshots/{run_id}.json")
    dq_path = Path(f"data/dq_reports/{run_id}.json")

    snapshot = _safe_load(snapshot_path) or {}
    dq = _safe_load(dq_path) or {}
    metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
    cfg = snapshot.get("run_config", {}) if isinstance(snapshot.get("run_config"), dict) else {}
    realism = snapshot.get("realism_summary", {}) if isinstance(snapshot.get("realism_summary"), dict) else {}

    findings: list[dict[str, Any]] = []

    # 1) Availability starvation
    try:
        writeoff_rate = float(metrics.get("writeoff_rate_vs_requested_units")) if metrics.get("writeoff_rate_vs_requested_units") is not None else None
    except Exception:
        writeoff_rate = None
    try:
        fill_rate = float(metrics.get("fill_rate_units")) if metrics.get("fill_rate_units") is not None else None
    except Exception:
        fill_rate = None

    if writeoff_rate is not None and fill_rate is not None and writeoff_rate <= 0.01 and fill_rate < float(args.fill_rate_floor):
        findings.append(
            {
                "code": "availability_starvation",
                "severity": "WARN",
                "message": "writeoff is low but fill rate is below floor",
                "evidence": {
                    "writeoff_rate_vs_requested_units": writeoff_rate,
                    "fill_rate_units": fill_rate,
                    "fill_rate_floor": float(args.fill_rate_floor),
                },
            }
        )

    # 2) Margin burning (needs baseline snapshot if available)
    baseline_run_id = str(cfg.get("control_run_id", "") or "").strip()
    if baseline_run_id:
        base_snapshot = _safe_load(Path(f"data/metrics_snapshots/{baseline_run_id}.json")) or {}
        base_metrics = base_snapshot.get("metrics", {}) if isinstance(base_snapshot.get("metrics"), dict) else {}
        try:
            gmv = float(metrics.get("gmv"))
            gmv_b = float(base_metrics.get("gmv"))
            gp_m = float(metrics.get("gp_margin"))
            gp_m_b = float(base_metrics.get("gp_margin"))
        except Exception:
            gmv = gmv_b = gp_m = gp_m_b = None
        if None not in {gmv, gmv_b, gp_m, gp_m_b} and gmv_b > 0:
            if gmv > gmv_b and (gp_m_b - gp_m) > float(args.gp_margin_drop_threshold):
                findings.append(
                    {
                        "code": "margin_burning",
                        "severity": "WARN",
                        "message": "GMV increased while gp_margin dropped beyond threshold",
                        "evidence": {
                            "gmv": gmv,
                            "baseline_gmv": gmv_b,
                            "gp_margin": gp_m,
                            "baseline_gp_margin": gp_m_b,
                            "gp_margin_drop_threshold": float(args.gp_margin_drop_threshold),
                        },
                    }
                )

    # 3) Sterile environment
    try:
        shock_days_share = float(metrics.get("shock_days_share")) if metrics.get("shock_days_share") is not None else None
    except Exception:
        shock_days_share = None

    shocks_enabled = str(cfg.get("enable_demand_shocks", "")).strip() in {"1", "true", "True"}
    if shocks_enabled and shock_days_share is not None and shock_days_share == 0.0:
        findings.append(
            {
                "code": "sterile_shocks_no_effect",
                "severity": "WARN",
                "message": "demand shocks enabled but observed shock impact is zero",
                "evidence": {"shock_days_share": shock_days_share},
            }
        )

    ensemble_path = Path(f"data/ensemble_reports/{_base_run_id(run_id)}_ensemble.json")
    if ensemble_path.exists():
        ens = _safe_load(ensemble_path) or {}
        if isinstance(ens, dict) and bool(ens.get("stability_pass", True)) is False:
            findings.append(
                {
                    "code": "ensemble_instability",
                    "severity": "WARN",
                    "message": "ensemble stability failed",
                    "evidence": {"stability_pass": False},
                }
            )
        # near-zero spread if present
        em = ens.get("metrics", {}) if isinstance(ens.get("metrics"), dict) else {}
        for key, val in em.items():
            if not isinstance(val, dict):
                continue
            p25 = val.get("p25")
            p75 = val.get("p75")
            med = val.get("median")
            try:
                p25f = float(p25)
                p75f = float(p75)
                medf = float(med)
            except Exception:
                continue
            denom = abs(medf) if abs(medf) > 1e-9 else 1.0
            if abs(p75f - p25f) / denom < 1e-6:
                findings.append(
                    {
                        "code": "sterile_zero_variance",
                        "severity": "WARN",
                        "message": f"ensemble variance is near zero for metric {key}",
                        "evidence": {"metric": key, "p25": p25f, "p75": p75f, "median": medf},
                    }
                )

    result = "PASS"
    if any(f.get("severity") == "FAIL" for f in findings):
        result = "FAIL"
    elif findings:
        result = "WARN"

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "result": result,
        "realism_status": str(realism.get("status", "unknown") or "unknown"),
        "findings": findings,
        "inputs": {
            "metrics_snapshot": str(snapshot_path),
            "dq_report": str(dq_path),
            "ensemble_report": str(ensemble_path) if ensemble_path.exists() else None,
        },
        "version": "synthetic_bias_audit.v1",
    }

    out_dir = Path("data/realism_reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / f"{run_id}_synthetic_bias.json"
    out_md = out_dir / f"{run_id}_synthetic_bias.md"
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        f"# Synthetic Bias Audit — {run_id}",
        "",
        f"- result: `{result}`",
        f"- realism_status: `{payload['realism_status']}`",
        "",
        "## Findings",
    ]
    if findings:
        for f in findings:
            lines.append(f"- [{f.get('severity')}] {f.get('code')}: {f.get('message')}")
    else:
        lines.append("- none")
    out_md.write_text(_redact_text("\n".join(lines) + "\n"), encoding="utf-8")

    print(f"ok: synthetic bias audit written for run_id={run_id}")


if __name__ == "__main__":
    main()
