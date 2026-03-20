#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import write_sha256_sidecar


def _safe_float(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _safe_int(v: Any) -> int:
    try:
        return int(float(v))
    except Exception:
        return 0


def _iter_trace_rows(run_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    candidates = [
        Path("data/logs/llm_trace.jsonl"),
        Path(f"data/logs/{run_id}_llm_trace.jsonl"),
    ]
    for path in candidates:
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line in lines:
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            if str(obj.get("run_id", "")).strip() == run_id:
                rows.append(obj)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build per-run cost ledger from LLM traces.")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    rows = _iter_trace_rows(run_id)
    tokens_total = sum(_safe_int(r.get("total_tokens")) for r in rows)
    latency_ms_total = sum(_safe_int(r.get("latency_ms")) for r in rows)
    usd_total = round(sum(_safe_float(r.get("cost_usd_estimate")) for r in rows), 6)
    fallback_used = any(bool(r.get("edge_fallback_used")) or bool(r.get("used_fallback")) for r in rows)
    tiers = sorted(
        {
            str(r.get("tier_used", r.get("backend", ""))).strip().lower()
            for r in rows
            if str(r.get("tier_used", r.get("backend", ""))).strip()
        }
    )
    ledger = {
        "version": "cost_ledger_v1",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tokens": int(tokens_total),
        "latency_ms": int(latency_ms_total),
        "usd_estimate": float(usd_total),
        "tier_used": tiers if tiers else ["unknown"],
        "fallback_used": bool(fallback_used),
        "rows_count": len(rows),
    }
    out = Path(f"data/cost/{run_id}_cost_ledger.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ledger, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out)
    print(f"ok: cost ledger written {out}")


if __name__ == "__main__":
    main()
