#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.architecture_v3 import (
    CONTRACTS_DIR,
    historical_context_pack_path,
    load_json_with_integrity,
    reasoning_memory_ledger_path,
    save_json_with_sidecar,
    write_gate_result,
)
from src.retrieval_runtime import build_semantic_hybrid_pack


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and validate semantic+fact historical_context_pack before Doctor")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--min-semantic-score", type=float, default=0.08)
    args = parser.parse_args()

    run_id = args.run_id
    error_code = "NONE"
    blocked_by: list[str] = []
    required_actions: list[str] = []

    try:
        _ = load_json_with_integrity(CONTRACTS_DIR / "historical_context_pack_v1.json")
        _ = load_json_with_integrity(CONTRACTS_DIR / "reasoning_memory_ledger_v1.json")
        _ = load_json_with_integrity(CONTRACTS_DIR / "decision_outcomes_ledger_v1.json")
        _ = load_json_with_integrity(CONTRACTS_DIR / "offline_kpi_backtest_v1.json")

        payload, error_code, blocked_by, required_actions = build_semantic_hybrid_pack(
            run_id=run_id,
            top_k=max(1, int(args.top_k)),
            min_semantic_score=max(0.0, float(args.min_semantic_score)),
        )
        save_json_with_sidecar(historical_context_pack_path(run_id), payload)

        ledger = {
            "version": "reasoning_memory_ledger_v1",
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": [
                {
                    "stage": "historical_retrieval_gate",
                    "artifact_ref": f"artifact:{historical_context_pack_path(run_id)}",
                    "used": bool(str(payload.get("status", "")).upper() == "PASS"),
                    "usage_note": (
                        "historical context pack generated with semantic retrieval + structured fact pull before doctor"
                    ),
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        }
        save_json_with_sidecar(reasoning_memory_ledger_path(run_id), ledger)

        status = str(payload.get("status", "FAIL")).upper()
        write_gate_result(
            run_id,
            gate_name="historical_retrieval_gate",
            status=status,
            error_code=(error_code or "NONE"),
            blocked_by=blocked_by,
            required_actions=required_actions,
            details={
                "retrieval_mode": str(payload.get("retrieval_mode", "")),
                "embedding_model": str(payload.get("embedding_model", "")),
                "historical_rows": len(payload.get("rows", []) if isinstance(payload.get("rows"), list) else []),
                "fact_refs": len(payload.get("fact_refs", []) if isinstance(payload.get("fact_refs"), list) else []),
                "evidence_hashes": len(
                    payload.get("evidence_hashes", []) if isinstance(payload.get("evidence_hashes"), list) else []
                ),
                "pack_ref": str(historical_context_pack_path(run_id)),
                "ledger_ref": str(reasoning_memory_ledger_path(run_id)),
            },
        )
        if status != "PASS":
            raise SystemExit(1)
        print(f"ok: historical retrieval gate PASS for run_id={run_id}")
    except SystemExit:
        raise
    except Exception as exc:
        write_gate_result(
            run_id,
            gate_name="historical_retrieval_gate",
            status="FAIL",
            error_code="HISTORICAL_CONTEXT_INTEGRITY_FAIL",
            blocked_by=["historical_context_pack_generation_failed"],
            required_actions=["fix_historical_context_generation_and_rerun"],
            details={"error": str(exc)},
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
