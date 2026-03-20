#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
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


def _redact(text: str) -> str:
    out = text
    for p, repl in REDACTION_PATTERNS:
        out = p.sub(repl, out)
    return out


def _load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _stable_id(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _action(actor: str, action_type: str, decision_enum: str, reason_codes: list[str], evidence_refs: list[str], key_fields: dict[str, Any]) -> dict[str, Any]:
    base = {
        "actor": actor,
        "action_type": action_type,
        "decision_enum": decision_enum,
        "key_fields": key_fields,
    }
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action_type": action_type,
        "proposal_id": _stable_id(base),
        "decision_enum": decision_enum,
        "reason_codes": sorted({str(x) for x in reason_codes if str(x).strip()}),
        "evidence_refs": sorted({str(x) for x in evidence_refs if str(x).strip()}),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build deterministic action trace")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    dq = _load(Path(f"data/dq_reports/{run_id}.json")) or {}
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
    evaluator = _load(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")) or {}
    commander = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json")) or {}
    narrative_val = _load(Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json")) or {}
    synthetic_bias = _load(Path(f"data/realism_reports/{run_id}_synthetic_bias.json")) or {}

    rows: list[dict[str, Any]] = []

    dq_rows = dq.get("rows", []) if isinstance(dq.get("rows"), list) else []
    fail_checks = [str(r.get("check_name")) for r in dq_rows if isinstance(r, dict) and str(r.get("status")) == "FAIL"]
    rows.append(
        _action(
            "captain",
            "quality_gate",
            "WARN" if fail_checks else "PASS",
            fail_checks[:10],
            [f"data/dq_reports/{run_id}.json#/rows"],
            {"run_id": run_id, "fail_count": len(fail_checks)},
        )
    )

    doctor_dec = str(doctor.get("normalized_decision", doctor.get("decision", "HOLD_NEED_DATA")))
    doctor_reasons = [str(r.get("code")) for r in (doctor.get("reasons", []) if isinstance(doctor.get("reasons"), list) else []) if isinstance(r, dict)]
    rows.append(
        _action(
            "doctor",
            "experiment_plan",
            doctor_dec,
            doctor_reasons[:10],
            [f"data/agent_reports/{run_id}_doctor_variance.json#/ab_plan"],
            {"run_id": run_id, "decision": doctor_dec},
        )
    )

    eval_dec = str(evaluator.get("decision", "HOLD_NEED_DATA"))
    eval_blocked = evaluator.get("blocked_by", []) if isinstance(evaluator.get("blocked_by"), list) else []
    rows.append(
        _action(
            "evaluator",
            "ab_decision",
            eval_dec,
            [str(x) for x in eval_blocked][:10],
            [f"data/agent_reports/{run_id}_experiment_evaluator.json#/ab_status"],
            {"run_id": run_id, "decision": eval_dec, "ab_status": str(evaluator.get("ab_status", ""))},
        )
    )

    cmd_dec = str(commander.get("normalized_decision", commander.get("decision", "HOLD_NEED_DATA")))
    cmd_blocked = commander.get("blocked_by", []) if isinstance(commander.get("blocked_by"), list) else []
    rows.append(
        _action(
            "commander",
            "portfolio_decision",
            cmd_dec,
            [str(x) for x in cmd_blocked][:10],
            [f"data/agent_reports/{run_id}_commander_priority.json#/next_experiment"],
            {"run_id": run_id, "decision": cmd_dec},
        )
    )

    grounded = bool(narrative_val.get("grounded", False))
    rows.append(
        _action(
            "narrative_analyst",
            "causal_validation",
            "GROUNDED" if grounded else "UNGROUNDED",
            [str(x) for x in (narrative_val.get("issues", []) if isinstance(narrative_val.get("issues"), list) else [])][:10],
            [f"reports/L1_ops/{run_id}/causal_claims_validation.json#/grounded"],
            {"run_id": run_id, "grounded": grounded},
        )
    )

    rows.append(
        _action(
            "safety",
            "synthetic_bias_gate",
            str(synthetic_bias.get("status", "UNKNOWN")),
            ["synthetic_bias"],
            [f"data/realism_reports/{run_id}_synthetic_bias.json#/status"],
            {"run_id": run_id, "status": str(synthetic_bias.get("status", "UNKNOWN"))},
        )
    )

    out = Path(f"data/decision_traces/{run_id}_actions.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(_redact(json.dumps(row, ensure_ascii=False)) + "\n")

    print(f"ok: action trace written for run_id={run_id}")


if __name__ == "__main__":
    main()
