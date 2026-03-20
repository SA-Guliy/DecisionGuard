#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.architecture_v3 import load_json_optional_with_integrity
from src.security_utils import write_sha256_sidecar

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


def _safe_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(json.dumps(payload, ensure_ascii=False, indent=2)), encoding="utf-8")
    write_sha256_sidecar(path)


def _load(path: Path, *, require_integrity: bool = False) -> dict[str, Any] | None:
    if require_integrity:
        return load_json_optional_with_integrity(path, required=True)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _stable_proposal_id(row: dict[str, Any]) -> str:
    raw = "|".join(
        [
            str(row.get("agent", "")).strip().lower(),
            str(row.get("proposal_type", "")).strip().lower(),
            str(row.get("title", "")).strip().lower(),
            json.dumps(row.get("key_fields", {}), ensure_ascii=False, sort_keys=True),
        ]
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Build agent governance approvals")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    base = _load(Path(f"data/governance/approvals_{run_id}.json"), require_integrity=True) or {}
    evaluator = _load(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"), require_integrity=True) or {}
    commander = _load(Path(f"data/agent_reports/{run_id}_commander_priority.json"), require_integrity=True) or {}
    val = _load(Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json"), require_integrity=True) or {}

    rows = base.get("approvals", []) if isinstance(base.get("approvals"), list) else []
    approvals = [r for r in rows if isinstance(r, dict)]

    eval_dec = str(evaluator.get("decision", "HOLD_NEED_DATA")).upper()
    narrative_grounded = bool(val.get("grounded", False))
    rejection_reasons: list[str] = []

    for row in approvals:
        if not str(row.get("proposal_id", "")).strip():
            row["proposal_id"] = _stable_proposal_id(row)
        ptype = str(row.get("proposal_type", "")).strip()
        if ptype not in {"hypothesis", "measurement_fix", "explanation", "experiment_plan"}:
            row["proposal_type"] = "explanation"
            ptype = "explanation"
        decision = str(row.get("decision", "REJECT")).upper()
        if not str(row.get("reason_code", "")).strip():
            row["reason_code"] = "missing_evidence"
        if decision not in {"APPROVE", "REJECT"}:
            row["decision"] = "REJECT"
            row["reason_code"] = "missing_evidence"
        if eval_dec == "STOP" and ptype in {"hypothesis", "experiment_plan"}:
            row["decision"] = "REJECT"
            row["reason_code"] = "guardrail_risk"
            rejection_reasons.append("evaluator_stop_forces_reject")
        if not narrative_grounded and ptype == "explanation":
            row["decision"] = "REJECT"
            row["reason_code"] = "missing_evidence"
            rejection_reasons.append("narrative_ungrounded")

    if not narrative_grounded:
        cmd_dec = str(commander.get("normalized_decision", commander.get("decision", "HOLD_NEED_DATA"))).upper()
        if cmd_dec in {"RUN_AB", "ROLLOUT_CANDIDATE", "GO"}:
            rejection_reasons.append("commander_decision_ceiling_hold_risk")

    has_doctor_portfolio = False
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json"), require_integrity=True) or {}
    if isinstance(doctor.get("hypothesis_portfolio"), list) and len(doctor.get("hypothesis_portfolio", [])) > 0:
        has_doctor_portfolio = True
    governance_status = "ok"
    if has_doctor_portfolio and len(approvals) == 0:
        governance_status = "missing_review"
        rejection_reasons.append("doctor_portfolio_without_approvals")

    out = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "approvals": {
            "doctor_hypothesis_approved": any(str(r.get("agent")) == "doctor" and str(r.get("proposal_type")) == "hypothesis" and str(r.get("decision")).upper() == "APPROVE" for r in approvals),
            "narrative_claims_approved": narrative_grounded and any(str(r.get("agent")) == "narrative_analyst" and str(r.get("decision")).upper() == "APPROVE" for r in approvals),
            "captain_data_quality_approved": any(str(r.get("agent")) == "captain" and str(r.get("decision")).upper() == "APPROVE" for r in approvals),
        },
        "proposal_rows": approvals,
        "rejection_reasons": sorted(set(rejection_reasons)),
        "governance_status": governance_status,
        "decision_ceiling": "HOLD_RISK" if governance_status == "missing_review" else "NONE",
        "source_of_truth": "data/governance/approvals_<run_id>.json",
        "version": "agent_governance.v1",
    }

    out_path = Path(f"data/agent_governance/{run_id}_agent_approvals.json")
    _safe_write(out_path, out)
    print(f"ok: agent governance written for run_id={run_id}")


if __name__ == "__main__":
    main()
