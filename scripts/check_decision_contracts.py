#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.decision_contract import (
    load_decision_contract,
    validate_decision,
    validate_reasoning_checks,
    validate_required_fields,
)

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


def _safe_load(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except Exception:
        return None, "invalid_json"


def _derive_run_ids(limit: int) -> list[str]:
    runs: list[tuple[float, str]] = []
    for p in Path("data/agent_reports").glob("*_doctor_variance.json"):
        run_id = p.name[: -len("_doctor_variance.json")]
        try:
            mtime = p.stat().st_mtime
        except Exception:
            mtime = 0.0
        runs.append((mtime, run_id))
    runs.sort(reverse=True)
    out: list[str] = []
    seen: set[str] = set()
    for _, run_id in runs:
        if run_id in seen:
            continue
        seen.add(run_id)
        out.append(run_id)
        if len(out) >= max(1, limit):
            break
    return out


def _validate_payload(contract: dict[str, Any], payload: dict[str, Any], role: str) -> list[str]:
    errors: list[str] = []
    try:
        validate_required_fields(payload, contract, role)
    except Exception as exc:
        errors.append(str(exc))
    dec_field = "decision"
    if role == "doctor":
        dec_field = "normalized_decision"
    try:
        validate_decision(str(payload.get(dec_field, "")), contract, dec_field)
    except Exception as exc:
        errors.append(str(exc))
    return errors


def _check_run(run_id: str, contract: dict[str, Any]) -> dict[str, Any]:
    files = {
        "doctor": Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
        "evaluator": Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"),
        "commander": Path(f"data/agent_reports/{run_id}_commander_priority.json"),
    }
    role_results: dict[str, Any] = {}
    passed = True
    for role, path in files.items():
        payload, load_err = _safe_load(path)
        errors: list[str] = []
        if load_err == "missing":
            errors.append(f"missing artifact: {path}")
        elif load_err == "invalid_json":
            errors.append(f"invalid json: {path}")
        else:
            assert payload is not None
            errors.extend(_validate_payload(contract, payload, role))
        if errors:
            passed = False
        role_results[role] = {
            "path": str(path),
            "errors": errors,
            "passed": len(errors) == 0,
        }
    agent_eval_path = Path(f"data/agent_eval/{run_id}_agent_value_eval.json")
    agent_eval, agent_eval_err = _safe_load(agent_eval_path)
    reasoning_errors: list[str] = []
    if agent_eval_err == "missing":
        reasoning_errors.append(f"missing artifact: {agent_eval_path}")
    elif agent_eval_err == "invalid_json":
        reasoning_errors.append(f"invalid json: {agent_eval_path}")
    else:
        assert agent_eval is not None
        try:
            validate_reasoning_checks(agent_eval, contract)
        except Exception as exc:
            reasoning_errors.append(str(exc))
    if reasoning_errors:
        passed = False
    role_results["reasoning"] = {
        "path": str(agent_eval_path),
        "errors": reasoning_errors,
        "passed": len(reasoning_errors) == 0,
    }
    return {"run_id": run_id, "passed": passed, "roles": role_results}


def _write_l1_md(run_id: str, result: dict[str, Any]) -> None:
    out_dir = Path(f"reports/L1_ops/{run_id}")
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Decision Contract Check — {run_id}",
        "",
        f"- passed: `{result.get('passed')}`",
        "",
        "## Roles",
    ]
    roles = result.get("roles", {}) if isinstance(result.get("roles"), dict) else {}
    for role in ("doctor", "evaluator", "commander", "reasoning"):
        rr = roles.get(role, {}) if isinstance(roles.get(role), dict) else {}
        lines.append(f"- {role}: `{rr.get('passed')}`")
        errs = rr.get("errors", []) if isinstance(rr.get("errors"), list) else []
        for err in errs[:5]:
            lines.append(f"  - {err}")
    (out_dir / "decision_contract_check.md").write_text(_redact_text("\n".join(lines) + "\n"), encoding="utf-8")


def _write_l2_md(results: list[dict[str, Any]]) -> None:
    now = datetime.now(timezone.utc)
    y, w, _ = now.isocalendar()
    week_id = f"{y}-W{w:02d}"
    out_dir = Path(f"reports/L2_mgmt/{week_id}")
    out_dir.mkdir(parents=True, exist_ok=True)
    passed_cnt = sum(1 for r in results if bool(r.get("passed")))
    lines = [
        f"# Decision Contract Checks — {week_id}",
        "",
        f"- checked_runs: `{len(results)}`",
        f"- passed_runs: `{passed_cnt}`",
        "",
        "## Run Results",
    ]
    for r in results:
        lines.append(f"- {r.get('run_id')}: `{r.get('passed')}`")
    (out_dir / "decision_contracts_latest.md").write_text(_redact_text("\n".join(lines) + "\n"), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate doctor/evaluator/commander artifacts against decision contract")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()

    run_id = args.run_id.strip()
    log_path = Path(f"data/logs/decision_contract_check_{run_id or 'latest'}.log")
    out_dir = Path("data/agent_quality")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        contract = load_decision_contract()
        run_ids = [run_id] if run_id else _derive_run_ids(args.limit)
        results = [_check_run(rid, contract) for rid in run_ids]
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "contract_version": str(contract.get("version", "decision_contract_v1")),
            "checked_runs": len(results),
            "passed_runs": sum(1 for r in results if bool(r.get("passed"))),
            "results": results,
            "version": "decision_contract_check.v1",
        }

        if run_id:
            out_json = out_dir / f"{run_id}_decision_contracts.json"
            out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            _write_l1_md(run_id, results[0] if results else {"run_id": run_id, "passed": False, "roles": {}})
        else:
            out_json = out_dir / "decision_contracts_latest.json"
            out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            _write_l2_md(results)

        print(f"ok: decision contract check done ({len(results)} runs)")
    except Exception:
        log_path.write_text(traceback.format_exc(), encoding="utf-8")
        raise SystemExit(f"decision contract check failed. See {log_path}")


if __name__ == "__main__":
    main()
