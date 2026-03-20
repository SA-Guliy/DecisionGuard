#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_registry(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = _load_json(path)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out: list[dict[str, Any]] = []
    for row in data:
        if isinstance(row, dict):
            out.append(row)
    return out


def _normalize_scope(value: Any) -> list[str]:
    if isinstance(value, list):
        scope = [str(x) for x in value if str(x).strip()]
        return scope if scope else ["all"]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return ["all"]


def _upsert(rows: list[dict[str, Any]], new_row: dict[str, Any]) -> list[dict[str, Any]]:
    key = (
        str(new_row.get("name", "")),
        str(new_row.get("unit", "")),
        str(new_row.get("lever_type", "")),
        json.dumps(new_row.get("scope", []), ensure_ascii=True),
        str(new_row.get("start_date", "")),
    )
    replaced = False
    out: list[dict[str, Any]] = []
    for row in rows:
        row_key = (
            str(row.get("name", "")),
            str(row.get("unit", "")),
            str(row.get("lever_type", "")),
            json.dumps(row.get("scope", []), ensure_ascii=True),
            str(row.get("start_date", "")),
        )
        if row_key == key:
            out.append(new_row)
            replaced = True
        else:
            out.append(row)
    if not replaced:
        out.append(new_row)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Update active experiments registry from Commander output")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--registry-path", default="data/agent_reports/active_experiments.json")
    args = parser.parse_args()

    run_id = args.run_id
    commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
    registry_path = Path(args.registry_path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    if not commander_path.exists():
        print("SKIP: commander report not found; registry unchanged")
        return

    commander = _load_json(commander_path)
    if not isinstance(commander, dict):
        print("SKIP: commander report invalid; registry unchanged")
        return

    decision = str(commander.get("decision", "")).upper().strip()
    next_exp = commander.get("next_experiment")
    if decision != "GO" or not isinstance(next_exp, dict):
        print("SKIP: no GO experiment to register")
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    new_row = {
        "name": str(next_exp.get("name", "unknown_experiment")),
        "unit": str(next_exp.get("unit", "customer")),
        "lever_type": str(next_exp.get("lever_type", "unknown")),
        "scope": _normalize_scope(next_exp.get("scope", ["all"])),
        "start_date": str(next_exp.get("start_date", datetime.now(timezone.utc).date().isoformat())),
        "duration_days": int(next_exp.get("duration_days", 14)),
        "freeze_window_days": int(next_exp.get("freeze_window_days", 14)),
        "status": "planned",
        "source_run_id": run_id,
        "updated_at": now_iso,
    }

    rows = _load_registry(registry_path)
    rows = _upsert(rows, new_row)
    registry_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print("ok: active experiments registry updated")


if __name__ == "__main__":
    main()
