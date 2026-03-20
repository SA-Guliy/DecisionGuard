#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

from jsonschema import validate


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_captain_sanity_llm as captain_mod
from scripts import run_doctor_variance as doctor_mod
from scripts import run_commander_priority as commander_mod


class VisibleReasoningTraceV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema_path = ROOT / "configs/contracts/visible_reasoning_trace_v1.json"
        cls.schema = json.loads(schema_path.read_text(encoding="utf-8"))

    def _validate_trace(self, trace: dict) -> None:
        validate(instance=trace, schema=self.schema)
        self.assertIsInstance(trace.get("claims"), list)
        self.assertIsInstance(trace.get("gates_checked"), list)
        self.assertIsInstance(trace.get("unknowns"), list)
        for gate in trace.get("gates_checked", []):
            self.assertIsInstance(gate, str)

    def test_captain_trace_schema_when_flag_enabled(self) -> None:
        os.environ["ENABLE_VISIBLE_REASONING_TRACE"] = "1"
        flags = captain_mod._active_feature_flags()
        trace = captain_mod._build_visible_reasoning_trace(
            run_id="t_run",
            result={
                "issues": [
                    {
                        "check_name": "check_A",
                        "severity": "WARN",
                        "message": "A warning from DQ.",
                        "hypotheses": ["hypothesis_1", "unknown"],
                        "verification_steps": ["SELECT 1 FROM step1.vw_valid_orders WHERE run_id='t_run';"],
                    }
                ]
            },
            eval_metrics={"issue_coverage": 1.0, "no_extra_issues": True, "safety": True, "extra_issues": []},
            enabled=bool(flags["ENABLE_VISIBLE_REASONING_TRACE"]),
        )
        self._validate_trace(trace)

    def test_doctor_trace_schema_when_flag_enabled(self) -> None:
        os.environ["ENABLE_VISIBLE_REASONING_TRACE"] = "1"
        flags = doctor_mod._active_feature_flags()
        trace = doctor_mod._build_doctor_visible_reasoning_trace(
            run_id="t_run",
            decision="HOLD_NEED_DATA",
            reasons=[
                {
                    "code": "measurement_blind_spot",
                    "severity": "WARN",
                    "message": "Assignment log missing.",
                    "evidence_refs": ["artifact:data/dq_reports/t_run.json#"],
                }
            ],
            protocol_checks=[{"name": "read_only_tools", "passed": True, "detail": "ok"}],
            measurement_state="BLOCKED_BY_DATA",
            ab_status="MISSING_ASSIGNMENT",
            measurement_fix_plan={"missing_items": ["assignment_log"]},
            enabled=bool(flags["ENABLE_VISIBLE_REASONING_TRACE"]),
        )
        self._validate_trace(trace)

    def test_commander_trace_schema_when_flag_enabled(self) -> None:
        os.environ["ENABLE_VISIBLE_REASONING_TRACE"] = "1"
        flags = commander_mod._active_feature_flags()
        trace = commander_mod._build_commander_visible_reasoning_trace(
            payload={
                "run_id": "t_run",
                "decision": "HOLD_RISK",
                "normalized_decision": "HOLD_RISK",
                "blocked_by": ["goal_metric_misalignment"],
                "methodology_check": {
                    "unit_alignment_ok": True,
                    "goal_metric_alignment_ok": False,
                    "stats_consistent": True,
                    "measurement_state": "OBSERVABLE",
                    "ab_status": "OK",
                },
                "data_requests": [{"why": "Need cohort heterogeneity check."}],
                "cohort_analysis": {"status": "BLOCKED_BY_DATA"},
                "evidence_refs": {
                    "doctor": "data/agent_reports/t_run_doctor_variance.json",
                    "metrics_snapshot": "data/metrics_snapshots/t_run.json",
                },
            },
            enabled=bool(flags["ENABLE_VISIBLE_REASONING_TRACE"]),
        )
        self._validate_trace(trace)


if __name__ == "__main__":
    unittest.main()
