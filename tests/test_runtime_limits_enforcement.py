#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_all as run_all_mod
import src.runtime_controls as runtime_controls
from src.runtime_controls import enforce_runtime_limits_for_run, get_retry_budget_status
from src.security_utils import write_sha256_sidecar


def _feature_state_enabled() -> dict[str, str]:
    return {
        "weak_path_runtime": "ENABLED",
        "reconciliation_runtime": "IMPLEMENTED",
        "auto_decision_change": "FORBIDDEN",
        "default_weak_path_ceiling": "HOLD_NEED_DATA",
    }


def _runtime_limits_small() -> dict[str, int]:
    return {
        "concurrency": 1,
        "max_batch_size": 50,
        "max_payload_bytes": 100,
        "max_reconcile_attempts": 3,
        "reconciliation_ttl_hours": 24,
    }


class RuntimeLimitsEnforcementTests(unittest.TestCase):
    def _write_events(self, event_root: Path, payload: list[dict[str, object]]) -> None:
        event_root.mkdir(parents=True, exist_ok=True)
        (event_root / "events.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def test_schema_missing_required_causes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            event_root = Path(td)
            self._write_events(
                event_root,
                [
                    {
                        "topic": "ai.reconciliation.requested.v1",
                        "payload": {
                            # event_id is required by schema and intentionally missing
                            "run_id": "r_schema",
                            "experiment_id": "exp",
                            "reconciliation_id": "rec_schema",
                            "source_event_id": "source_schema",
                            "max_attempts": 3,
                            "backoff_seconds": 60,
                            "payload_ref": "s3://bucket/chunk",
                            "max_payload_bytes": 10,
                            "chunk_ref_required": True,
                            "reconciliation_status": "REQUESTED",
                            "loop_guard_key": "lg_schema",
                            "requested_at": "2026-03-03T00:00:00Z",
                        },
                    }
                ],
            )
            with self.assertRaisesRegex(RuntimeError, "schema_validation_error"):
                enforce_runtime_limits_for_run(
                    "r_schema",
                    _runtime_limits_small(),
                    _feature_state_enabled(),
                    event_bus_root=event_root,
                )

    def test_attempt_over_contract_max_causes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            event_root = Path(td)
            self._write_events(
                event_root,
                [
                    {
                        "topic": "ai.reconciliation.requested.v1",
                        "payload": {
                            "event_id": "evt_attempt_1",
                            "run_id": "r_attempt",
                            "experiment_id": "exp",
                            "reconciliation_id": "rec_1",
                            "source_event_id": "source_1",
                            "attempt_no": 4,
                            "max_attempts": 10,
                            "backoff_seconds": 60,
                            "payload_ref": "s3://bucket/chunk_1",
                            "max_payload_bytes": 10,
                            "chunk_ref_required": True,
                            "reconciliation_status": "REQUESTED",
                            "loop_guard_key": "lg_1",
                            "requested_at": "2026-03-03T00:00:00Z",
                        },
                    }
                ],
            )
            with self.assertRaisesRegex(RuntimeError, "loop_or_dedup_violation"):
                enforce_runtime_limits_for_run(
                    "r_attempt",
                    _runtime_limits_small(),
                    _feature_state_enabled(),
                    event_bus_root=event_root,
                )

    def test_chunk_ref_false_causes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            event_root = Path(td)
            self._write_events(
                event_root,
                [
                    {
                        "topic": "ai.reconciliation.requested.v1",
                        "payload": {
                            "event_id": "evt_payload_1",
                            "run_id": "r_payload",
                            "experiment_id": "exp",
                            "reconciliation_id": "rec_2",
                            "source_event_id": "source_2",
                            "attempt_no": 1,
                            "max_attempts": 3,
                            "backoff_seconds": 60,
                            "payload_ref": "s3://bucket/chunk_2",
                            "max_payload_bytes": 50,
                            "chunk_ref_required": False,
                            "reconciliation_status": "REQUESTED",
                            "loop_guard_key": "lg_2",
                            "requested_at": "2026-03-03T00:00:00Z",
                        },
                    }
                ],
            )
            with self.assertRaisesRegex(RuntimeError, "schema_validation_error"):
                enforce_runtime_limits_for_run(
                    "r_payload",
                    _runtime_limits_small(),
                    _feature_state_enabled(),
                    event_bus_root=event_root,
                )

    def test_duplicate_loop_guard_key_causes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            event_root = Path(td)
            self._write_events(
                event_root,
                [
                    {
                        "topic": "ai.reconciliation.requested.v1",
                        "payload": {
                            "event_id": "evt_loop_1",
                            "run_id": "r_loop",
                            "experiment_id": "exp",
                            "reconciliation_id": "rec_loop_1",
                            "source_event_id": "source_loop_1",
                            "attempt_no": 1,
                            "max_attempts": 3,
                            "backoff_seconds": 60,
                            "payload_ref": "s3://bucket/chunk_a",
                            "max_payload_bytes": 10,
                            "chunk_ref_required": True,
                            "reconciliation_status": "REQUESTED",
                            "loop_guard_key": "dup_lg",
                            "requested_at": "2026-03-03T00:00:00Z",
                        },
                    },
                    {
                        "topic": "ai.reconciliation.completed.v1",
                        "payload": {
                            "event_id": "evt_loop_2",
                            "run_id": "r_loop",
                            "experiment_id": "exp",
                            "reconciliation_id": "rec_loop_1",
                            "source_event_id": "source_loop_1",
                            "reconciliation_status": "COMPLETED",
                            "attempt_no": 1,
                            "max_attempts": 3,
                            "auto_decision_change_applied": False,
                            "completed_at": "2026-03-03T00:10:00Z",
                            "loop_guard_key": "dup_lg",
                        },
                    },
                ],
            )
            with self.assertRaisesRegex(RuntimeError, "loop_or_dedup_violation"):
                enforce_runtime_limits_for_run(
                    "r_loop",
                    _runtime_limits_small(),
                    _feature_state_enabled(),
                    event_bus_root=event_root,
                )

    def test_ttl_exceeded_causes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            event_root = Path(td)
            self._write_events(
                event_root,
                [
                    {
                        "topic": "ai.reasoning.weak_path_detected.v1",
                        "payload": {
                            "run_id": "r_ttl",
                            "experiment_id": "exp",
                            "source_event_id": "source_3",
                            "tier_used": "weak",
                            "audited_by_weak_model": True,
                            "decision_ceiling_applied": "HOLD_NEED_DATA",
                            "reconciliation_status": "REQUESTED",
                            "auto_decision_change_applied": False,
                            "retry_count": 1,
                            "retry_budget": 3,
                            "occurred_at": "2026-01-01T00:00:00Z",
                        },
                    }
                ],
            )
            with self.assertRaisesRegex(RuntimeError, "loop_or_dedup_violation"):
                enforce_runtime_limits_for_run(
                    "r_ttl",
                    _runtime_limits_small(),
                    _feature_state_enabled(),
                    event_bus_root=event_root,
                )

    def test_retry_budget_exceeded_stops_pipeline_with_safe_decision(self) -> None:
        blocked_status = {
            "allowed": False,
            "reason": "retry_budget_exceeded",
            "safe_decision": "HOLD_NEED_DATA",
            "state": {"llm_calls": 12},
        }
        with mock.patch.object(run_all_mod, "get_retry_budget_status", return_value=blocked_status), mock.patch.object(
            run_all_mod, "write_retry_guard_report"
        ) as write_report, mock.patch.object(
            run_all_mod, "_write_orchestrator_safe_decision_artifact", return_value=Path("data/agent_reports/run_x_orchestrator_safe_decision.json")
        ) as write_safe_artifact:
            with self.assertRaises(SystemExit) as ctx:
                run_all_mod._enforce_retry_budget_before_llm_or_exit(
                    "run_x",
                    {
                        "version": "retry_policy_v1",
                        "safe_decision": "HOLD_NEED_DATA",
                    },
                    step_name="run_captain_sanity_llm",
                )
            self.assertEqual(ctx.exception.code, 1)
            self.assertEqual(write_report.call_count, 1)
            kwargs = write_report.call_args.kwargs
            self.assertEqual(kwargs.get("status"), "FAIL")
            self.assertIn("retry_budget_exceeded", str(kwargs.get("reason", "")))
            self.assertEqual(write_safe_artifact.call_count, 1)

    def test_tampered_retry_state_blocks_budget_check(self) -> None:
        run_id = "r_retry_tamper"
        retry_policy = {
            "version": "retry_policy_v1",
            "safe_decision": "HOLD_NEED_DATA",
            "max_llm_calls_per_run": 12,
            "max_llm_failures_per_run": 4,
            "max_consecutive_failures_before_open_circuit": 2,
            "circuit_cooldown_seconds": 1800,
        }
        with tempfile.TemporaryDirectory() as td:
            runtime_guard = Path(td)
            state_path = runtime_guard / f"{run_id}_retry_state.json"
            state_path.write_text(json.dumps({"run_id": run_id, "llm_calls": 1}), encoding="utf-8")
            write_sha256_sidecar(state_path)
            state_path.write_text(json.dumps({"run_id": run_id, "llm_calls": 999}), encoding="utf-8")

            with mock.patch.object(runtime_controls, "_RUNTIME_GUARD_DIR", runtime_guard), mock.patch.dict(
                "os.environ", {"DS_STRICT_RUNTIME": "1"}, clear=False
            ), mock.patch.object(run_all_mod, "write_retry_guard_report") as write_report, mock.patch.object(
                run_all_mod,
                "_write_orchestrator_safe_decision_artifact",
                return_value=Path("data/agent_reports/r_retry_tamper_orchestrator_safe_decision.json"),
            ) as write_safe_artifact:
                with self.assertRaises(SystemExit) as ctx:
                    run_all_mod._enforce_retry_budget_before_llm_or_exit(
                        run_id,
                        retry_policy,
                        step_name="run_captain_sanity_llm",
                    )
                self.assertEqual(ctx.exception.code, 1)
                self.assertEqual(write_report.call_count, 1)
                reason = str(write_report.call_args.kwargs.get("reason", ""))
                self.assertIn("retry_state_integrity_error", reason)
                self.assertEqual(write_safe_artifact.call_count, 1)
                safe_reason = str(write_safe_artifact.call_args.kwargs.get("reason_code", ""))
                self.assertIn("retry_state_integrity_error", safe_reason)

    def test_missing_retry_state_sidecar_blocks_in_strict_mode(self) -> None:
        run_id = "r_retry_missing_sidecar"
        retry_policy = {
            "safe_decision": "HOLD_NEED_DATA",
            "max_llm_calls_per_run": 12,
            "max_llm_failures_per_run": 4,
        }
        with tempfile.TemporaryDirectory() as td:
            runtime_guard = Path(td)
            state_path = runtime_guard / f"{run_id}_retry_state.json"
            state_path.write_text(json.dumps({"run_id": run_id, "llm_calls": 1}), encoding="utf-8")
            with mock.patch.object(runtime_controls, "_RUNTIME_GUARD_DIR", runtime_guard), mock.patch.dict(
                "os.environ", {"DS_STRICT_RUNTIME": "1"}, clear=False
            ):
                status = get_retry_budget_status(run_id, retry_policy)
            self.assertFalse(bool(status.get("allowed")))
            self.assertEqual(str(status.get("reason")), "retry_state_integrity_error")
            self.assertIn("missing_integrity_sidecar", str(status.get("reason_code", "")))

    def test_retry_state_integrity_error_writes_safe_decision_and_stops(self) -> None:
        run_id = "r_retry_register_fail"
        retry_policy = {
            "version": "retry_policy_v1",
            "safe_decision": "HOLD_NEED_DATA",
            "max_llm_calls_per_run": 12,
            "max_llm_failures_per_run": 4,
            "max_consecutive_failures_before_open_circuit": 2,
            "circuit_cooldown_seconds": 1800,
        }
        with tempfile.TemporaryDirectory() as td:
            runtime_guard = Path(td)
            state_path = runtime_guard / f"{run_id}_retry_state.json"
            state_path.write_text(json.dumps({"run_id": run_id, "llm_calls": 0}), encoding="utf-8")
            write_sha256_sidecar(state_path)
            state_path.write_text(json.dumps({"run_id": run_id, "llm_calls": 2}), encoding="utf-8")

            with mock.patch.object(runtime_controls, "_RUNTIME_GUARD_DIR", runtime_guard), mock.patch.dict(
                "os.environ", {"DS_STRICT_RUNTIME": "1"}, clear=False
            ), mock.patch.object(
                run_all_mod,
                "get_retry_budget_status",
                return_value={"allowed": True, "reason": "ok", "safe_decision": "HOLD_NEED_DATA", "state": {}},
            ), mock.patch.object(run_all_mod, "_run_step") as run_step_mock, mock.patch.object(
                run_all_mod, "write_retry_guard_report"
            ) as write_report, mock.patch.object(
                run_all_mod,
                "_write_orchestrator_safe_decision_artifact",
                return_value=Path("data/agent_reports/r_retry_register_fail_orchestrator_safe_decision.json"),
            ) as write_safe_artifact:
                with self.assertRaises(SystemExit) as ctx:
                    run_all_mod._run_llm_step_budgeted(
                        run_id=run_id,
                        retry_policy=retry_policy,
                        cmd=["python3", "scripts/run_captain_sanity_llm.py", "--run-id", run_id],
                        step_name="run_captain_sanity_llm",
                        log_file=Path(td) / "run.log",
                    )
                self.assertEqual(ctx.exception.code, 1)
                self.assertEqual(run_step_mock.call_count, 1)
                self.assertEqual(write_report.call_count, 1)
                self.assertEqual(str(write_report.call_args.kwargs.get("status")), "FAIL")
                reason = str(write_report.call_args.kwargs.get("reason", ""))
                self.assertIn("retry_state_integrity_error", reason)
                self.assertEqual(write_safe_artifact.call_count, 1)
                safe_reason = str(write_safe_artifact.call_args.kwargs.get("reason_code", ""))
                self.assertIn("retry_guard_failed", safe_reason)
                self.assertIn("retry_state_integrity_error", safe_reason)


if __name__ == "__main__":
    unittest.main()
