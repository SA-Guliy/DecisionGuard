#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import verify_acceptance as acceptance_mod
from src.runtime_controls import load_feature_state_contract, load_runtime_limits_contract


class RuntimeControlsAndAcceptanceEventsTests(unittest.TestCase):
    def test_runtime_limits_contract_loads(self) -> None:
        limits = load_runtime_limits_contract()
        self.assertEqual(limits.get("concurrency"), 1)
        self.assertTrue(bool(limits.get("chunk_ref_required")))
        self.assertTrue(bool(limits.get("runtime_guard_report_required")))
        self.assertEqual(limits.get("sla_mode"), "batch_nightly")
        self.assertGreater(int(limits.get("max_reconcile_attempts", 0) or 0), 0)

    def test_runtime_limits_contract_requires_runtime_guard_report_flag(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "runtime_limits_tmp.json"
            payload = {
                "version": "runtime_limits_v1",
                "limits": {
                    "concurrency": 1,
                    "max_batch_size": 100,
                    "max_payload_bytes": 1024,
                    "chunk_ref_required": True,
                    "max_reconcile_attempts": 3,
                    "backoff_schedule": [1, 2, 3],
                    "reconciliation_ttl_hours": 24,
                    "sla_mode": "batch_nightly",
                    "runtime_guard_report_required": False,
                },
            }
            p.write_text(json.dumps(payload), encoding="utf-8")
            # Generate valid sidecar manually for this temp test payload.
            import hashlib

            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            (Path(str(p) + ".sha256")).write_text(digest + "\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "runtime_guard_report_required_must_be_true"):
                load_runtime_limits_contract(str(p))

    def test_feature_state_contract_loads(self) -> None:
        state = load_feature_state_contract()
        self.assertEqual(state.get("weak_path_runtime"), "DISABLED")
        self.assertEqual(state.get("reconciliation_runtime"), "NOT_IMPLEMENTED")
        self.assertEqual(state.get("auto_decision_change"), "FORBIDDEN")
        self.assertEqual(state.get("default_weak_path_ceiling"), "HOLD_NEED_DATA")

    def test_extract_run_events_from_envelope_payload(self) -> None:
        payload = {
            "topic": "ai.reasoning.weak_path_detected.v1",
            "payload": {
                "run_id": "r1",
                "experiment_id": "e1",
                "source_event_id": "evt_1",
                "tier_used": "weak",
                "audited_by_weak_model": True,
                "decision_ceiling_applied": "HOLD_NEED_DATA",
                "reconciliation_status": "REQUESTED",
                "auto_decision_change_applied": False,
                "retry_count": 0,
                "retry_budget": 2,
                "occurred_at": "2026-03-03T00:00:00Z",
            },
        }
        rows = acceptance_mod._extract_run_events_from_payload(
            payload,
            run_id="r1",
            source_path="data/event_bus/sample.json",
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("__kind"), "weak_reasoning_result")
        self.assertEqual(rows[0].get("__topic"), "ai.reasoning.weak_path_detected.v1")

    def test_extract_run_events_from_events_list(self) -> None:
        payload = {
            "topic": "bundle",
            "events": [
                {
                    "topic": "ai.reconciliation.requested.v1",
                    "payload": {
                        "run_id": "r2",
                        "experiment_id": "e1",
                        "reconciliation_id": "recon_1",
                        "source_event_id": "evt_1",
                        "attempt_no": 1,
                        "max_attempts": 3,
                        "backoff_seconds": 60,
                        "payload_ref": "s3://bucket/chunk-1",
                        "max_payload_bytes": 1000,
                        "chunk_ref_required": True,
                        "reconciliation_status": "REQUESTED",
                        "loop_guard_key": "guard_1",
                        "requested_at": "2026-03-03T00:00:00Z",
                    },
                },
                {
                    "topic": "ai.reconciliation.completed.v1",
                    "payload": {
                        "run_id": "r2",
                        "experiment_id": "e1",
                        "reconciliation_id": "recon_1",
                        "source_event_id": "evt_1",
                        "reconciliation_status": "COMPLETED",
                        "attempt_no": 1,
                        "max_attempts": 3,
                        "auto_decision_change_applied": False,
                        "completed_at": "2026-03-03T01:00:00Z",
                        "loop_guard_key": "guard_1_done",
                    },
                },
            ],
        }
        rows = acceptance_mod._extract_run_events_from_payload(
            payload,
            run_id="r2",
            source_path="data/event_bus/sample_events.json",
        )
        kinds = [str(r.get("__kind")) for r in rows]
        self.assertIn("reconciliation_request", kinds)
        self.assertIn("reconciliation_result", kinds)


if __name__ == "__main__":
    unittest.main()
