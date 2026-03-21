from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src import paired_registry as pr
from src.security_utils import write_sha256_sidecar


class TestPairedRegistry(unittest.TestCase):
    def test_normalize_registry_key_rejects_path_tokens(self) -> None:
        with self.assertRaises(RuntimeError):
            pr.normalize_registry_key("../bad")
        with self.assertRaises(RuntimeError):
            pr.normalize_registry_key("a/b")

    def test_treatment_failed_status_is_not_aliased(self) -> None:
        payload = {
            "paired_status": "COMPLETE",
            "experiment_id": "exp_001",
            "parent_run_id": "run_001",
        }
        updated = pr.mark_treatment_failed_then_partial(payload, reason="unit_test")
        self.assertEqual(updated.get("paired_status"), pr.PairedRunStatus.TREATMENT_FAILED.value)
        history = updated.get("status_history")
        self.assertIsInstance(history, list)
        self.assertGreaterEqual(len(history), 1)

    def test_apply_status_transition_writes_history_chain(self) -> None:
        payload = {
            "paired_status": "COMPLETE",
            "experiment_id": "exp_001",
            "parent_run_id": "run_001",
            "status_history": [],
        }
        step1 = pr.apply_status_transition(
            payload,
            to_status="TREATMENT_FAILED",
            reason="treatment_failed",
            error_code="AB_ARTIFACT_REQUIRED",
        )
        step2 = pr.apply_status_transition(
            step1,
            to_status="PARTIAL",
            reason="anti_goodhart_missing_ab_artifact",
            error_code="AB_ARTIFACT_REQUIRED",
        )
        self.assertEqual(step2.get("paired_status"), "PARTIAL")
        history = step2.get("status_history")
        self.assertIsInstance(history, list)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0].get("from"), "COMPLETE")
        self.assertEqual(history[0].get("to"), "TREATMENT_FAILED")
        self.assertEqual(history[1].get("from"), "TREATMENT_FAILED")
        self.assertEqual(history[1].get("to"), "PARTIAL")

    def test_apply_status_transition_rejects_invalid_lifecycle(self) -> None:
        payload = {
            "paired_status": "CTRL_FAILED",
            "experiment_id": "exp_001",
            "parent_run_id": "run_001",
            "status_history": [],
        }
        with self.assertRaises(RuntimeError):
            pr.apply_status_transition(
                payload,
                to_status="COMPLETE",
                reason="forbidden_recovery",
                error_code="NONE",
            )

    def test_load_registry_for_run_optional_in_single_mode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "missing_registry_dir"
            with mock.patch.object(pr, "PAIRED_REGISTRY_DIR", root):
                self.assertIsNone(pr.load_registry_for_run("single_run", required=False))

    def test_load_registry_for_run_reads_valid_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = {
                "version": "paired_registry_v1",
                "mode": "paired",
                "experiment_id": "exp_001",
                "parent_run_id": "run_001",
                "ctrl_run_id": "run_001_ctrl",
                "treatment_run_id": "run_001",
                "paired_status": "PARTIAL",
                "created_at": "2026-03-20T00:00:00+00:00",
                "updated_at": "2026-03-20T00:00:00+00:00",
                "error_code": "AB_ARTIFACT_REQUIRED",
                "reason": "unit",
                "paired_context_ref": "artifact:data/agent_context/run_001_paired_experiment_v2.json",
                "audit_ref": "artifact:data/agent_quality/run_001_ctrl_foundation_audit.json",
            }
            p = root / "exp_001__run_001.json"
            p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            write_sha256_sidecar(p)
            with mock.patch.object(pr, "PAIRED_REGISTRY_DIR", root):
                loaded = pr.load_registry_for_run("run_001", required=True)
            self.assertIsInstance(loaded, dict)
            self.assertEqual(str(loaded.get("paired_status")), "PARTIAL")


if __name__ == "__main__":
    unittest.main()
