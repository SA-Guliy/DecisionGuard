from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

from scripts import verify_acceptance as acceptance_mod
from src.architecture_v3 import anti_goodhart_verdict_path, paired_experiment_context_path
from src.paired_registry import paired_registry_path
from src.security_utils import write_sha256_sidecar


class PairedPartialAcceptanceFlowTests(unittest.TestCase):
    def _write_json(self, path: Path, payload: dict, *, with_sidecar: bool = True) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if with_sidecar:
            write_sha256_sidecar(path)

    def _cleanup_paths(self, paths: list[Path]) -> None:
        for path in paths:
            sidecar = Path(f"{path}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if path.exists():
                path.unlink()

    def test_paired_ab_artifact_required_partial_subset_checks_pass_with_minimal_fixture(self) -> None:
        run_id = "ut_paired_partial_acceptance"
        ctrl_run_id = f"{run_id}_ctrl"
        experiment_id = "exp_paired_partial_acceptance"

        registry_path = paired_registry_path(experiment_id, run_id)
        context_path = paired_experiment_context_path(run_id)
        ctrl_audit_path = Path(f"data/agent_quality/{ctrl_run_id}_ctrl_foundation_audit.json")
        anti_goodhart_path = anti_goodhart_verdict_path(run_id)
        commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
        doctor_path = Path(f"data/agent_reports/{run_id}_doctor_variance.json")
        acceptance_json = Path(f"data/acceptance/{run_id}_acceptance.json")
        acceptance_md = Path(f"data/acceptance/{run_id}_acceptance.md")
        acceptance_log = Path(f"data/logs/verify_acceptance_{run_id}.log")
        report_md = Path(f"reports/L1_ops/{run_id}/ACCEPTANCE_REPORT.md")

        self._cleanup_paths(
            [
                registry_path,
                context_path,
                ctrl_audit_path,
                anti_goodhart_path,
                commander_path,
                doctor_path,
                acceptance_json,
                acceptance_md,
                acceptance_log,
                report_md,
            ]
        )
        try:
            self._write_json(
                registry_path,
                {
                    "version": "paired_registry_v1",
                    "mode": "paired",
                    "experiment_id": experiment_id,
                    "parent_run_id": run_id,
                    "ctrl_run_id": ctrl_run_id,
                    "treatment_run_id": run_id,
                    "paired_status": "PARTIAL",
                    "created_at": "2026-03-20T00:00:00+00:00",
                    "updated_at": "2026-03-20T00:10:00+00:00",
                    "error_code": "AB_ARTIFACT_REQUIRED",
                    "reason": "anti_goodhart_missing_ab_artifact",
                    "paired_context_ref": f"artifact:{context_path}",
                    "audit_ref": f"artifact:{ctrl_audit_path}",
                    "status_history": [
                        {
                            "from": "COMPLETE",
                            "to": "TREATMENT_FAILED",
                            "reason": "treatment_pipeline_failed",
                            "changed_at": "2026-03-20T00:01:00+00:00",
                        },
                        {
                            "from": "TREATMENT_FAILED",
                            "to": "PARTIAL",
                            "reason": "anti_goodhart_missing_ab_artifact",
                            "changed_at": "2026-03-20T00:02:00+00:00",
                        },
                    ],
                },
            )
            self._write_json(
                context_path,
                {
                    "version": "paired_experiment_v2",
                    "run_id": run_id,
                    "experiment_id": experiment_id,
                    "ctrl_run_id": ctrl_run_id,
                    "treatment_run_id": run_id,
                    "paired_status": "PARTIAL",
                    "partial_reason": "anti_goodhart_missing_ab_artifact",
                    "failed_step": "anti_goodhart_sot",
                    "decision_ceiling": "HOLD_NEED_DATA",
                    "generated_at": "2026-03-20T00:02:00+00:00",
                },
            )
            self._write_json(
                ctrl_audit_path,
                {
                    "version": "ctrl_foundation_audit_v1",
                    "run_id": ctrl_run_id,
                    "status": "PASS",
                    "error_code": "NONE",
                    "executed_steps": [
                        "run_simulation",
                        "run_dq",
                        "make_metrics_snapshot_v1",
                        "run_ab_preflight",
                        "run_ab_analysis",
                    ],
                    "allowed_steps": [
                        "run_simulation",
                        "run_dq",
                        "make_metrics_snapshot_v1",
                        "run_synthetic_bias_audit",
                        "run_ab_preflight",
                        "run_ab_analysis",
                    ],
                    "generated_at": "2026-03-20T00:02:00+00:00",
                },
            )
            self._write_json(
                anti_goodhart_path,
                {
                    "version": "anti_goodhart_verdict_v1",
                    "run_id": run_id,
                    "status": "FAIL",
                    "error_code": "AB_ARTIFACT_REQUIRED",
                    "source_of_truth": "anti_goodhart_verdict_v1",
                    "anti_goodhart_triggered": True,
                    "occurred_at": "2026-03-20T00:02:00+00:00",
                },
            )
            self._write_json(
                commander_path,
                {
                    "run_id": run_id,
                    "decision": "HOLD_NEED_DATA",
                    "normalized_decision": "HOLD_NEED_DATA",
                    "forced_decision_ceiling": "HOLD_NEED_DATA",
                    "blocked_by": ["paired_partial_forced_ceiling:anti_goodhart_missing_ab_artifact"],
                },
                with_sidecar=False,
            )
            self._write_json(
                doctor_path,
                {
                    "run_id": run_id,
                    "normalized_decision": "HOLD_NEED_DATA",
                    "measurement_state": "OBSERVABLE",
                    "hypothesis_portfolio": [],
                },
                with_sidecar=False,
            )

            with mock.patch.object(sys, "argv", ["verify_acceptance.py", "--run-id", run_id]):
                with self.assertRaises(SystemExit):
                    acceptance_mod.main()

            payload = json.loads(acceptance_json.read_text(encoding="utf-8"))
            # This test intentionally uses a minimal fixture focused on paired policy.
            # Full acceptance is expected to fail because unrelated CRITICAL artifacts are absent.
            self.assertEqual(payload.get("overall_status"), "FAIL")
            checks = payload.get("checks", {})
            self.assertEqual(checks.get("paired_partial_anti_goodhart_expected_outcome", {}).get("status"), "PASS")
            self.assertEqual(checks.get("paired_partial_ceiling_enforced", {}).get("status"), "PASS")
            self.assertEqual(checks.get("paired_status_lifecycle_valid", {}).get("status"), "PASS")
        finally:
            self._cleanup_paths(
                [
                    registry_path,
                    context_path,
                    ctrl_audit_path,
                    anti_goodhart_path,
                    commander_path,
                    doctor_path,
                    acceptance_json,
                    acceptance_md,
                    acceptance_log,
                    report_md,
                ]
            )


if __name__ == "__main__":
    unittest.main()
