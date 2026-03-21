from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path

from src.architecture_v3 import validate_v3_contract_set
from src.security_utils import write_sha256_sidecar

ROOT = Path(__file__).resolve().parents[1]


class ArchitectureV3RuntimeContractsTests(unittest.TestCase):
    def _write_json_with_sidecar(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)

    def _cleanup_run(self, run_id: str) -> None:
        targets = [
            Path(f"data/llm_reports/{run_id}_captain.json"),
            Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
            Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"),
            Path(f"data/agent_reports/{run_id}_commander_priority.json"),
            Path(f"data/agent_eval/{run_id}_agent_value_eval.json"),
            Path(f"data/agent_governance/{run_id}_agent_approvals.json"),
            Path(f"data/agent_quality/{run_id}_reasoning_score_policy.json"),
            Path(f"data/agent_quality/{run_id}_governance_ceiling.json"),
            Path(f"data/agent_context/{run_id}_context_frame.json"),
            Path(f"data/eval/adversarial_suite_{run_id}.json"),
            Path(f"data/metrics_snapshots/{run_id}.json"),
            Path(f"data/ab_reports/{run_id}_exp1_ab.json"),
            Path(f"data/governance/approvals_{run_id}.json"),
            Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json"),
            Path(f"data/gates/{run_id}_reasoning_score_policy_gate_result.json"),
            Path(f"data/gates/{run_id}_governance_ceiling_gate_result.json"),
            Path(f"data/gates/{run_id}_context_frame_gate_result.json"),
            Path(f"data/gates/{run_id}_adversarial_gate_result.json"),
            Path(f"data/gates/{run_id}_agent_governance_gate_result.json"),
        ]
        for path in targets:
            sidecar = Path(f"{path}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if path.exists():
                path.unlink()

    def test_validate_v3_contract_set_integrity(self) -> None:
        payload = validate_v3_contract_set()
        self.assertIn("context_frame", payload)
        self.assertIn("governance_ceiling", payload)
        self.assertIn("gate_result", payload)
        self.assertIn("decision_outcomes_ledger", payload)
        self.assertIn("offline_kpi_backtest", payload)
        self.assertIn("experiment_duration_policy", payload)

    def test_reasoning_policy_fail_closed_on_full_fallback(self) -> None:
        run_id = "ut_v3_reasoning_policy"
        self._cleanup_run(run_id)
        try:
            self._write_json_with_sidecar(
                Path(f"data/llm_reports/{run_id}_captain.json"),
                {
                    "model": "local_mock",
                    "fallback_used": True,
                    "llm_provenance": {"selected_model_before_fallback": "local_mock"},
                },
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
                {
                    "model_used": "local_mock",
                    "ab_interpretation_methodology": {
                        "selection_provenance": {
                            "selected_by": "fallback_policy",
                            "model_intent": "local_mock",
                        }
                    },
                },
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"),
                {"run_id": run_id, "decision": "HOLD_NEED_DATA"},
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_commander_priority.json"),
                {
                    "run_id": run_id,
                    "normalized_decision": "RUN_AB",
                    "commander_model": "local_mock",
                    "llm_decision_provenance": {"model": "local_mock", "used_fallback": True},
                },
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_eval/{run_id}_agent_value_eval.json"),
                {"run_id": run_id, "system": {"reasoning_layer_status": "PASS", "reasoning_layer_score": 0.99}},
            )

            proc = subprocess.run(
                ["python3", "scripts/run_reasoning_score_policy.py", "--run-id", run_id],
                cwd=ROOT,
                env={**os.environ, "DS_INTEGRITY_MODE": "best_effort"},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            out_path = Path(f"data/agent_quality/{run_id}_reasoning_score_policy.json")
            payload = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "FAIL")
            self.assertEqual(payload["decision_ceiling"], "HOLD_NEED_DATA")
            self.assertEqual(payload["error_code"], "METHODOLOGY_INVARIANT_BROKEN")
        finally:
            self._cleanup_run(run_id)

    def test_governance_ceiling_missing_review_is_fail_closed(self) -> None:
        run_id = "ut_v3_governance_ceiling"
        self._cleanup_run(run_id)
        try:
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_commander_priority.json"),
                {"run_id": run_id, "normalized_decision": "RUN_AB"},
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_governance/{run_id}_agent_approvals.json"),
                {
                    "run_id": run_id,
                    "governance_status": "missing_review",
                    "proposal_rows": [],
                    "rejection_reasons": [],
                },
            )

            proc = subprocess.run(
                ["python3", "scripts/run_governance_ceiling.py", "--run-id", run_id],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            out_path = Path(f"data/agent_quality/{run_id}_governance_ceiling.json")
            payload = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "FAIL")
            self.assertEqual(payload["error_code"], "GOVERNANCE_REVIEW_REQUIRED")
            self.assertEqual(payload["decision_ceiling"], "HOLD_NEED_DATA")
            self.assertGreaterEqual(len(payload.get("required_actions", [])), 1)
        finally:
            self._cleanup_run(run_id)

    def test_context_frame_runs_without_pythonpath_env(self) -> None:
        run_id = "ut_v3_context_no_pythonpath"
        self._cleanup_run(run_id)
        try:
            self._write_json_with_sidecar(
                Path(f"data/metrics_snapshots/{run_id}.json"),
                {"run_config": {"experiment_id": "exp_current"}},
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
                {"ab_plan": [{"experiment_id": "exp_next"}]},
            )
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            proc = subprocess.run(
                ["python3", "scripts/run_context_frame.py", "--run-id", run_id],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
            self.assertNotIn("ModuleNotFoundError", proc.stderr)
            out_path = Path(f"data/agent_context/{run_id}_context_frame.json")
            self.assertTrue(out_path.exists())
        finally:
            self._cleanup_run(run_id)

    def test_adversarial_suite_fails_on_tampered_integrity_input(self) -> None:
        run_id = "ut_v3_adv_tamper"
        self._cleanup_run(run_id)
        try:
            self._write_json_with_sidecar(
                Path(f"data/metrics_snapshots/{run_id}.json"),
                {
                    "run_config": {"experiment_id": "exp1"},
                    "metrics": {
                        "writeoff_rate_vs_requested_units": 0.01,
                        "fill_rate_units": 0.95,
                        "oos_lost_gmv_rate": 0.05,
                    },
                },
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"),
                {"run_id": run_id, "ab_status": "OK", "decision": "RUN_AB"},
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_commander_priority.json"),
                {"run_id": run_id, "normalized_decision": "RUN_AB"},
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
                {"run_id": run_id, "measurement_state": "OBSERVABLE"},
            )
            self._write_json_with_sidecar(
                Path(f"data/ab_reports/{run_id}_exp1_ab.json"),
                {"run_id": run_id, "status": "OK", "summary": {"primary_metric_uplift": 0.02}},
            )
            tampered = Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")
            tampered.write_text(
                json.dumps({"run_id": run_id, "ab_status": "METHODOLOGY_MISMATCH", "decision": "RUN_AB"}, ensure_ascii=False),
                encoding="utf-8",
            )
            proc = subprocess.run(
                ["python3", "scripts/run_adversarial_eval_suite.py", "--run-id", run_id],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
        finally:
            self._cleanup_run(run_id)

    def test_agent_governance_fails_on_tampered_integrity_input(self) -> None:
        run_id = "ut_v3_gov_tamper"
        self._cleanup_run(run_id)
        try:
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"),
                {"run_id": run_id, "decision": "RUN_AB"},
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_commander_priority.json"),
                {"run_id": run_id, "normalized_decision": "RUN_AB"},
            )
            self._write_json_with_sidecar(
                Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
                {"run_id": run_id, "hypothesis_portfolio": [{"hypothesis_id": "h1"}]},
            )
            self._write_json_with_sidecar(
                Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json"),
                {"grounded": True},
            )
            self._write_json_with_sidecar(
                Path(f"data/governance/approvals_{run_id}.json"),
                {"run_id": run_id, "approvals": []},
            )
            tampered = Path(f"data/agent_reports/{run_id}_commander_priority.json")
            tampered.write_text(
                json.dumps({"run_id": run_id, "normalized_decision": "STOP"}, ensure_ascii=False),
                encoding="utf-8",
            )
            proc = subprocess.run(
                ["python3", "scripts/run_agent_governance.py", "--run-id", run_id],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
        finally:
            self._cleanup_run(run_id)


if __name__ == "__main__":
    unittest.main()
