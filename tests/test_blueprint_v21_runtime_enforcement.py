from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from scripts import run_all as run_all_mod
from src.llm_secure_gateway import gateway_chat_completion, gateway_generate
from src.security_utils import verify_json_manifest, write_sha256_sidecar

ROOT = Path(__file__).resolve().parents[1]


class GroqBackend:
    def get_model_name(self) -> str:
        return "test-groq-model"

    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        _ = (prompt, system_prompt)
        return '{"ok":true}'


class _FakeUsage:
    prompt_tokens = 12
    completion_tokens = 8
    total_tokens = 20


class _FakeMessage:
    content = '{"ok":true}'


class _FakeChoice:
    message = _FakeMessage()


class _FakeChatResponse:
    choices = [_FakeChoice()]
    usage = _FakeUsage()


class _FakeCompletions:
    def create(self, **kwargs):  # noqa: ANN003
        _ = kwargs
        return _FakeChatResponse()


class _FakeChat:
    completions = _FakeCompletions()


class _FakeClient:
    chat = _FakeChat()


class BlueprintV21RuntimeEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self._prev_kms_master = os.environ.get("SANITIZATION_KMS_MASTER_KEY")
        os.environ["SANITIZATION_KMS_MASTER_KEY"] = "unit-test-kms-master-key"

    def tearDown(self) -> None:
        if self._prev_kms_master is None:
            os.environ.pop("SANITIZATION_KMS_MASTER_KEY", None)
        else:
            os.environ["SANITIZATION_KMS_MASTER_KEY"] = self._prev_kms_master

    def _write_json(self, path: Path, payload: dict, *, sidecar: bool = False) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if sidecar:
            write_sha256_sidecar(path)

    def _cleanup_paths(self, paths: list[Path]) -> None:
        for path in paths:
            sidecar = Path(f"{path}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if path.exists():
                path.unlink()

    def test_run_all_required_gate_order_exact_sequence(self) -> None:
        args = argparse.Namespace(
            run_id="ut_v21_gate_order",
            backend="ollama",
            domain_template="",
            enable_deepseek_doctor=0,
            enable_react_doctor=0,
            react_max_steps=1,
            react_timeout_sec=5,
            enable_react_commander=0,
            react_commander_max_steps=1,
            build_weekly=0,
            build_exec=0,
        )
        with (
            mock.patch.object(run_all_mod, "_run_llm_step_budgeted", return_value=None),
            mock.patch.object(run_all_mod, "_run_step", return_value=None),
            mock.patch.object(run_all_mod, "_try_run_step", return_value=True),
            mock.patch.object(run_all_mod, "_write_gate_result_safe", return_value=None),
            mock.patch.object(run_all_mod, "_run_py_step_specs", return_value=None),
            mock.patch.object(run_all_mod, "_app_db_env", return_value={}),
        ):
            run_all_mod._REQUIRED_GATE_EXECUTION_LOG.clear()
            run_all_mod._run_core_agents_and_proof_steps(
                args=args,
                exp_id="",
                log_file=Path("data/logs/ut_v21_gate_order.log"),
                llm_env={},
                retry_policy={"safe_decision": "HOLD_NEED_DATA"},
            )
            run_all_mod._run_eval_publish_tail(
                args=args,
                log_file=Path("data/logs/ut_v21_gate_order_tail.log"),
                lightweight=False,
                build_reports_cmd=["python3", "scripts/build_reports.py", "--run-id", args.run_id],
                security_profile={
                    "fail_closed_integrity_finalize": True,
                    "fail_closed_verify_acceptance": True,
                    "fail_closed_pre_publish_audit": True,
                },
            )
        self.assertEqual(
            run_all_mod._REQUIRED_GATE_EXECUTION_LOG,
            run_all_mod.REQUIRED_GATE_ORDER,
        )

    def test_run_all_propagates_hypothesis_review_flag_to_commander(self) -> None:
        args = argparse.Namespace(
            run_id="ut_v21_hyp_review_flag",
            backend="ollama",
            domain_template="",
            enable_deepseek_doctor=0,
            enable_react_doctor=0,
            react_max_steps=1,
            react_timeout_sec=5,
            enable_react_commander=0,
            react_commander_max_steps=1,
            build_weekly=0,
            build_exec=0,
            experiment_id="exp1",
        )
        with (
            mock.patch.object(run_all_mod, "_run_llm_step_budgeted", return_value=None) as llm_step_mock,
            mock.patch.object(run_all_mod, "_run_step", return_value=None),
            mock.patch.object(run_all_mod, "_try_run_step", return_value=True),
            mock.patch.object(run_all_mod, "_write_gate_result_safe", return_value=None),
            mock.patch.object(run_all_mod, "_run_py_step_specs", return_value=None),
            mock.patch.object(run_all_mod, "_run_gate_step", return_value=None),
            mock.patch.object(run_all_mod, "_app_db_env", return_value={}),
        ):
            run_all_mod._run_core_agents_and_proof_steps(
                args=args,
                exp_id="exp1",
                log_file=Path("data/logs/ut_v21_hyp_review_flag.log"),
                llm_env={},
                retry_policy={"safe_decision": "HOLD_NEED_DATA"},
                hypothesis_review_flag=1,
            )
        commander_calls = [
            c
            for c in llm_step_mock.call_args_list
            if c.kwargs.get("step_name") == "run_commander_priority"
        ]
        self.assertEqual(len(commander_calls), 1)
        cmd = commander_calls[0].kwargs.get("cmd", [])
        self.assertIn("--enable-hypothesis-review-v1", cmd)
        idx = cmd.index("--enable-hypothesis-review-v1")
        self.assertEqual(str(cmd[idx + 1]), "1")

    def test_effective_hypothesis_review_flag_defaults(self) -> None:
        args_auto = argparse.Namespace(enable_hypothesis_review_v1=-1)
        with mock.patch.dict(os.environ, {"DS_STRICT_RUNTIME": "0"}, clear=False):
            self.assertEqual(
                run_all_mod._effective_hypothesis_review_flag(args_auto, {"name": "production"}),
                1,
            )
            self.assertEqual(
                run_all_mod._effective_hypothesis_review_flag(args_auto, {"name": "lightweight"}),
                0,
            )
        args_off = argparse.Namespace(enable_hypothesis_review_v1=0)
        self.assertEqual(
            run_all_mod._effective_hypothesis_review_flag(args_off, {"name": "production"}),
            0,
        )

    def test_commander_happy_path_without_ab_err(self) -> None:
        run_id = "ut_v21_commander_happy"
        cleanup_targets = [
            Path(f"data/dq_reports/{run_id}.json"),
            Path(f"data/llm_reports/{run_id}_captain.json"),
            Path(f"data/metrics_snapshots/{run_id}.json"),
            Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
            Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"),
            Path(f"data/realism_reports/{run_id}_synthetic_bias.json"),
            Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json"),
            Path(f"data/agent_context/{run_id}_doctor_context.json"),
            Path(f"data/agent_context/{run_id}_historical_context_pack.json"),
            Path(f"data/ab_reports/{run_id}_exp1_ab.json"),
            Path(f"data/ab_reports/{run_id}_exp1_ab_v2.json"),
            Path(f"data/agent_quality/{run_id}_anti_goodhart_verdict.json"),
            Path(f"data/agent_reports/{run_id}_commander_priority.json"),
            Path(f"data/agent_reports/{run_id}_commander_priority.md"),
            Path(f"reports/L1_ops/{run_id}/COMMANDER_60S_MEMO.md"),
            Path(f"data/logs/commander_priority_{run_id}.log"),
            Path(f"data/governance/approvals_{run_id}.json"),
            Path(f"data/agent_governance/{run_id}_agent_approvals.json"),
        ]
        self._cleanup_paths(cleanup_targets)
        try:
            self._write_json(Path(f"data/dq_reports/{run_id}.json"), {"rows": []})
            self._write_json(Path(f"data/llm_reports/{run_id}_captain.json"), {"result": {"verdict": "PASS", "issues": []}})
            self._write_json(
                Path(f"data/metrics_snapshots/{run_id}.json"),
                {
                    "run_id": run_id,
                    "run_config": {"experiment_id": "exp1"},
                    "metrics": {"gmv": 100.0, "fill_rate_units": 0.95},
                },
            )
            self._write_json(
                Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
                {
                    "normalized_decision": "RUN_AB",
                    "decision": "RUN_AB",
                    "assignment_status": "ready",
                    "measurement_state": "OBSERVABLE",
                    "hypothesis_portfolio": [{"hypothesis_id": "h1", "target_metric": "gmv_growth_rate"}],
                },
            )
            self._write_json(Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"), {"decision": "RUN_AB", "ab_status": "OK"})
            self._write_json(Path(f"data/realism_reports/{run_id}_synthetic_bias.json"), {"signals": []})
            self._write_json(Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json"), {"grounded": True})
            self._write_json(Path(f"data/agent_context/{run_id}_doctor_context.json"), {"goal_blocks": {}})
            self._write_json(Path(f"data/agent_context/{run_id}_historical_context_pack.json"), {"status": "PASS", "rows": [{"x": 1}]}, sidecar=True)
            self._write_json(
                Path(f"data/ab_reports/{run_id}_exp1_ab.json"),
                {
                    "status": "OK",
                    "summary": {
                        "primary_metric": "gmv",
                        "sample_size_control": 100,
                        "sample_size_treat": 100,
                        "primary_metric_uplift_ci95": [0.01, 0.03],
                    },
                },
            )
            self._write_json(Path(f"data/ab_reports/{run_id}_exp1_ab_v2.json"), {"primary_metric": {"name": "gmv"}, "anti_goodhart_triggered": False})
            self._write_json(
                Path(f"data/agent_quality/{run_id}_anti_goodhart_verdict.json"),
                {"status": "PASS", "source_of_truth": "anti_goodhart_verdict_v1", "anti_goodhart_triggered": False},
                sidecar=True,
            )

            proc = subprocess.run(
                ["python3", "scripts/run_commander_priority.py", "--run-id", run_id, "--backend", "ollama", "--experiment-id", "exp1"],
                cwd=ROOT,
                env={**os.environ, "LLM_ALLOW_REMOTE": "0", "DS_DOMAIN_TEMPLATE": "domain_templates/darkstore_fresh_v1.json"},
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
            out = json.loads(Path(f"data/agent_reports/{run_id}_commander_priority.json").read_text(encoding="utf-8"))
            blocked_by = out.get("blocked_by", []) if isinstance(out.get("blocked_by"), list) else []
            self.assertNotIn("invalid_input:unexpected_error", blocked_by)
        finally:
            self._cleanup_paths(cleanup_targets)

    def test_cloud_gateway_generate_writes_map_audit_and_manifest(self) -> None:
        run_id = f"ut_v21_cloud_{uuid.uuid4().hex[:10]}"
        map_root = Path("data/security/obfuscation_maps")
        manifest_path = map_root / f"{run_id}_obfuscation_manifest.json"
        audit_path = map_root / "audit_log.jsonl"
        before_audit_size = audit_path.stat().st_size if audit_path.exists() else 0
        output, meta = gateway_generate(
            backend=GroqBackend(),
            run_id=run_id,
            agent_name="captain",
            call_name="unit_test_cloud",
            prompt="token=abc123",
            system_prompt="you are system",
        )
        self.assertIn("ok", output)
        map_ref = Path(str(meta.get("obfuscation_map_ref", "")))
        self.assertTrue(map_ref.exists())
        self.assertTrue(Path(f"{map_ref}.sha256").exists())
        map_doc = json.loads(map_ref.read_text(encoding="utf-8"))
        self.assertEqual(map_doc.get("version"), "obfuscation_map_v2")
        self.assertNotIn("payload", map_doc)
        self.assertIn("envelope", map_doc)
        self.assertTrue(bool(map_doc.get("sanitization_vectorization_applied", False)))
        self.assertTrue(bool(map_doc.get("response_deobfuscation_required", False)))
        self.assertFalse(bool(map_doc.get("response_deobfuscation_applied_actual", False)))
        self.assertTrue(manifest_path.exists())
        manifest_ok, manifest_issues = verify_json_manifest(manifest_path, require_manifest=True, verify_manifest_sidecar=True)
        self.assertTrue(manifest_ok, msg=f"manifest_issues={manifest_issues}")
        self.assertTrue(audit_path.exists())
        after_audit_size = audit_path.stat().st_size
        self.assertGreater(after_audit_size, before_audit_size)
        audit_tail = audit_path.read_text(encoding="utf-8")[-2000:]
        self.assertIn(run_id, audit_tail)

        # cleanup run-scoped files from this test
        time.sleep(0.01)
        run_maps = [p for p in map_root.glob(f"{run_id}_*.json") if p.is_file()]
        for path in run_maps:
            sidecar = Path(f"{path}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            path.unlink()
        manifest_sidecar = Path(f"{manifest_path}.sha256")
        if manifest_sidecar.exists():
            manifest_sidecar.unlink()
        if manifest_path.exists():
            manifest_path.unlink()

    def test_cloud_gateway_chat_completion_writes_map(self) -> None:
        run_id = f"ut_v21_chat_{uuid.uuid4().hex[:10]}"
        map_root = Path("data/security/obfuscation_maps")
        backend = GroqBackend()
        backend._client = _FakeClient()  # type: ignore[attr-defined]
        output, usage = gateway_chat_completion(
            backend=backend,
            system_prompt="system token=abc",
            user_prompt="user prompt",
            temperature=0.2,
            run_id=run_id,
            agent_name="poc",
            call_name="chat_test",
        )
        self.assertIn("ok", output)
        self.assertTrue(str(usage.get("obfuscation_map_ref", "")).strip())
        map_ref = Path(str(usage.get("obfuscation_map_ref")))
        self.assertTrue(map_ref.exists())
        self.assertTrue(Path(f"{map_ref}.sha256").exists())
        map_doc = json.loads(map_ref.read_text(encoding="utf-8"))
        self.assertEqual(map_doc.get("version"), "obfuscation_map_v2")
        self.assertNotIn("payload", map_doc)
        self.assertIn("envelope", map_doc)
        self.assertTrue(bool(map_doc.get("sanitization_vectorization_applied", False)))
        self.assertTrue(bool(map_doc.get("response_deobfuscation_required", False)))
        self.assertFalse(bool(map_doc.get("response_deobfuscation_applied_actual", False)))
        manifest_path = map_root / f"{run_id}_obfuscation_manifest.json"
        self.assertTrue(manifest_path.exists())
        for path in map_root.glob(f"{run_id}_*.json"):
            sidecar = Path(f"{path}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if path.exists():
                path.unlink()
        manifest_sidecar = Path(f"{manifest_path}.sha256")
        if manifest_sidecar.exists():
            manifest_sidecar.unlink()


if __name__ == "__main__":
    unittest.main()
