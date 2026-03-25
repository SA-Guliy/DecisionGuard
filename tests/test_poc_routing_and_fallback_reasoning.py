#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_poc_e2e as poc_mod


class PocRoutingAndFallbackReasoningTests(unittest.TestCase):
    def test_groq_secrets_not_required_for_edge_only(self) -> None:
        loaded, source, key = poc_mod._load_groq_secrets_conditional(need_cloud=False, strict=False)
        self.assertFalse(loaded)
        self.assertEqual(source, "not_required")
        self.assertEqual(key, "")

    def test_groq_secrets_required_for_cloud_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            with mock.patch.dict(os.environ, {"GROQ_API_KEY": "", "HOME": tmp_home}, clear=False):
                with self.assertRaises(SystemExit) as ctx:
                    poc_mod._load_groq_secrets_conditional(need_cloud=True, strict=True)
        self.assertIn("Missing ~/.groq_secrets", str(ctx.exception))

    def test_groq_secrets_source_is_sanitized_label(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            secrets_path = Path(tmp_home) / ".groq_secrets"
            secrets_path.write_text("GROQ_API_KEY=gsk_TEST1234567890AB\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"GROQ_API_KEY": "", "HOME": tmp_home}, clear=False):
                loaded, source, key = poc_mod._load_groq_secrets_conditional(need_cloud=True, strict=True)
        self.assertTrue(loaded)
        self.assertEqual(source, "home_groq_secrets")
        self.assertTrue(key.startswith("gsk_"))

    def test_safe_error_reason_redacts_groq_key(self) -> None:
        msg = "auth failed for gsk_ABCDEF1234567890 with Bearer QWERTY1234567890TOKEN"
        redacted = poc_mod._safe_error_reason(msg, limit=500)
        self.assertNotIn("gsk_ABCDEF1234567890", redacted)
        self.assertIn("gsk_[REDACTED]", redacted)
        self.assertNotIn("Bearer QWERTY1234567890TOKEN", redacted)
        self.assertIn("Bearer [REDACTED]", redacted)

    def test_sanitization_kms_source_normalized(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"SANITIZATION_KMS_MASTER_KEY": "k1", "SANITIZATION_KMS_SOURCE": ""},
            clear=False,
        ):
            loaded, source = poc_mod._ensure_sanitization_kms_master_key()
            self.assertTrue(loaded)
            self.assertEqual(source, "env_provided")

        with mock.patch.dict(
            os.environ,
            {"SANITIZATION_KMS_MASTER_KEY": "k2", "SANITIZATION_KMS_SOURCE": "vault"},
            clear=False,
        ):
            loaded, source = poc_mod._ensure_sanitization_kms_master_key()
            self.assertTrue(loaded)
            self.assertEqual(source, "vault")

    def test_sandbox_key_emits_warning(self) -> None:
        with mock.patch.dict(os.environ, {"SANITIZATION_KMS_MASTER_KEY": "", "SANITIZATION_LOCAL_DEMO_KEY": "demo_key"}, clear=False):
            loaded, source = poc_mod._ensure_sanitization_kms_master_key()
            self.assertFalse(loaded)
            self.assertEqual(source, "sandbox_demo")
            with mock.patch.object(poc_mod, "print") as mock_print:
                poc_mod._emit_sanitization_kms_warning_if_needed(source)
                mock_print.assert_called_once()
                self.assertIn("SANDBOX KMS KEY IN USE", str(mock_print.call_args[0][0]))

    def test_captain_pass_status_overrides_false_pass_to_doctor(self) -> None:
        captain = {
            "sanity_status": " pass ",
            "pass_to_doctor": False,
            "issues": [],
        }
        captain_failed, pass_by_status, pass_to_doctor = poc_mod._normalize_captain_gate(captain)
        self.assertTrue(pass_by_status)
        self.assertTrue(pass_to_doctor)
        self.assertFalse(captain_failed)
        self.assertEqual(captain.get("pass_to_doctor"), True)
        self.assertIn("captain_routing_autofix_pass_status", captain.get("issues", []))

    def test_doctor_fallback_emits_historical_risk_signals(self) -> None:
        context_pack = [
            {
                "experiment_id": "exp_hist_001",
                "similarity": 0.548,
                "guardrail_breach": {"metric_id": "gp_margin"},
                "reasoning_decision": {"decision": "STOP_ROLLOUT"},
            }
        ]

        with mock.patch.object(
            poc_mod,
            "_call_llm_with_observability",
            side_effect=RuntimeError("No local LLM backend available"),
        ), mock.patch.object(
            poc_mod,
            "_append_synthetic_trace",
            return_value={"run_id": "t1", "agent": "doctor_edge_heuristic"},
        ), mock.patch.object(
            poc_mod,
            "_debug_cloud_error",
            return_value=None,
        ):
            result, meta = poc_mod._doctor_analysis(
                run_id="t1",
                hypothesis="Run flash discounts on high-turnover SKUs to boost conversion this week.",
                historical_context_pack=context_pack,
                backend_name="groq",
                model_chain=("qwen/qwen3-32b",),
                edge_backend_name="ollama",
                edge_model_name="gemma3:1b",
                simulate_cloud_outage=False,
                allow_heuristic_edge_fallback=True,
            )

        self.assertTrue(result.get("provisional_local_edge_fallback"))
        self.assertTrue(meta.get("edge_fallback_used"))
        signals = result.get("risk_signals", [])
        self.assertIn("cloud_unavailable", signals)
        self.assertIn("edge_model_unavailable", signals)
        self.assertTrue(any(str(x).startswith("historical_guardrail_breach:") for x in signals))
        self.assertTrue(any(str(x).startswith("historical_similarity:") for x in signals))
        self.assertEqual(result.get("suggested_decision"), "STOP_ROLLOUT")


if __name__ == "__main__":
    unittest.main()
