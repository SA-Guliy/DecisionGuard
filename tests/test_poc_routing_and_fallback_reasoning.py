#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_poc_e2e as poc_mod


class PocRoutingAndFallbackReasoningTests(unittest.TestCase):
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

