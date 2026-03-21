from __future__ import annotations

import unittest
from unittest import mock

from src.reasoning_confidence import compute_reasoning_confidence


POLICY = {
    "version": "reasoning_confidence_policy_v1",
    "base_score": 0.6,
    "significant_p_value_max": 0.05,
    "analog_similarity_weight": 0.2,
    "min_sample_size_n": 30,
    "penalties": {
        "layer1_missing": 0.2,
        "layer2_missing": 0.15,
        "guardrail_data_incomplete": 0.12,
        "underpowered_or_no_data": 0.18,
        "srm_failed": 0.1,
    },
    "caps": {
        "single_mode_no_live_evidence": 0.64,
        "partial_or_failed_paired_status": 0.6,
        "missing_layers12": 0.62,
    },
    "score_bounds": {"min": 0.0, "max": 1.0},
}


class ReasoningConfidenceTests(unittest.TestCase):
    def _compute(self, **kwargs):
        with mock.patch("src.reasoning_confidence.load_reasoning_confidence_policy", return_value=POLICY):
            return compute_reasoning_confidence(**kwargs)

    def test_significant_pvalue_improves_score(self) -> None:
        good, _ = self._compute(
            layers_present={"layer1_live_stats": True, "layer2_guardrail_check": True},
            p_value=0.01,
            best_analog_similarity=0.7,
            guardrail_data_complete=True,
            n_min=40,
            srm_pass=True,
            mode="paired",
            paired_status="COMPLETE",
            has_live_evidence=True,
        )
        weak, _ = self._compute(
            layers_present={"layer1_live_stats": True, "layer2_guardrail_check": True},
            p_value=0.4,
            best_analog_similarity=0.7,
            guardrail_data_complete=True,
            n_min=40,
            srm_pass=True,
            mode="paired",
            paired_status="COMPLETE",
            has_live_evidence=True,
        )
        self.assertGreater(good, weak)

    def test_missing_layers_penalized_and_capped(self) -> None:
        score, basis = self._compute(
            layers_present={"layer1_live_stats": False, "layer2_guardrail_check": False},
            p_value=None,
            best_analog_similarity=0.1,
            guardrail_data_complete=False,
            n_min=10,
            srm_pass=False,
            mode="single",
            paired_status="SINGLE",
            has_live_evidence=False,
        )
        self.assertLessEqual(score, POLICY["caps"]["missing_layers12"])
        self.assertTrue(any(str(x).startswith("penalty:layer1_missing") for x in basis))
        self.assertTrue(any(str(x).startswith("cap:missing_layers12") for x in basis))

    def test_partial_status_cap_applied(self) -> None:
        score, basis = self._compute(
            layers_present={"layer1_live_stats": True, "layer2_guardrail_check": True},
            p_value=0.01,
            best_analog_similarity=0.95,
            guardrail_data_complete=True,
            n_min=100,
            srm_pass=True,
            mode="paired",
            paired_status="PARTIAL",
            has_live_evidence=True,
        )
        self.assertLessEqual(score, POLICY["caps"]["partial_or_failed_paired_status"])
        self.assertTrue(any(str(x).startswith("cap:partial_or_failed_paired_status") for x in basis))

    def test_single_without_live_evidence_cap_applied(self) -> None:
        score, basis = self._compute(
            layers_present={"layer1_live_stats": True, "layer2_guardrail_check": True},
            p_value=0.01,
            best_analog_similarity=0.95,
            guardrail_data_complete=True,
            n_min=100,
            srm_pass=True,
            mode="single",
            paired_status="SINGLE",
            has_live_evidence=False,
        )
        self.assertLessEqual(score, POLICY["caps"]["single_mode_no_live_evidence"])
        self.assertTrue(any(str(x).startswith("cap:single_mode_no_live_evidence") for x in basis))

    def test_score_clamped_into_bounds(self) -> None:
        score, _ = self._compute(
            layers_present={"layer1_live_stats": True, "layer2_guardrail_check": True},
            p_value=0.0,
            best_analog_similarity=1.0,
            guardrail_data_complete=True,
            n_min=1000,
            srm_pass=True,
            mode="paired",
            paired_status="COMPLETE",
            has_live_evidence=True,
        )
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


if __name__ == "__main__":
    unittest.main()

