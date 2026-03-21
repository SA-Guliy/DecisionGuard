from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from scripts.run_doctor_variance import _write_doctor_context


class DoctorPairedStatWiringTests(unittest.TestCase):
    def test_doctor_context_contains_stat_bundle_and_goal_alignment_fields(self) -> None:
        run_id = "ut_doctor_paired_stat_ctx"
        out_path = Path(f"data/agent_context/{run_id}_doctor_context.json")
        out_path.unlink(missing_ok=True)
        try:
            snapshot = {
                "metrics": {
                    "aov": 42.0,
                    "fill_rate_units": 0.95,
                    "oos_lost_gmv_rate": 0.03,
                    "gp_margin": 0.2,
                },
                "run_config": {
                    "experiment_unit": "store",
                    "experiment_treat_pct": 50,
                    "horizon_days": 14,
                    "ab_pre_period_weeks": 2,
                    "ab_test_period_weeks": 2,
                    "ab_wash_in_days": 3,
                    "ab_attribution_rule": "same_week",
                    "ab_test_side": "two-sided",
                },
            }
            dq = {"qa_status": "PASS", "rows": []}
            captain = {"verdict": "PASS"}
            synthetic_bias = {"status": "PASS", "findings": [], "signals": []}
            ab_report = {"summary": {"primary_metric": "aov", "srm_status": "PASS"}}
            layers_present = {
                "layer1_live_stats": True,
                "layer2_guardrail_check": True,
                "layer3_history": True,
            }
            confidence_inputs = {
                "layers_present": layers_present,
                "p_value": 0.03,
                "best_analog_similarity": 0.7,
                "guardrail_data_complete": True,
                "n_min": 120,
                "srm_pass": True,
                "paired_status": "COMPLETE",
            }
            stat_ref = f"artifact:data/agent_context/{run_id}_stat_evidence_bundle_v1.json#"

            with mock.patch.dict(os.environ, {"DS_DOMAIN_TEMPLATE_PATH": "domain_templates/darkstore_fresh_v1.json"}, clear=False):
                path = _write_doctor_context(
                    run_id,
                    snapshot,
                    dq,
                    captain,
                    synthetic_bias,
                    experiment_id="exp_stat_ctx",
                    assignment_status="ASSIGNED",
                    measurement_state="OBSERVABLE",
                    ab_status="PASS",
                    ab_report=ab_report,
                    paired_status="COMPLETE",
                    layers_present=layers_present,
                    reasoning_confidence_inputs=confidence_inputs,
                    stat_bundle_ref=stat_ref,
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("ab_primary_goal", payload.get("experiment_header", {}))
            self.assertEqual(payload.get("experiment_header", {}).get("paired_status"), "COMPLETE")
            self.assertEqual(payload.get("sources", {}).get("stat_evidence_bundle"), stat_ref)
            self.assertEqual(payload.get("layers_present"), layers_present)
            self.assertEqual(payload.get("reasoning_confidence_inputs"), confidence_inputs)
        finally:
            out_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
