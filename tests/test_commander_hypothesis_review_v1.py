#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_batch_eval as batch_mod
from scripts import run_commander_priority as commander_mod
from scripts import verify_acceptance as acceptance_mod


class CommanderHypothesisReviewV1Tests(unittest.TestCase):
    def _cleanup_run(self, run_id: str) -> None:
        targets = [
            Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
            Path(f"data/agent_reports/{run_id}_commander_priority.json"),
            Path(f"data/acceptance/{run_id}_acceptance.json"),
            Path(f"data/acceptance/{run_id}_acceptance.md"),
            Path(f"data/logs/verify_acceptance_{run_id}.log"),
            Path(f"reports/L1_ops/{run_id}/ACCEPTANCE_REPORT.md"),
        ]
        for path in targets:
            sidecar = Path(f"{path}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if path.exists():
                path.unlink()
        run_report_dir = Path(f"reports/L1_ops/{run_id}")
        if run_report_dir.exists() and not any(run_report_dir.iterdir()):
            run_report_dir.rmdir()

    def test_empty_evidence_refs_is_untestable(self) -> None:
        doctor = {
            "hypothesis_portfolio": [
                {
                    "hypothesis_id": "h_empty_refs",
                    "target_metric": "gmv_growth_rate",
                    "expected_uplift_range": "+2%..+6%",
                    "falsifiability_condition": "Reject if uplift < 2%.",
                    "evidence_refs": [],
                }
            ]
        }
        rows, summary, blockers = commander_mod._verify_doctor_hypotheses(
            run_id="ut_hyp_review_empty_refs",
            doctor=doctor,
            ab=None,
            ab_v2=None,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["final_verdict"], "UNTESTABLE")
        self.assertEqual(summary["untestable_count"], 1)
        self.assertTrue(any("missing_or_invalid_evidence_refs" in x for x in blockers))

    def test_review_structure_accepts_zero_summary_counts(self) -> None:
        commander_doc = {
            "doctor_hypothesis_review": [],
            "hypothesis_review_summary": {
                "total_count": 0,
                "supported_count": 0,
                "weak_count": 0,
                "refuted_count": 0,
                "untestable_count": 0,
                "refuted_high_count": 0,
                "goal_alignment_status": "UNKNOWN",
                "misaligned_hypothesis_count": 0,
                "verification_quality_score": 1.0,
            },
        }
        ok, meta = acceptance_mod._validate_doctor_hypothesis_review_structure(commander_doc)
        self.assertTrue(ok, msg=str(meta))
        self.assertEqual(meta.get("issues"), [])

    def test_doctor_respects_ab_primary_goal(self) -> None:
        doctor = {
            "hypothesis_portfolio": [
                {
                    "hypothesis_id": "h_goal_align",
                    "target_metric": "aov",
                    "impact_class": "medium",
                    "expected_uplift_range": "+2%..+6%",
                    "falsifiability_condition": "Reject if uplift <= 0%.",
                    "evidence_refs": ["artifact:data/metrics_snapshots/x.json#/metrics/aov"],
                }
            ]
        }
        ab = {"summary": {"primary_metric": "aov"}}
        with mock.patch.object(
            commander_mod,
            "goal_from_metric",
            side_effect=lambda metric: "goal2" if str(metric).strip() == "aov" else "unknown",
        ):
            rows, summary, _ = commander_mod._verify_doctor_hypotheses(
                run_id="ut_doctor_primary_goal_alignment",
                doctor=doctor,
                ab=ab,
                ab_v2=None,
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("goal_alignment"), "aligned")
        self.assertIsNone(rows[0].get("cross_goal_reference"))
        self.assertEqual(summary.get("goal_alignment_status"), "PASS")
        self.assertEqual(int(summary.get("misaligned_hypothesis_count", -1)), 0)

    def test_sign_conflict_is_refuted(self) -> None:
        doctor = {
            "hypothesis_portfolio": [
                {
                    "hypothesis_id": "h_sign_conflict",
                    "target_metric": "gmv_growth_rate",
                    "impact_class": "high",
                    "expected_uplift_range": "+3%..+8%",
                    "falsifiability_condition": "Reject if uplift <= 0%.",
                    "evidence_refs": ["artifact:data/metrics_snapshots/x.json#/metrics/gmv_growth_rate"],
                    "guardrails": {"primary_guardrail_metric": "margin_rate"},
                }
            ]
        }
        ab = {"summary": {"primary_metric_uplift": -1.5}}
        rows, summary, _ = commander_mod._verify_doctor_hypotheses(
            run_id="ut_hyp_review_sign_conflict",
            doctor=doctor,
            ab=ab,
            ab_v2=None,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["final_verdict"], "REFUTED")
        self.assertEqual(rows[0]["conflict_type"], "sign_conflict")
        self.assertEqual(summary["refuted_count"], 1)

    def test_refuted_high_enforces_hold_need_data(self) -> None:
        payload = {
            "decision": "RUN_AB",
            "normalized_decision": "RUN_AB",
            "blocked_by": [],
            "top_reasons": [],
            "hypothesis_review_summary": {"refuted_high_count": 1},
        }
        commander_mod._enforce_hypothesis_review_ceiling(payload, enforce=True)
        self.assertEqual(payload["normalized_decision"], "HOLD_NEED_DATA")
        self.assertIn("hypothesis_refuted_high", payload["blocked_by"])

    def test_contract_driven_validation_fails_when_new_required_field_missing(self) -> None:
        payload = {
            "version": "doctor_hypothesis_review_v1",
            "run_id": "ut_hyp_contract_drift",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "doctor_hypothesis_review": [
                {
                    "hypothesis_id": "h1",
                    "target_metric": "gmv_growth_rate",
                    "impact_class": "high",
                    "deterministic_verdict": "REFUTED",
                    "final_verdict": "REFUTED",
                    "goal_alignment": "unknown",
                    "cross_goal_reference": None,
                    "evidence_refs": ["artifact:data/metrics_snapshots/x.json#"],
                    "rationale": "sign conflict",
                    "mitigation": "collect better data",
                }
            ],
            "hypothesis_review_summary": {
                "total_count": 1,
                "supported_count": 0,
                "weak_count": 0,
                "refuted_count": 1,
                "untestable_count": 0,
                "refuted_high_count": 1,
                "goal_alignment_status": "UNKNOWN",
                "misaligned_hypothesis_count": 0,
                "verification_quality_score": 0.3,
            },
            "review_blockers": ["h1:deterministic_sign_conflict"],
        }
        contract = commander_mod._load_doctor_hypothesis_review_contract()
        modified_contract = json.loads(json.dumps(contract))
        rows_schema = (
            modified_contract.get("properties", {})
            .get("doctor_hypothesis_review", {})
            .get("items", {})
        )
        existing_required = rows_schema.get("required", [])
        rows_schema["required"] = list(existing_required) + ["new_required_field"]
        with mock.patch.object(
            commander_mod,
            "_load_doctor_hypothesis_review_contract",
            return_value=modified_contract,
        ):
            with self.assertRaisesRegex(ValueError, "missing_row_required"):
                commander_mod._validate_hypothesis_review_payload(payload)

    def test_acceptance_fails_when_review_missing(self) -> None:
        run_id = "ut_hyp_review_acceptance_missing"
        self._cleanup_run(run_id)
        try:
            doctor_path = Path(f"data/agent_reports/{run_id}_doctor_variance.json")
            commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
            doctor_path.parent.mkdir(parents=True, exist_ok=True)
            commander_path.parent.mkdir(parents=True, exist_ok=True)
            doctor_path.write_text(
                json.dumps(
                    {
                        "run_id": run_id,
                        "normalized_decision": "HOLD_NEED_DATA",
                        "measurement_state": "OBSERVABLE",
                        "hypothesis_portfolio": [
                            {
                                "hypothesis_id": "h1",
                                "target_metric": "gmv_growth_rate",
                                "evidence_refs": ["artifact:data/metrics_snapshots/x.json#"],
                            }
                        ],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            commander_path.write_text(
                json.dumps(
                    {
                        "run_id": run_id,
                        "normalized_decision": "HOLD_NEED_DATA",
                        "blocked_by": [],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            with mock.patch.object(sys, "argv", ["verify_acceptance.py", "--run-id", run_id]):
                with self.assertRaises(SystemExit):
                    acceptance_mod.main()

            acceptance_path = Path(f"data/acceptance/{run_id}_acceptance.json")
            self.assertTrue(acceptance_path.exists())
            payload = json.loads(acceptance_path.read_text(encoding="utf-8"))
            checks = payload.get("checks", {})
            review_check = checks.get("commander_hypothesis_review_present", {})
            self.assertEqual(review_check.get("status"), "FAIL")
            self.assertEqual(review_check.get("reason_code"), "HYPOTHESIS_REVIEW_MISSING")
        finally:
            self._cleanup_run(run_id)

    def test_acceptance_fails_when_review_coverage_incomplete(self) -> None:
        run_id = "ut_hyp_review_acceptance_coverage"
        self._cleanup_run(run_id)
        try:
            doctor_path = Path(f"data/agent_reports/{run_id}_doctor_variance.json")
            commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
            doctor_path.parent.mkdir(parents=True, exist_ok=True)
            commander_path.parent.mkdir(parents=True, exist_ok=True)
            doctor_path.write_text(
                json.dumps(
                    {
                        "run_id": run_id,
                        "normalized_decision": "HOLD_NEED_DATA",
                        "measurement_state": "OBSERVABLE",
                        "hypothesis_portfolio": [
                            {
                                "hypothesis_id": "h1",
                                "target_metric": "gmv_growth_rate",
                                "evidence_refs": ["artifact:data/metrics_snapshots/x.json#"],
                            },
                            {
                                "hypothesis_id": "h2",
                                "target_metric": "margin_rate",
                                "evidence_refs": ["artifact:data/metrics_snapshots/y.json#"],
                            },
                        ],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            commander_path.write_text(
                json.dumps(
                    {
                        "run_id": run_id,
                        "normalized_decision": "HOLD_NEED_DATA",
                        "doctor_hypothesis_review": [
                            {
                                "hypothesis_id": "h1",
                                "deterministic_verdict": "SUPPORTED",
                                "final_verdict": "SUPPORTED",
                                "impact_class": "low",
                                "goal_alignment": "unknown",
                                "cross_goal_reference": None,
                                "evidence_refs": ["artifact:data/metrics_snapshots/x.json#"],
                            }
                        ],
                        "hypothesis_review_summary": {
                            "total_count": 1,
                            "supported_count": 1,
                            "weak_count": 0,
                            "refuted_count": 0,
                            "untestable_count": 0,
                            "refuted_high_count": 0,
                            "goal_alignment_status": "UNKNOWN",
                            "misaligned_hypothesis_count": 0,
                            "verification_quality_score": 1.0,
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            with mock.patch.object(sys, "argv", ["verify_acceptance.py", "--run-id", run_id]):
                with self.assertRaises(SystemExit):
                    acceptance_mod.main()

            acceptance_path = Path(f"data/acceptance/{run_id}_acceptance.json")
            self.assertTrue(acceptance_path.exists())
            payload = json.loads(acceptance_path.read_text(encoding="utf-8"))
            checks = payload.get("checks", {})
            coverage_check = checks.get("commander_hypothesis_review_coverage", {})
            self.assertEqual(coverage_check.get("status"), "FAIL")
            self.assertEqual(coverage_check.get("reason_code"), "HYPOTHESIS_REVIEW_MISSING")
        finally:
            self._cleanup_run(run_id)

    def test_batch_summary_contains_review_aggregate_fields(self) -> None:
        batch_id = "ut_hyp_review_batch_summary"
        out_summary = ROOT / f"data/batch_eval/{batch_id}_summary.json"
        out_sidecar = Path(f"{out_summary}.sha256")
        out_summary.unlink(missing_ok=True)
        out_sidecar.unlink(missing_ok=True)

    def test_batch_summary_excludes_unavailable_review_from_quality_kpi(self) -> None:
        batch_id = "ut_hyp_review_batch_unavailable"
        out_summary = ROOT / f"data/batch_eval/{batch_id}_summary.json"
        out_sidecar = Path(f"{out_summary}.sha256")
        out_summary.unlink(missing_ok=True)
        out_sidecar.unlink(missing_ok=True)

        fake_cases = [
            {"case_id": "case_001", "query": "q1", "expected_block": False},
            {"case_id": "case_002", "query": "q2", "expected_block": False},
        ]

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        unavailable_payload = {
            "runtime_flags": {"provisional_local_fallback": False},
            "captain_usage": {"cost_usd_estimate": 0.01, "cloud_path": True},
            "doctor_usage": {"cost_usd_estimate": 0.02, "cloud_path": True},
            "commander_usage": {"cost_usd_estimate": 0.03, "cloud_path": True},
            "commander": {"decision": "HOLD_NEED_DATA"},
            "doctor": {"risk_signals": [], "recommended_actions": []},
            "reasoning": {"confidence": {}, "evidence_quality": {}},
            "supported_count": 0,
            "refuted_count": 0,
            "untestable_count": 0,
            "verification_quality_score": 0.0,
            "verification_unavailable": True,
        }
        available_payload = {
            "runtime_flags": {"provisional_local_fallback": False},
            "captain_usage": {"cost_usd_estimate": 0.01, "cloud_path": True},
            "doctor_usage": {"cost_usd_estimate": 0.02, "cloud_path": True},
            "commander_usage": {"cost_usd_estimate": 0.03, "cloud_path": True},
            "commander": {"decision": "HOLD_NEED_DATA"},
            "doctor": {"risk_signals": [], "recommended_actions": []},
            "reasoning": {"confidence": {}, "evidence_quality": {}},
            "supported_count": 3,
            "refuted_count": 1,
            "untestable_count": 1,
            "verification_quality_score": 0.5,
            "verification_unavailable": False,
        }

        with mock.patch.object(sys, "argv", ["run_batch_eval.py", "--batch-id", batch_id, "--max-cases", "2", "--sleep-seconds", "0"]), mock.patch.object(
            batch_mod, "_ensure_groq_secrets", return_value=Path("/tmp/.groq_secrets")
        ), mock.patch.object(
            batch_mod, "build_batch_eval_cases", return_value=fake_cases
        ), mock.patch.object(
            batch_mod, "subprocess"
        ) as mock_subprocess, mock.patch.object(
            batch_mod, "_run_chain_once", return_value=(0, "", "", 0.01)
        ), mock.patch.object(
            batch_mod, "_load_artifact", side_effect=[unavailable_payload, available_payload]
        ), mock.patch.object(
            batch_mod.time, "sleep", return_value=None
        ):
            mock_subprocess.run.return_value = _Proc()
            batch_mod.main()

        payload = json.loads(out_summary.read_text(encoding="utf-8"))
        self.assertEqual(payload.get("verification_unavailable_cases"), 1)
        self.assertEqual(payload.get("verification_quality_cases"), 1)
        self.assertAlmostEqual(float(payload.get("verification_quality_score")), 0.5, places=4)
        self.assertEqual(payload.get("supported_count"), 3)
        self.assertEqual(payload.get("refuted_count"), 1)
        self.assertEqual(payload.get("untestable_count"), 1)

        out_summary.unlink(missing_ok=True)
        out_sidecar.unlink(missing_ok=True)

        fake_case = {"case_id": "case_001", "query": "q", "expected_block": False}

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        fake_payload = {
            "runtime_flags": {"provisional_local_fallback": False},
            "captain_usage": {"cost_usd_estimate": 0.01, "cloud_path": True},
            "doctor_usage": {"cost_usd_estimate": 0.02, "cloud_path": True},
            "commander_usage": {"cost_usd_estimate": 0.03, "cloud_path": True},
            "commander": {"decision": "HOLD_NEED_DATA"},
            "doctor": {"risk_signals": [], "recommended_actions": []},
            "reasoning": {"confidence": {}, "evidence_quality": {}},
            "supported_count": 2,
            "refuted_count": 1,
            "untestable_count": 1,
            "verification_quality_score": 0.61,
        }

        with mock.patch.object(sys, "argv", ["run_batch_eval.py", "--batch-id", batch_id, "--max-cases", "1", "--sleep-seconds", "0"]), mock.patch.object(
            batch_mod, "_ensure_groq_secrets", return_value=Path("/tmp/.groq_secrets")
        ), mock.patch.object(
            batch_mod, "build_batch_eval_cases", return_value=[fake_case]
        ), mock.patch.object(
            batch_mod, "subprocess"
        ) as mock_subprocess, mock.patch.object(
            batch_mod, "_run_chain_once", return_value=(0, "", "", 0.01)
        ), mock.patch.object(
            batch_mod, "_load_artifact", return_value=fake_payload
        ), mock.patch.object(
            batch_mod.time, "sleep", return_value=None
        ):
            mock_subprocess.run.return_value = _Proc()
            batch_mod.main()

        payload = json.loads(out_summary.read_text(encoding="utf-8"))
        self.assertIn("supported_count", payload)
        self.assertIn("refuted_count", payload)
        self.assertIn("untestable_count", payload)
        self.assertIn("verification_quality_score", payload)
        self.assertEqual(payload["supported_count"], 2)
        self.assertEqual(payload["refuted_count"], 1)
        self.assertEqual(payload["untestable_count"], 1)
        self.assertAlmostEqual(float(payload["verification_quality_score"]), 0.61, places=4)

        out_summary.unlink(missing_ok=True)
        out_sidecar.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
