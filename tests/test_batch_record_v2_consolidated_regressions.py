#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import build_batch_consolidated_report as consolidated_mod
from scripts import run_batch_eval as batch_mod
from scripts import run_poc_e2e as poc_mod
from src.security_utils import write_sha256_sidecar


def _usage(cost: float = 0.01) -> dict[str, object]:
    return {"cost_usd_estimate": float(cost), "model": "stub-model", "total_tokens": 100}


def _reasoning_case(decision: str, run_id: str) -> dict[str, object]:
    return {
        "run_id": run_id,
        "decision": decision,
        "query": f"hypothesis {run_id}",
        "executive_summary": f"summary {run_id}",
        "go_no_go_rationale": ["rationale_a", "rationale_b"],
        "risk_signals": ["risk_a"],
        "recommended_actions": ["action_a"],
        "reasoning_observed_facts": ["fact_a", "fact_b"],
        "reasoning_causal_interpretation": "causal interpretation",
        "reasoning_why_not_opposite_decision": "opposite rejected",
        "reasoning_confidence": {"score": 0.73, "label": "MEDIUM", "basis": ["basis_a"]},
        "reasoning_evidence_quality": {
            "score": 0.68,
            "label": "MEDIUM",
            "evidence_count": 4,
            "missing_evidence": ["gap_a"],
        },
        "reasoning_decision_tradeoffs": ["tradeoff_a"],
        "reasoning_mitigations": ["mitigation_a"],
        "reasoning_uncertainty_gaps": ["gap_a"],
        "commander_next_steps": ["next_a"],
        "top_match": {
            "experiment_id": f"exp_{run_id}",
            "similarity": 0.57,
            "primary_metric_outcome": {"metric_id": "gmv", "delta_pct": 0.06},
            "guardrail_breach": {"metric_id": "margin", "delta_pct": -0.02},
        },
    }


class BatchRecordAndConsolidatedRegressionsTests(unittest.TestCase):
    def test_batch_record_v2_includes_reasoning_and_passes_contract(self) -> None:
        contract = poc_mod._load_batch_record_contract()
        record = poc_mod._build_batch_record_v2(
            run_id="run_reasoning_001",
            query="Test hypothesis",
            generated_at="2026-03-11T00:00:00+00:00",
            captain={"sanity_status": "PASS", "pass_to_doctor": True},
            doctor={
                "suggested_decision": "HOLD_NEED_DATA",
                "risk_signals": ["risk_1"],
                "recommended_actions": ["collect_more_data"],
                "causal_story": "Causal chain suggests mixed effect.",
            },
            commander={
                "decision": "HOLD_NEED_DATA",
                "executive_summary": "Need more data before rollout.",
                "rationale_bullets": ["uncertain guardrail impact"],
                "next_steps": ["expand sample"],
            },
            captain_usage=_usage(0.01),
            doctor_usage=_usage(0.02),
            commander_usage=_usage(0.03),
            runtime_flags={"backend_error": False, "retryable_api_error": False, "provisional_local_fallback": False, "fallback_agents": []},
            retrieval_top_k=3,
            top_matches=[
                {
                    "experiment_id": "exp_1",
                    "similarity": 0.61,
                    "primary_metric_outcome": {"metric_id": "orders", "delta_pct": 0.04},
                    "guardrail_breach": {"metric_id": "margin", "delta_pct": -0.01},
                }
            ],
            needs_cloud_reconciliation=False,
            reconciliation=None,
        )
        poc_mod._validate_batch_record_payload(record, contract)
        reasoning = record.get("reasoning")
        self.assertIsInstance(reasoning, dict)
        self.assertIn("observed_facts", reasoning)
        self.assertIn("causal_interpretation", reasoning)
        self.assertIn("why_not_opposite_decision", reasoning)
        self.assertIn("confidence", reasoning)
        self.assertIn("evidence_quality", reasoning)
        self.assertIn("decision_tradeoffs", reasoning)
        self.assertIn("mitigations", reasoning)
        self.assertIn("uncertainty_gaps", reasoning)

    def test_run_batch_eval_marks_failed_record_and_continues(self) -> None:
        batch_id = "unit_failed_record_batch"
        out_summary = ROOT / f"data/batch_eval/{batch_id}_summary.json"
        out_sidecar = Path(f"{out_summary}.sha256")
        if out_summary.exists():
            out_summary.unlink()
        if out_sidecar.exists():
            out_sidecar.unlink()

        fake_case = {"case_id": "case_001", "query": "q", "expected_block": False}

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        with mock.patch.object(sys, "argv", ["run_batch_eval.py", "--batch-id", batch_id, "--max-cases", "1", "--sleep-seconds", "0"]), mock.patch.object(
            batch_mod, "_ensure_groq_secrets", return_value=Path("/tmp/.groq_secrets")
        ), mock.patch.object(
            batch_mod, "build_batch_eval_cases", return_value=[fake_case]
        ), mock.patch.object(
            batch_mod, "subprocess"
        ) as mock_subprocess, mock.patch.object(
            batch_mod, "_run_chain_once", return_value=(0, "", "", 0.01)
        ), mock.patch.object(
            batch_mod, "_load_artifact", side_effect=RuntimeError("schema_validation_error:missing_reasoning")
        ), mock.patch.object(
            batch_mod.time, "sleep", return_value=None
        ):
            mock_subprocess.run.return_value = _Proc()
            batch_mod.main()

        self.assertTrue(out_summary.exists(), "summary should be written even on FAILED_RECORD")
        payload = json.loads(out_summary.read_text(encoding="utf-8"))
        self.assertEqual(payload.get("failed_cases"), 1)
        self.assertEqual(len(payload.get("records", [])), 1)
        self.assertEqual(str(payload["records"][0].get("status")), "FAILED_RECORD")
        self.assertTrue(out_sidecar.exists(), "summary sidecar should exist")

        out_summary.unlink(missing_ok=True)
        out_sidecar.unlink(missing_ok=True)

    def test_consolidated_groups_by_decision_buckets_and_contains_reasoning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            summary_path = td_path / "batch_summary.json"
            report_path = td_path / "BATCH_CONSOLIDATED_REPORT.md"
            payload = {
                "batch_id": "batch_regression_001",
                "dataset": "baseline",
                "record_format": "batch_record_v2",
                "records_source": "summary.records_from_staging",
                "summary_source_of_truth": "data/batch_eval/batch_regression_001_summary.json",
                "completed_cases": 3,
                "availability_kpi": 1.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
                "records": [
                    _reasoning_case("GO", "r_go"),
                    _reasoning_case("HOLD_NEED_DATA", "r_hold"),
                    _reasoning_case("STOP_ROLLOUT", "r_stop"),
                ],
            }
            summary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            write_sha256_sidecar(summary_path)

            with mock.patch.object(
                sys,
                "argv",
                [
                    "build_batch_consolidated_report.py",
                    "--summary",
                    str(summary_path),
                    "--out",
                    str(report_path),
                    "--group-size",
                    "2",
                ],
            ):
                consolidated_mod.main()

            text = report_path.read_text(encoding="utf-8")
            self.assertIn("Decision Group: GO", text)
            self.assertIn("Decision Group: HOLD", text)
            self.assertIn("Decision Group: STOP", text)
            self.assertIn("Observed Facts:", text)
            self.assertIn("Why Not Opposite Decision:", text)
            self.assertIn("Confidence:", text)
            self.assertIn("Evidence Quality:", text)
            self.assertLess(text.find("Decision Group: GO"), text.find("Decision Group: HOLD"))
            self.assertLess(text.find("Decision Group: HOLD"), text.find("Decision Group: STOP"))

    def test_consolidated_fails_when_required_reasoning_fields_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            summary_path = td_path / "batch_summary_invalid.json"
            report_path = td_path / "BATCH_CONSOLIDATED_REPORT_INVALID.md"
            bad_case = _reasoning_case("GO", "r_bad")
            del bad_case["reasoning_confidence"]
            payload = {
                "batch_id": "batch_regression_002",
                "dataset": "baseline",
                "record_format": "batch_record_v2",
                "records_source": "summary.records_from_staging",
                "summary_source_of_truth": "data/batch_eval/batch_regression_002_summary.json",
                "completed_cases": 1,
                "availability_kpi": 1.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
                "records": [bad_case],
            }
            summary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            write_sha256_sidecar(summary_path)

            with mock.patch.object(
                sys,
                "argv",
                [
                    "build_batch_consolidated_report.py",
                    "--summary",
                    str(summary_path),
                    "--out",
                    str(report_path),
                ],
            ):
                with self.assertRaisesRegex(SystemExit, "required_case_fields"):
                    consolidated_mod.main()


if __name__ == "__main__":
    unittest.main()
