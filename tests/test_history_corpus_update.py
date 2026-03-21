from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import update_history_corpus as history_mod
from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar


class HistoryCorpusUpdateTests(unittest.TestCase):
    def _write_json(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)

    def test_updates_corpus_and_vector_index_for_significant_result(self) -> None:
        run_id = "ut_history_sig"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            paired_context = root / f"{run_id}_paired_experiment_v2.json"
            stat_bundle = root / f"{run_id}_stat_evidence_bundle_v1.json"
            doctor = root / f"{run_id}_doctor_variance.json"
            commander = root / f"{run_id}_commander_priority.json"
            sot = root / "history_sot_v1.json"
            index = root / "history_vector_index_v1.json"
            audit = root / f"{run_id}_history_corpus_update.json"

            self._write_json(
                paired_context,
                {
                    "version": "paired_experiment_v2",
                    "run_id": run_id,
                    "experiment_id": "exp_hist_sig",
                    "paired_status": "COMPLETE",
                    "layer1": {"ok": True},
                    "layer2": {"ok": True},
                    "merger_artifact_ref": "artifact:data/x.json#",
                },
            )
            self._write_json(
                stat_bundle,
                {
                    "version": "stat_evidence_bundle_v1",
                    "run_id": run_id,
                    "generated_at": "2026-03-20T00:00:00+00:00",
                    "status": "PASS",
                    "paired_status": "COMPLETE",
                    "layers_present": {
                        "layer1_live_stats": True,
                        "layer2_guardrail_check": True,
                        "layer3_history": True,
                    },
                    "srm_flag": False,
                    "n_min_required": 30,
                    "metrics": [
                        {
                            "metric_id": "aov",
                            "metric_type": "continuous",
                            "ctrl_value": 100.0,
                            "trt_value": 110.0,
                            "delta": 10.0,
                            "n_ctrl": 120,
                            "n_trt": 120,
                            "method": "welch_ttest_from_stats",
                            "p_value": 0.01,
                            "ci_lower": 5.0,
                            "ci_upper": 15.0,
                            "power": None,
                            "verdict": "POSITIVE_SIGNIFICANT",
                            "is_guardrail_breach": False,
                            "note": "",
                        },
                        {
                            "metric_id": "fill_rate_units",
                            "metric_type": "ratio_or_proportion",
                            "ctrl_value": 0.95,
                            "trt_value": 0.91,
                            "delta": -0.04,
                            "n_ctrl": 120,
                            "n_trt": 120,
                            "method": "aggregate_only",
                            "p_value": None,
                            "ci_lower": None,
                            "ci_upper": None,
                            "power": None,
                            "verdict": "UNDERPOWERED",
                            "is_guardrail_breach": True,
                            "note": "ratio metric",
                        },
                    ],
                    "guardrail_status_check": [
                        {
                            "metric_id": "fill_rate_units",
                            "status": "BREACH",
                            "blocks_rollout": True,
                            "evidence_ref": "artifact:data/metrics_snapshots/x.json#/metrics/fill_rate_units",
                        }
                    ],
                    "error_code": "NONE",
                    "blocked_by": [],
                    "required_actions": [],
                },
            )
            self._write_json(
                doctor,
                {
                    "run_id": run_id,
                    "hypothesis_portfolio": [{"hypothesis_id": "h1", "hypothesis": "Increase AOV via min basket"}],
                    "experiment_header": {"ab_primary_metric": "aov"},
                    "executive_summary": {"headline": "AOV can be lifted with threshold tuning"},
                },
            )
            self._write_json(
                commander,
                {
                    "run_id": run_id,
                    "normalized_decision": "HOLD_NEED_DATA",
                    "executive_summary": {"headline": "Significant gain but guardrail breach blocks rollout"},
                },
            )
            self._write_json(
                sot,
                {
                    "version": "history_sot_v1",
                    "generated_at": "2026-03-19T00:00:00+00:00",
                    "reports": [
                        {
                            "experiment_id": "exp_old",
                            "hypothesis": "legacy",
                            "primary_metric_outcome": {"metric_id": "aov", "control": 1, "treatment": 2, "delta_pct": 1.0},
                            "guardrail_breach": {"metric_id": "gp_margin", "control": 0.2, "treatment": 0.19, "delta_pct": -0.05, "breach_reason": "legacy"},
                            "reasoning_decision": {"decision": "HOLD_NEED_DATA", "analyst_summary": "legacy"},
                        }
                    ],
                },
            )
            self._write_json(
                index,
                {
                    "version": "history_vector_index_v1",
                    "generated_at": "2026-03-19T00:00:00+00:00",
                    "vocab": ["legacy"],
                    "vectors": [{"experiment_id": "exp_old", "vector": [1.0]}],
                },
            )

            argv = [
                "update_history_corpus.py",
                "--run-id",
                run_id,
                "--paired-context-path",
                str(paired_context),
                "--stat-evidence-path",
                str(stat_bundle),
                "--doctor-path",
                str(doctor),
                "--commander-path",
                str(commander),
                "--sot-path",
                str(sot),
                "--index-path",
                str(index),
                "--audit-path",
                str(audit),
            ]
            with mock.patch.object(sys, "argv", argv):
                history_mod.main()

            out_sot = json.loads(sot.read_text(encoding="utf-8"))
            out_index = json.loads(index.read_text(encoding="utf-8"))
            out_audit = json.loads(audit.read_text(encoding="utf-8"))

            self.assertEqual(out_audit.get("status"), "PASS")
            reports = out_sot.get("reports", [])
            self.assertEqual(len(reports), 2)
            self.assertTrue(any(str(r.get("experiment_id")) == "exp_hist_sig" for r in reports if isinstance(r, dict)))
            self.assertEqual(len(out_index.get("vectors", [])), 2)

            self.assertTrue(verify_sha256_sidecar(sot, required=True)[0])
            self.assertTrue(verify_sha256_sidecar(index, required=True)[0])
            self.assertTrue(verify_sha256_sidecar(audit, required=True)[0])

    def test_skips_update_when_primary_metric_not_significant(self) -> None:
        run_id = "ut_history_skip"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            paired_context = root / f"{run_id}_paired_experiment_v2.json"
            stat_bundle = root / f"{run_id}_stat_evidence_bundle_v1.json"
            doctor = root / f"{run_id}_doctor_variance.json"
            commander = root / f"{run_id}_commander_priority.json"
            sot = root / "history_sot_v1.json"
            index = root / "history_vector_index_v1.json"
            audit = root / f"{run_id}_history_corpus_update.json"

            self._write_json(
                paired_context,
                {
                    "version": "paired_experiment_v2",
                    "run_id": run_id,
                    "experiment_id": "exp_hist_skip",
                    "paired_status": "COMPLETE",
                    "layer1": {"ok": True},
                    "layer2": {"ok": True},
                    "merger_artifact_ref": "artifact:data/x.json#",
                },
            )
            self._write_json(
                stat_bundle,
                {
                    "version": "stat_evidence_bundle_v1",
                    "run_id": run_id,
                    "generated_at": "2026-03-20T00:00:00+00:00",
                    "status": "PASS",
                    "paired_status": "COMPLETE",
                    "layers_present": {
                        "layer1_live_stats": True,
                        "layer2_guardrail_check": True,
                        "layer3_history": True,
                    },
                    "srm_flag": False,
                    "n_min_required": 30,
                    "metrics": [
                        {
                            "metric_id": "aov",
                            "metric_type": "continuous",
                            "ctrl_value": 100.0,
                            "trt_value": 101.0,
                            "delta": 1.0,
                            "n_ctrl": 120,
                            "n_trt": 120,
                            "method": "welch_ttest_from_stats",
                            "p_value": 0.4,
                            "ci_lower": -2.0,
                            "ci_upper": 4.0,
                            "power": None,
                            "verdict": "NO_SIGNIFICANT_EFFECT",
                            "is_guardrail_breach": False,
                            "note": "",
                        }
                    ],
                    "guardrail_status_check": [],
                    "error_code": "NONE",
                    "blocked_by": [],
                    "required_actions": [],
                },
            )
            self._write_json(doctor, {"run_id": run_id, "hypothesis_portfolio": []})
            self._write_json(commander, {"run_id": run_id, "normalized_decision": "HOLD_NEED_DATA"})
            self._write_json(
                sot,
                {
                    "version": "history_sot_v1",
                    "generated_at": "2026-03-19T00:00:00+00:00",
                    "reports": [],
                },
            )
            self._write_json(
                index,
                {
                    "version": "history_vector_index_v1",
                    "generated_at": "2026-03-19T00:00:00+00:00",
                    "vocab": [],
                    "vectors": [],
                },
            )

            argv = [
                "update_history_corpus.py",
                "--run-id",
                run_id,
                "--paired-context-path",
                str(paired_context),
                "--stat-evidence-path",
                str(stat_bundle),
                "--doctor-path",
                str(doctor),
                "--commander-path",
                str(commander),
                "--sot-path",
                str(sot),
                "--index-path",
                str(index),
                "--audit-path",
                str(audit),
            ]
            with mock.patch.object(sys, "argv", argv):
                history_mod.main()

            out_sot = json.loads(sot.read_text(encoding="utf-8"))
            out_audit = json.loads(audit.read_text(encoding="utf-8"))
            self.assertEqual(len(out_sot.get("reports", [])), 0)
            self.assertEqual(out_audit.get("status"), "SKIP")
            self.assertEqual(out_audit.get("details", {}).get("reason"), "primary_metric_not_significant")


if __name__ == "__main__":
    unittest.main()

