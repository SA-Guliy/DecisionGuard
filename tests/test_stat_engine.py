from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.security_utils import write_sha256_sidecar
from src.stat_engine import compute_stat_evidence


class StatEngineTests(unittest.TestCase):
    def _write_json(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)

    def _snapshot(
        self,
        *,
        run_id: str,
        orders_cnt: int = 120,
        aov: float = 100.0,
        aov_stddev: float | None = 10.0,
        fill_rate_units: float = 0.97,
        oos_lost_gmv_rate: float = 0.03,
        gp_margin: float = 0.22,
    ) -> dict:
        metrics = {
            "orders_cnt": orders_cnt,
            "aov": aov,
            "fill_rate_units": fill_rate_units,
            "oos_lost_gmv_rate": oos_lost_gmv_rate,
            "gp_margin": gp_margin,
            "fill_rate_stddev": 0.02,
            "oos_lost_gmv_rate_stddev": 0.01,
            "gp_margin_stddev": 0.02,
        }
        if aov_stddev is not None:
            metrics["aov_stddev"] = aov_stddev
        return {"run_id": run_id, "metrics": metrics}

    def _row(self, bundle: dict, metric_id: str) -> dict:
        rows = bundle.get("metrics", [])
        for row in rows:
            if isinstance(row, dict) and str(row.get("metric_id", "")) == metric_id:
                return row
        raise AssertionError(f"metric not found: {metric_id}")

    def test_welch_ttest_from_stats_used_for_aov_with_sufficient_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctrl = root / "ctrl.json"
            trt = root / "trt.json"
            self._write_json(ctrl, self._snapshot(run_id="ctrl", aov=100.0, aov_stddev=9.0, orders_cnt=140))
            self._write_json(trt, self._snapshot(run_id="trt", aov=108.0, aov_stddev=9.5, orders_cnt=145))

            bundle = compute_stat_evidence(ctrl, trt, "domain_templates/darkstore_fresh_v1.json").to_dict()
            aov_row = self._row(bundle, "aov")
            self.assertEqual(aov_row.get("method"), "welch_ttest_from_stats")
            self.assertIsInstance(aov_row.get("p_value"), float)
            self.assertIn(aov_row.get("verdict"), {"POSITIVE_SIGNIFICANT", "NEGATIVE_SIGNIFICANT", "NO_SIGNIFICANT_EFFECT"})

    def test_ratio_metrics_use_aggregate_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctrl = root / "ctrl.json"
            trt = root / "trt.json"
            self._write_json(ctrl, self._snapshot(run_id="ctrl"))
            self._write_json(trt, self._snapshot(run_id="trt"))

            bundle = compute_stat_evidence(ctrl, trt, "domain_templates/darkstore_fresh_v1.json").to_dict()
            gp_margin_row = self._row(bundle, "gp_margin")
            self.assertEqual(gp_margin_row.get("method"), "aggregate_only")
            self.assertIsNone(gp_margin_row.get("p_value"))
            self.assertEqual(gp_margin_row.get("verdict"), "UNDERPOWERED")

    def test_missing_stddev_marks_underpowered(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctrl = root / "ctrl.json"
            trt = root / "trt.json"
            self._write_json(ctrl, self._snapshot(run_id="ctrl", aov_stddev=None))
            self._write_json(trt, self._snapshot(run_id="trt"))

            bundle = compute_stat_evidence(ctrl, trt, "domain_templates/darkstore_fresh_v1.json").to_dict()
            aov_row = self._row(bundle, "aov")
            self.assertEqual(aov_row.get("method"), "insufficient_data")
            self.assertEqual(aov_row.get("verdict"), "UNDERPOWERED")

    def test_guardrail_breach_is_detected_and_blocks_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctrl = root / "ctrl.json"
            trt = root / "trt.json"
            self._write_json(ctrl, self._snapshot(run_id="ctrl", fill_rate_units=0.97))
            self._write_json(trt, self._snapshot(run_id="trt", fill_rate_units=0.01))

            bundle = compute_stat_evidence(ctrl, trt, "domain_templates/darkstore_fresh_v1.json").to_dict()
            checks = [x for x in bundle.get("guardrail_status_check", []) if isinstance(x, dict) and x.get("metric_id") == "fill_rate_units"]
            self.assertTrue(checks)
            self.assertEqual(checks[0].get("status"), "BREACH")
            self.assertTrue(checks[0].get("blocks_rollout"))

    def test_srm_flag_when_ratio_drift_exceeds_10_percent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctrl = root / "ctrl.json"
            trt = root / "trt.json"
            self._write_json(ctrl, self._snapshot(run_id="ctrl", orders_cnt=150))
            self._write_json(trt, self._snapshot(run_id="trt", orders_cnt=100))

            bundle = compute_stat_evidence(ctrl, trt, "domain_templates/darkstore_fresh_v1.json").to_dict()
            self.assertTrue(bundle.get("srm_flag"))

    def test_small_samples_mark_underpowered(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctrl = root / "ctrl.json"
            trt = root / "trt.json"
            self._write_json(ctrl, self._snapshot(run_id="ctrl", orders_cnt=20, aov_stddev=8.0))
            self._write_json(trt, self._snapshot(run_id="trt", orders_cnt=18, aov_stddev=9.0))

            bundle = compute_stat_evidence(ctrl, trt, "domain_templates/darkstore_fresh_v1.json").to_dict()
            aov_row = self._row(bundle, "aov")
            self.assertEqual(aov_row.get("method"), "insufficient_data")
            self.assertEqual(aov_row.get("verdict"), "UNDERPOWERED")


if __name__ == "__main__":
    unittest.main()

