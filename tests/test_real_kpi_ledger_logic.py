from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts import run_agent_value_eval as eval_mod
from src.security_utils import write_sha256_sidecar


class RealKpiLedgerLogicTests(unittest.TestCase):
    def _write_ledger(self, run_id: str, payload: dict) -> Path:
        path = Path(f"data/agent_eval/{run_id}_decision_outcomes_ledger.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)
        return path

    def _cleanup(self, run_ids: list[str]) -> None:
        for run_id in run_ids:
            path = Path(f"data/agent_eval/{run_id}_decision_outcomes_ledger.json")
            sidecar = Path(f"{path}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if path.exists():
                path.unlink()

    def test_collect_real_outcomes_uses_history_only(self) -> None:
        current = "ut_real_kpi_current"
        old_1 = "ut_real_kpi_old_1"
        old_2 = "ut_real_kpi_old_2"
        self._cleanup([current, old_1, old_2])
        try:
            self._write_ledger(
                old_1,
                {
                    "version": "decision_outcomes_ledger_v1",
                    "run_id": old_1,
                    "generated_at": "2026-03-01T00:00:00+00:00",
                    "ground_truth_source": "history",
                    "ground_truth_refs": ["artifact:data/agent_eval/source1.json"],
                    "label_window_days": 14,
                    "sample_size": 2,
                    "would_have_prevented_loss_rate": 0.5,
                    "decision_regret_rate": 0.5,
                    "outcomes": [
                        {"decision_id": "d1", "decision": "STOP", "actual_outcome": "loss_risk", "prevented_loss": True, "regret": False},
                        {"decision_id": "d2", "decision": "RUN_AB", "actual_outcome": "loss_risk", "prevented_loss": False, "regret": True},
                    ],
                },
            )
            self._write_ledger(
                old_2,
                {
                    "version": "decision_outcomes_ledger_v1",
                    "run_id": old_2,
                    "generated_at": "2026-03-02T00:00:00+00:00",
                    "ground_truth_source": "history",
                    "ground_truth_refs": ["artifact:data/agent_eval/source2.json"],
                    "label_window_days": 21,
                    "sample_size": 1,
                    "would_have_prevented_loss_rate": 1.0,
                    "decision_regret_rate": 0.0,
                    "outcomes": [
                        {"decision_id": "d3", "decision": "HOLD_NEED_DATA", "actual_outcome": "loss_risk", "prevented_loss": True, "regret": False}
                    ],
                },
            )
            outcomes, refs, label_window = eval_mod._collect_real_outcomes_from_history(current)
            self.assertEqual(len(outcomes), 3)
            self.assertEqual(len(refs), 2)
            self.assertEqual(label_window, 21)
        finally:
            self._cleanup([current, old_1, old_2])


if __name__ == "__main__":
    unittest.main()
