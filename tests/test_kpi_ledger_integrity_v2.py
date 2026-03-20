from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts import run_agent_value_eval as eval_mod
from src.security_utils import write_sha256_sidecar


class KpiLedgerIntegrityV2Tests(unittest.TestCase):
    def _ledger_path(self, run_id: str) -> Path:
        return Path(f"data/agent_eval/{run_id}_decision_outcomes_ledger.json")

    def _write_ledger(self, run_id: str, payload: dict) -> None:
        path = self._ledger_path(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)

    def _cleanup(self, run_ids: list[str]) -> None:
        for run_id in run_ids:
            path = self._ledger_path(run_id)
            sidecar = Path(f"{path}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if path.exists():
                path.unlink()

    def test_filters_dirty_outcomes(self) -> None:
        current = "ut_kpi_v2_current"
        old = "ut_kpi_v2_old"
        self._cleanup([current, old])
        try:
            self._write_ledger(
                old,
                {
                    "version": "decision_outcomes_ledger_v1",
                    "run_id": old,
                    "label_window_days": 14,
                    "outcomes": [
                        {"decision_id": "ok_1", "decision": "STOP", "actual_outcome": "risk", "prevented_loss": True, "regret": False},
                        {"decision_id": "bad_1", "decision": "UNKNOWN_DECISION", "actual_outcome": "risk", "prevented_loss": False, "regret": True},
                        {"decision_id": "", "decision": "RUN_AB", "actual_outcome": "risk", "prevented_loss": False, "regret": True},
                    ],
                },
            )
            rows, refs, label_window = eval_mod._collect_real_outcomes_from_history(current)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["decision_id"], "ok_1")
            self.assertEqual(len(refs), 1)
            self.assertEqual(label_window, 14)
        finally:
            self._cleanup([current, old])

    def test_filters_cross_family_contamination(self) -> None:
        current = "v13_agent_prod_013"
        same_family = "v13_agent_prod_001"
        foreign_family = "v99_agent_prod_002"
        self._cleanup([current, same_family, foreign_family])
        try:
            self._write_ledger(
                same_family,
                {
                    "version": "decision_outcomes_ledger_v1",
                    "run_id": same_family,
                    "label_window_days": 10,
                    "outcomes": [
                        {"decision_id": "same_family_1", "decision": "HOLD_NEED_DATA", "actual_outcome": "risk", "prevented_loss": True, "regret": False}
                    ],
                },
            )
            self._write_ledger(
                foreign_family,
                {
                    "version": "decision_outcomes_ledger_v1",
                    "run_id": foreign_family,
                    "label_window_days": 30,
                    "outcomes": [
                        {"decision_id": "foreign_1", "decision": "STOP", "actual_outcome": "risk", "prevented_loss": True, "regret": False}
                    ],
                },
            )
            rows, refs, _ = eval_mod._collect_real_outcomes_from_history(current)
            ids = sorted(r["decision_id"] for r in rows)
            self.assertEqual(ids, ["same_family_1"])
            self.assertEqual(len(refs), 1)
            self.assertIn(same_family, refs[0])
        finally:
            self._cleanup([current, same_family, foreign_family])

    def test_deduplicates_duplicate_decision_id_collisions(self) -> None:
        current = "ut_kpi_dup_current"
        old_a = "ut_kpi_dup_old_a"
        old_b = "ut_kpi_dup_old_b"
        self._cleanup([current, old_a, old_b])
        try:
            payload_common = {
                "version": "decision_outcomes_ledger_v1",
                "label_window_days": 21,
                "outcomes": [
                    {"decision_id": "dup_1", "decision": "RUN_AB", "actual_outcome": "risk", "prevented_loss": False, "regret": True},
                    {"decision_id": "uniq_1", "decision": "STOP", "actual_outcome": "risk", "prevented_loss": True, "regret": False},
                ],
            }
            self._write_ledger(old_a, {**payload_common, "run_id": old_a})
            self._write_ledger(
                old_b,
                {
                    **payload_common,
                    "run_id": old_b,
                    "outcomes": [
                        {"decision_id": "dup_1", "decision": "RUN_AB", "actual_outcome": "risk", "prevented_loss": False, "regret": True},
                        {"decision_id": "uniq_2", "decision": "HOLD_RISK", "actual_outcome": "risk", "prevented_loss": True, "regret": False},
                    ],
                },
            )

            rows, _, _ = eval_mod._collect_real_outcomes_from_history(current)
            ids = sorted(r["decision_id"] for r in rows)
            self.assertEqual(ids, ["dup_1", "uniq_1", "uniq_2"])
            self.assertEqual(len(rows), 3)
        finally:
            self._cleanup([current, old_a, old_b])


if __name__ == "__main__":
    unittest.main()
