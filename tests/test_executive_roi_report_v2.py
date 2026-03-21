#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import build_executive_roi_report as roi_mod


class ExecutiveRoiReportV2Tests(unittest.TestCase):
    def test_roi_section_with_known_batch(self) -> None:
        section = roi_mod._build_roi_section(
            avg_rollout_cost_usd=50000.0,
            prevented_bad_decisions=3,
            missed_harmful_rollouts=1,
        )
        self.assertEqual(section.get("status"), "estimated")
        self.assertEqual(section.get("estimated_prevented_loss_usd"), 150000.0)
        self.assertEqual(section.get("estimated_missed_loss_usd"), 50000.0)
        self.assertEqual(section.get("estimated_saved_usd"), 100000.0)

    def test_roi_section_estimate_unavailable_when_avg_cost_zero(self) -> None:
        section = roi_mod._build_roi_section(
            avg_rollout_cost_usd=0.0,
            prevented_bad_decisions=2,
            missed_harmful_rollouts=0,
        )
        self.assertEqual(section.get("status"), "estimate_unavailable")
        self.assertIsNone(section.get("estimated_saved_usd"))


if __name__ == "__main__":
    unittest.main()
