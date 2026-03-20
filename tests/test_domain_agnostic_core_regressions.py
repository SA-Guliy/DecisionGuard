from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCTOR_PATH = REPO_ROOT / "scripts" / "run_doctor_variance.py"
COMMANDER_PATH = REPO_ROOT / "scripts" / "run_commander_priority.py"

FORBIDDEN_METRIC_TOKENS = [
    "goal1",
    "goal2",
    "goal3",
    "writeoff",
    "aov",
    "buyers",
    "orders_cnt",
    "fill_rate_units",
    "gp_margin",
    "oos_lost_gmv_rate",
    "gmv_floor",
    "mean_gmv",
    "gmv",
    "order_gmv",
]

FORBIDDEN_DOMAIN_TOKENS = [
    "enable_competitor_prices",
    "competitor_mode_missing",
    "competitor_confounding_risk",
    "inventory_closing_nonnegative_est",
    "realism_v13",
]


class TestDomainAgnosticCoreRegressions(unittest.TestCase):
    @staticmethod
    def _function_source(text: str, name: str) -> str:
        marker = f"def {name}("
        start = text.find(marker)
        if start < 0:
            raise AssertionError(f"function not found: {name}")
        tail = text[start:]
        next_def = tail.find("\ndef ", len(marker))
        return tail if next_def < 0 else tail[:next_def]

    def test_doctor_has_no_hardcoded_metric_or_domain_literals(self) -> None:
        text = DOCTOR_PATH.read_text(encoding="utf-8").lower()
        for token in FORBIDDEN_METRIC_TOKENS + FORBIDDEN_DOMAIN_TOKENS:
            self.assertNotIn(token, text, f"Doctor core contains forbidden literal: {token}")

    def test_commander_has_no_hardcoded_metric_literals(self) -> None:
        text = COMMANDER_PATH.read_text(encoding="utf-8").lower()
        for token in FORBIDDEN_METRIC_TOKENS:
            self.assertNotIn(token, text, f"Commander core contains forbidden literal: {token}")

    def test_doctor_uses_template_policy_hooks(self) -> None:
        text = DOCTOR_PATH.read_text(encoding="utf-8")
        self.assertIn("captain_issue_policies", text)
        self.assertIn("run_config_rules", text)

    def test_commander_helper_functions_have_no_legacy_gmv_fallback(self) -> None:
        text = COMMANDER_PATH.read_text(encoding="utf-8")
        activity_src = self._function_source(text, "_pick_mean_activity_proxy").lower()
        ref_src = self._function_source(text, "_pick_mean_reference_metric").lower()
        for token in ("mean_gmv", "gmv", "order_gmv"):
            self.assertNotIn(token, activity_src, f"legacy token found in _pick_mean_activity_proxy: {token}")
            self.assertNotIn(token, ref_src, f"legacy token found in _pick_mean_reference_metric: {token}")


if __name__ == "__main__":
    unittest.main()
