from __future__ import annotations

import unittest

from scripts.run_commander_priority import _enforce_guardrail_rollout_veto


class CommanderGuardrailMandateTests(unittest.TestCase):
    def test_guardrail_breach_blocks_aggressive_decision(self) -> None:
        payload = {
            "decision": "GO",
            "normalized_decision": "GO",
            "blocked_by": [],
            "guardrail_status_check": [
                {"metric_id": "fill_rate_units", "status": "BREACH", "blocks_rollout": True}
            ],
        }
        _enforce_guardrail_rollout_veto(payload)
        self.assertEqual(payload.get("decision"), "HOLD_NEED_DATA")
        self.assertEqual(payload.get("normalized_decision"), "HOLD_NEED_DATA")
        self.assertIn("guardrail_breach_rollout_blocked", payload.get("blocked_by", []))

    def test_no_breach_keeps_decision(self) -> None:
        payload = {
            "decision": "RUN_AB",
            "normalized_decision": "RUN_AB",
            "blocked_by": [],
            "guardrail_status_check": [
                {"metric_id": "fill_rate_units", "status": "PASS", "blocks_rollout": False}
            ],
        }
        _enforce_guardrail_rollout_veto(payload)
        self.assertEqual(payload.get("normalized_decision"), "RUN_AB")
        self.assertNotIn("guardrail_breach_rollout_blocked", payload.get("blocked_by", []))


if __name__ == "__main__":
    unittest.main()

