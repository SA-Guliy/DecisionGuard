#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_captain_sanity_llm as captain_mod
from scripts import run_commander_priority as commander_mod
from scripts import run_doctor_variance as doctor_mod
from src.visible_reasoning_trace import build_visible_reasoning_trace_advisory


class ReasoningTraceAdvisoryTests(unittest.TestCase):
    def _minimal_commander_payload(self) -> dict:
        return {
            "run_id": "t_run",
            "decision": "HOLD_RISK",
            "normalized_decision": "HOLD_RISK",
            "blocked_by": ["goal_metric_misalignment"],
            "methodology_check": {
                "unit_alignment_ok": True,
                "goal_metric_alignment_ok": False,
                "stats_consistent": True,
                "measurement_state": "OBSERVABLE",
                "ab_status": "OK",
            },
            "data_requests": [{"why": "Need segment cohort evidence."}],
            "cohort_analysis": {"status": "BLOCKED_BY_DATA"},
            "evidence_refs": {"doctor": "data/agent_reports/t_run_doctor_variance.json"},
        }

    def test_trace_builder_failure_falls_back_to_empty_trace(self) -> None:
        trace, meta = build_visible_reasoning_trace_advisory(
            enabled=True,
            trace_builder=lambda: (_ for _ in ()).throw(RuntimeError("trace_builder_failed")),
            trace_prefix="test:trace",
        )
        self.assertEqual(trace, {"claims": [], "gates_checked": [], "unknowns": []})
        self.assertTrue(meta.get("fallback"))
        self.assertEqual(meta.get("status"), "fallback_empty")

    def test_commander_trace_invariant_for_decision_on_flag_toggle(self) -> None:
        payload_off = self._minimal_commander_payload()
        payload_on = deepcopy(payload_off)

        with patch.dict("os.environ", {"ENABLE_VISIBLE_REASONING_TRACE": "0"}, clear=False):
            commander_mod._attach_phase_flags_and_visible_trace(payload_off)
        with patch.dict("os.environ", {"ENABLE_VISIBLE_REASONING_TRACE": "1"}, clear=False):
            commander_mod._attach_phase_flags_and_visible_trace(payload_on)

        self.assertEqual(payload_off["decision"], "HOLD_RISK")
        self.assertEqual(payload_on["decision"], "HOLD_RISK")
        self.assertEqual(payload_off["normalized_decision"], "HOLD_RISK")
        self.assertEqual(payload_on["normalized_decision"], "HOLD_RISK")
        self.assertEqual(payload_off["visible_reasoning_trace"], {"claims": [], "gates_checked": [], "unknowns": []})
        self.assertIsInstance(payload_on["visible_reasoning_trace"], dict)

    def test_commander_fault_injection_trace_builder_never_breaks_payload(self) -> None:
        payload = self._minimal_commander_payload()
        with (
            patch.dict("os.environ", {"ENABLE_VISIBLE_REASONING_TRACE": "1"}, clear=False),
            patch.object(
                commander_mod,
                "_build_commander_visible_reasoning_trace",
                side_effect=RuntimeError("forced_trace_failure"),
            ),
        ):
            commander_mod._attach_phase_flags_and_visible_trace(payload)

        self.assertEqual(payload["decision"], "HOLD_RISK")
        self.assertEqual(payload["normalized_decision"], "HOLD_RISK")
        self.assertEqual(payload["visible_reasoning_trace"], {"claims": [], "gates_checked": [], "unknowns": []})
        self.assertTrue(
            payload.get("llm_provenance", {})
            .get("visible_reasoning_trace", {})
            .get("fallback", False)
        )

    def test_captain_novel_issue_flag_controls_unknown_check_names(self) -> None:
        candidate = {
            "verdict": "WARN",
            "issues": [
                {
                    "check_name": "novel_unknown_check",
                    "severity": "WARN",
                    "message": "Potential anomaly detected.",
                    "hypotheses": ["unknown"],
                    "evidence_refs": ["artifact:data/dq_reports/t_run.json#/rows/novel_unknown_check"],
                    "verification_steps": [
                        "SELECT * FROM step1.vw_valid_orders WHERE run_id = '<run_id>' LIMIT 10;"
                    ],
                }
            ],
            "recommendations": ["review"],
        }
        allowed = {"known_check"}

        normalized_strict, _ = captain_mod._normalize_captain_candidate(
            deepcopy(candidate),
            allowed,
            allow_novel_issues=False,
        )
        self.assertEqual(len(normalized_strict["issues"]), 0)

        normalized_novel, _ = captain_mod._normalize_captain_candidate(
            deepcopy(candidate),
            allowed,
            allow_novel_issues=True,
        )
        self.assertEqual(len(normalized_novel["issues"]), 1)
        captain_mod._validate_issue_check_names(
            normalized_novel,
            allowed,
            allow_novel_issues=True,
        )

    def test_captain_fault_injection_trace_builder_does_not_change_verdict(self) -> None:
        parsed = {"verdict": "PASS", "issues": []}
        eval_metrics = {
            "safety": True,
            "target_warn_fail_count": 1,
            "issue_coverage": 0.2,
            "no_extra_issues": False,
        }
        with patch.object(
            captain_mod,
            "_build_visible_reasoning_trace",
            side_effect=RuntimeError("forced_trace_failure"),
        ):
            trace, meta = build_visible_reasoning_trace_advisory(
                enabled=True,
                trace_builder=lambda: captain_mod._build_visible_reasoning_trace(
                    run_id="t_run",
                    result=parsed,
                    eval_metrics=eval_metrics,
                    enabled=True,
                ),
                trace_prefix="captain:t_run",
                redact_text=captain_mod._redact_text,
            )
        if not eval_metrics["safety"]:
            parsed["verdict"] = "FAIL"
        elif eval_metrics["target_warn_fail_count"] > 0:
            if eval_metrics["issue_coverage"] < 0.6 or not eval_metrics["no_extra_issues"]:
                if parsed["verdict"] == "PASS":
                    parsed["verdict"] = "WARN"
        self.assertEqual(trace, {"claims": [], "gates_checked": [], "unknowns": []})
        self.assertTrue(meta.get("fallback"))
        self.assertEqual(parsed["verdict"], "WARN")

    def test_doctor_dynamic_hypotheses_flag_changes_portfolio(self) -> None:
        metrics = {
            "fill_rate_units": 0.88,
            "gp_margin": 0.12,
            "writeoff_rate_vs_requested_units": 0.08,
            "active_buyers_avg": 1200,
            "aov": 16.5,
            "gmv": 120000.0,
            "oos_lost_gmv_rate": 0.11,
        }
        captain = {
            "result": {
                "issues": [
                    {
                        "check_name": "fill_rate_units_drop",
                        "message": "fill_rate_units and oos_lost_gmv_rate regression observed",
                    }
                ]
            }
        }
        synthetic_bias = {"result": "WARN", "signals": [{"check_name": "writeoff_rate_vs_requested_units", "message": "drift"}]}

        legacy_portfolio = doctor_mod._build_hypothesis_portfolio(
            "t_run",
            metrics,
            captain,
            synthetic_bias,
            dynamic_enabled=False,
        )
        dynamic_portfolio = doctor_mod._build_hypothesis_portfolio(
            "t_run",
            metrics,
            captain,
            synthetic_bias,
            dynamic_enabled=True,
        )

        self.assertGreaterEqual(len(dynamic_portfolio), len(legacy_portfolio))
        self.assertFalse(any(bool(x.get("dynamic_hypothesis")) for x in legacy_portfolio))
        self.assertTrue(any(bool(x.get("dynamic_hypothesis")) for x in dynamic_portfolio))

    def test_doctor_context_rewriter_fallback_to_seed_templates_on_error(self) -> None:
        metrics = {
            "fill_rate_units": 0.91,
            "gp_margin": 0.13,
            "writeoff_rate_vs_requested_units": 0.07,
            "active_buyers_avg": 1300,
            "aov": 17.2,
            "gmv": 128000.0,
            "oos_lost_gmv_rate": 0.09,
        }
        captain = {"result": {"issues": []}}
        synthetic_bias = {"result": "PASS", "signals": []}
        with patch.object(
            doctor_mod,
            "_llm_context_rewriter_hypothesis_portfolio",
            side_effect=RuntimeError("forced_context_rewriter_error"),
        ):
            portfolio, mode, prov = doctor_mod._build_hypothesis_portfolio_with_mode(
                run_id="t_run",
                metrics=metrics,
                captain=captain,
                synthetic_bias=synthetic_bias,
                dynamic_enabled=True,
                backend_name="auto",
                output_schema={},
                model_override=None,
            )
        self.assertEqual(mode, "fallback_seed_templates")
        self.assertTrue(bool(prov.get("used_fallback")))
        self.assertGreaterEqual(len(portfolio), 1)
        self.assertFalse(any(bool(x.get("dynamic_hypothesis")) for x in portfolio))

    def test_doctor_provenance_hypothesis_generation_mode_consistent_with_flag(self) -> None:
        metrics = {
            "fill_rate_units": 0.88,
            "gp_margin": 0.12,
            "writeoff_rate_vs_requested_units": 0.08,
            "active_buyers_avg": 1200,
            "aov": 16.5,
            "gmv": 120000.0,
            "oos_lost_gmv_rate": 0.11,
        }
        captain = {
            "result": {
                "issues": [
                    {
                        "check_name": "fill_rate_units_drop",
                        "message": "fill_rate_units and oos_lost_gmv_rate regression observed",
                    }
                ]
            }
        }
        synthetic_bias = {
            "result": "WARN",
            "signals": [{"check_name": "writeoff_rate_vs_requested_units", "message": "drift"}],
        }

        for dynamic_enabled in (False, True):
            portfolio = doctor_mod._build_hypothesis_portfolio(
                "t_run",
                metrics,
                captain,
                synthetic_bias,
                dynamic_enabled=dynamic_enabled,
            )
            mode = doctor_mod._resolve_hypothesis_generation_mode(
                dynamic_enabled=dynamic_enabled,
                hypothesis_portfolio=portfolio,
            )
            artifact = {
                "hypothesis_generation_mode": mode,
                "llm_provenance": {
                    "feature_flags": {
                        "DOCTOR_DYNAMIC_HYPOTHESES": 1 if dynamic_enabled else 0,
                    },
                    "hypothesis_generation_mode": mode,
                },
            }
            prov = artifact["llm_provenance"]
            self.assertEqual(
                artifact["hypothesis_generation_mode"],
                prov["hypothesis_generation_mode"],
            )
            if bool(prov["feature_flags"]["DOCTOR_DYNAMIC_HYPOTHESES"]):
                self.assertIn(
                    prov["hypothesis_generation_mode"],
                    {"context_rewriter", "fallback_seed_templates"},
                )
            else:
                self.assertEqual(prov["hypothesis_generation_mode"], "seed_templates")

    def test_doctor_fault_injection_trace_builder_does_not_change_decision(self) -> None:
        decision = "HOLD_NEED_DATA"
        reasons = [
            {
                "code": "measurement_blind_spot",
                "severity": "WARN",
                "message": "Assignment log missing.",
                "evidence_refs": ["artifact:data/dq_reports/t_run.json#"],
            }
        ]
        protocol_checks = [{"name": "read_only_tools", "passed": True, "detail": "ok"}]
        with patch.object(
            doctor_mod,
            "_build_doctor_visible_reasoning_trace",
            side_effect=RuntimeError("forced_trace_failure"),
        ):
            trace, meta = build_visible_reasoning_trace_advisory(
                enabled=True,
                trace_builder=lambda: doctor_mod._build_doctor_visible_reasoning_trace(
                    run_id="t_run",
                    decision=decision,
                    reasons=reasons,
                    protocol_checks=protocol_checks,
                    measurement_state="BLOCKED_BY_DATA",
                    ab_status="MISSING_ASSIGNMENT",
                    measurement_fix_plan={"missing_items": ["assignment_log"]},
                    enabled=True,
                ),
                trace_prefix="doctor:t_run",
                redact_text=doctor_mod._redact_text,
            )
        out = {
            "decision": decision,
            "normalized_decision": decision,
            "visible_reasoning_trace": trace,
        }
        self.assertEqual(trace, {"claims": [], "gates_checked": [], "unknowns": []})
        self.assertTrue(meta.get("fallback"))
        self.assertEqual(out["decision"], "HOLD_NEED_DATA")
        self.assertEqual(out["normalized_decision"], "HOLD_NEED_DATA")


if __name__ == "__main__":
    unittest.main()
