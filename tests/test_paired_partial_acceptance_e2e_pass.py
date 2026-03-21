from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from scripts import verify_acceptance as acceptance_mod
from src.architecture_v3 import (
    REQUIRED_GATE_ORDER,
    anti_goodhart_verdict_path,
    context_frame_path,
    ctrl_foundation_audit_path,
    gate_result_path,
    governance_ceiling_path,
    handoff_guard_path,
    historical_conformance_path,
    historical_context_pack_path,
    paired_experiment_context_path,
    quality_invariants_path,
    reasoning_memory_ledger_path,
    reasoning_policy_path,
    save_json_with_sidecar,
    write_gate_result,
)
from src.paired_registry import save_registry
from src.security_utils import RUN_SCOPE_JSON_GLOBS, write_json_manifest, write_sha256_sidecar

ROOT = Path(__file__).resolve().parents[1]


class PairedPartialAcceptanceE2EPassTests(unittest.TestCase):
    @contextmanager
    def _isolated_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            for name in ("src", "configs", "domain_templates"):
                src = ROOT / name
                dst = ws / name
                os.symlink(src, dst, target_is_directory=True)
            scripts_dir = ws / "scripts"
            scripts_dir.mkdir(parents=True, exist_ok=True)
            # Minimal runtime script surface for policy scanners.
            (scripts_dir / "run_all.py").write_text(
                "#!/usr/bin/env python3\nprint('runtime placeholder')\n",
                encoding="utf-8",
            )
            (scripts_dir / "build_batch_consolidated_report.py").write_text(
                "#!/usr/bin/env python3\nprint('consolidated placeholder')\n",
                encoding="utf-8",
            )
            cwd = Path.cwd()
            os.chdir(ws)
            try:
                yield ws
            finally:
                os.chdir(cwd)

    def _write_json(self, path: Path, payload: dict, *, sidecar: bool = True) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if sidecar:
            write_sha256_sidecar(path)

    def _write_md(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _build_run_scope_manifest(self, run_id: str) -> None:
        paths: list[Path] = []
        seen: set[str] = set()
        for glob_tpl in RUN_SCOPE_JSON_GLOBS:
            pattern = str(glob_tpl).format(run_id=run_id)
            for p in Path().glob(pattern):
                if not p.is_file():
                    continue
                key = str(p.resolve())
                if key in seen:
                    continue
                seen.add(key)
                paths.append(p)
        manifest_path = Path(f"reports/L1_ops/{run_id}/artifact_manifest.json")
        write_json_manifest(manifest_path, sorted(paths), run_id=run_id)

    def _write_required_gate_results(self, run_id: str) -> None:
        write_gate_result(run_id, gate_name="captain", status="PASS", error_code="NONE")
        for gate_name in REQUIRED_GATE_ORDER:
            if gate_name in {"acceptance", "pre_publish"}:
                continue
            write_gate_result(run_id, gate_name=gate_name, status="PASS", error_code="NONE")

    def test_paired_partial_acceptance_overall_pass(self) -> None:
        run_id = "ut_paired_partial_e2e_pass"
        ctrl_run_id = f"{run_id}_ctrl"
        experiment_id = "exp_paired_partial_e2e"
        now = datetime.now(timezone.utc).isoformat()

        with self._isolated_workspace():
            # Core reports/artifacts
            ab_path = Path(f"data/ab_reports/{run_id}_{experiment_id}_ab.json")
            self._write_json(
                ab_path,
                {
                    "run_id": run_id,
                    "experiment_id": experiment_id,
                    "status": "OK",
                    "generated_at": now,
                    "summary": {
                        "primary_metric": "aov",
                        "srm_status": "PASS",
                        "primary_metric_uplift": 0.012,
                        "primary_metric_uplift_ci95": [0.001, 0.023],
                    },
                },
            )

            self._write_json(
                Path(f"data/llm_reports/{run_id}_captain.json"),
                {
                    "run_id": run_id,
                    "verdict": "PASS",
                    "model": "deterministic_rule_engine",
                    "llm_provenance": {
                        "remote_allowed": False,
                        "attempted_llm_path": False,
                        "used_fallback": False,
                        "obfuscation_map_refs": [],
                    },
                    "issues": [
                        {
                            "check_name": "dq_schema",
                            "severity": "medium",
                            "message": "coverage dip observed",
                            "hypotheses": ["seasonality"],
                            "verification_steps": ["SELECT 1"],
                            "observed_value": 0.95,
                            "threshold": 0.98,
                            "delta": -0.03,
                            "evidence_refs": ["artifact:data/ab_reports/x.json#"],
                        }
                    ],
                    "recommendations": ["collect_more_data"],
                },
                sidecar=False,
            )

            doctor_portfolio = [
                {"hypothesis_id": "h1", "hypothesis": "AOV lift via assortment", "evidence_refs": ["artifact:data/ab_reports/x.json#"]},
                {"hypothesis_id": "h2", "hypothesis": "Margin pressure via promo", "evidence_refs": ["artifact:data/ab_reports/x.json#"]},
                {"hypothesis_id": "h3", "hypothesis": "Fill-rate sensitivity", "evidence_refs": ["artifact:data/ab_reports/x.json#"]},
            ]
            self._write_json(
                Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
                {
                    "run_id": run_id,
                    "normalized_decision": "HOLD_NEED_DATA",
                    "measurement_state": "OBSERVABLE",
                    "hypothesis_portfolio": doctor_portfolio,
                    "reasons": ["guardrail caution"],
                },
                sidecar=False,
            )

            self._write_json(
                Path(f"data/agent_reports/{run_id}_experiment_evaluator.json"),
                {
                    "run_id": run_id,
                    "experiment_id": experiment_id,
                    "decision": "HOLD_NEED_DATA",
                    "ab_status": "OK",
                    "assignment_status": "ASSIGNED",
                    "blocked_by": [],
                    "reasons": [],
                },
                sidecar=False,
            )

            commander_reviews = [
                {
                    "hypothesis_id": "h1",
                    "deterministic_verdict": "SUPPORTED",
                    "final_verdict": "SUPPORTED",
                    "impact_class": "low",
                    "goal_alignment": "aligned",
                    "cross_goal_reference": None,
                    "evidence_refs": ["artifact:data/ab_reports/x.json#"],
                },
                {
                    "hypothesis_id": "h2",
                    "deterministic_verdict": "WEAK",
                    "final_verdict": "WEAK",
                    "impact_class": "medium",
                    "goal_alignment": "aligned",
                    "cross_goal_reference": None,
                    "evidence_refs": ["artifact:data/ab_reports/x.json#"],
                },
                {
                    "hypothesis_id": "h3",
                    "deterministic_verdict": "UNTESTABLE",
                    "final_verdict": "UNTESTABLE",
                    "impact_class": "low",
                    "goal_alignment": "unknown",
                    "cross_goal_reference": None,
                    "evidence_refs": ["artifact:data/ab_reports/x.json#"],
                },
            ]
            self._write_json(
                Path(f"data/agent_reports/{run_id}_commander_priority.json"),
                {
                    "run_id": run_id,
                    "experiment_id": experiment_id,
                    "decision": "HOLD_NEED_DATA",
                    "normalized_decision": "HOLD_NEED_DATA",
                    "forced_decision_ceiling": "HOLD_NEED_DATA",
                    "blocked_by": ["paired_partial_forced_ceiling:anti_goodhart_missing_ab_artifact"],
                    "doctor_hypothesis_review": commander_reviews,
                    "hypothesis_review_summary": {
                        "total_count": 3,
                        "supported_count": 1,
                        "weak_count": 1,
                        "refuted_count": 0,
                        "untestable_count": 1,
                        "refuted_high_count": 0,
                        "goal_alignment_status": "PASS",
                        "misaligned_hypothesis_count": 0,
                        "verification_quality_score": 0.84,
                    },
                    "mitigation_proposals": [
                        {
                            "title": "Recalibrate promo limits",
                            "applicability": "high",
                            "risk_tradeoff": "slower growth but safer margin",
                            "confidence": 0.7,
                            "evidence_refs": ["artifact:data/ab_reports/x.json#"],
                            "required_data": ["promo elasticity by cohort"],
                        },
                        {
                            "title": "Guardrail stop triggers",
                            "applicability": "high",
                            "risk_tradeoff": "fewer false positives",
                            "confidence": 0.73,
                            "evidence_refs": ["artifact:data/ab_reports/x.json#"],
                            "required_data": ["daily fill-rate monitor"],
                        },
                    ],
                    "llm_provenance": {
                        "remote_allowed": False,
                        "used_fallback": False,
                        "backend_requested": "ollama",
                    },
                },
                sidecar=False,
            )

            self._write_json(
                Path(f"data/agent_reports/{run_id}_narrative_claims.json"),
                {
                    "causal_chains": [
                        {"cause_type": "demand", "evidence_refs": ["a", "b"]},
                        {"cause_type": "pricing", "evidence_refs": ["c", "d"]},
                        {"cause_type": "ops", "evidence_refs": ["e", "f"]},
                    ]
                },
                sidecar=False,
            )
            self._write_json(
                Path(f"reports/L1_ops/{run_id}/causal_claims_validation.json"),
                {"grounded": True, "narrative_status": "GROUNDED", "issues": []},
                sidecar=False,
            )

            self._write_json(Path(f"data/realism_reports/{run_id}_synthetic_bias.json"), {"findings": []}, sidecar=False)
            self._write_json(
                Path(f"data/agent_governance/{run_id}_agent_approvals.json"),
                {
                    "governance_status": "reviewed",
                    "proposal_rows": [
                        {
                            "proposal_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "decision": "APPROVE",
                            "reason_code": "SAFE_HOLD",
                        }
                    ],
                },
                sidecar=False,
            )
            self._write_json(Path(f"data/eval/adversarial_suite_{run_id}.json"), {"scenarios": []}, sidecar=False)
            self._write_json(Path(f"data/agent_reports/{run_id}_vector_quality.json"), {"status": "PASS", "vector_quality_score": 0.9}, sidecar=False)
            self._write_json(
                Path(f"data/agent_quality/{run_id}_pre_publish_audit.json"),
                {"passed": True, "findings": [], "counts": {"critical": 0}},
                sidecar=False,
            )
            self._write_json(
                Path(f"data/runtime_guard/{run_id}_runtime_guard.json"),
                {
                    "run_id": run_id,
                    "status": "PASS",
                    "stages": [
                        {"stage": "integrity", "status": "PASS"},
                        {"stage": "schema", "status": "PASS"},
                        {"stage": "feature_state", "status": "PASS"},
                        {"stage": "payload_memory", "status": "PASS"},
                        {"stage": "loop_dedup", "status": "PASS"},
                        {"stage": "execution", "status": "PASS"},
                    ],
                },
            )

            # KPI ledgers
            outcomes = []
            for i in range(10):
                outcomes.append(
                    {
                        "decision_id": f"d_{i}",
                        "decision": "HOLD_NEED_DATA",
                        "actual_outcome": "safe_hold",
                        "prevented_loss": True,
                        "regret": False,
                    }
                )
            ledger_payload = {
                "version": "decision_outcomes_ledger_v1",
                "run_id": run_id,
                "generated_at": now,
                "ground_truth_source": "labeled_outcomes_warehouse_v1",
                "ground_truth_refs": [f"artifact:{ab_path}#"],
                "label_window_days": 14,
                "sample_size": 10,
                "would_have_prevented_loss_rate": 0.7,
                "decision_regret_rate": 0.1,
                "outcomes": outcomes,
            }
            self._write_json(Path(f"data/agent_eval/{run_id}_decision_outcomes_ledger.json"), ledger_payload)
            self._write_json(
                Path(f"data/agent_eval/{run_id}_offline_kpi_backtest.json"),
                {
                    **ledger_payload,
                    "version": "offline_kpi_backtest_v1",
                },
            )
            self._write_json(
                Path(f"data/agent_eval/{run_id}_agent_value_eval.json"),
                {
                    "system": {
                        "prevented_loss_proxy_rate": 0.65,
                        "unsafe_rollout_block_rate": 0.92,
                        "evidence_coverage_rate": 0.9,
                        "reasoning_layer_status": "PASS",
                        "reasoning_layer_score": 0.86,
                    },
                    "captain": {"score": 0.82},
                    "doctor": {"score": 0.84, "portfolio_diversity_score": 0.66},
                    "commander": {"score": 0.8},
                    "narrative": {
                        "score": 0.81,
                        "evidence_refs_to_actions_rate": 0.8,
                        "evidence_pattern_uniqueness_rate": 0.7,
                        "causal_chains": [1, 2, 3],
                    },
                    "reasoning_checks": {
                        "status": "PASS",
                        "mode": "standard",
                        "trace_completeness_rate": 0.85,
                        "alternative_hypothesis_quality": 0.8,
                        "falsifiability_specificity": 0.82,
                        "decision_change_sensitivity": 0.77,
                    },
                },
                sidecar=False,
            )

            # Governance context artifacts
            save_json_with_sidecar(
                context_frame_path(run_id),
                {
                    "version": "context_frame_v1",
                    "run_id": run_id,
                    "status": "PASS",
                    "current_ab": {"experiment_id": experiment_id},
                    "next_experiment": {"experiment_id": f"{experiment_id}_next"},
                },
            )
            save_json_with_sidecar(
                handoff_guard_path(run_id),
                {"version": "handoff_contract_guard_v1", "run_id": run_id, "status": "PASS"},
            )
            save_json_with_sidecar(
                historical_context_pack_path(run_id),
                {
                    "version": "historical_context_pack_v1",
                    "run_id": run_id,
                    "status": "PASS",
                    "retrieval_mode": "semantic_hybrid_mvp",
                    "query_ref": "artifact:data/agent_reports/query.json#",
                    "embedding_model": "token_jaccard_v1_mvp",
                    "top_k": 3,
                    "rows": [{"experiment_id": "h1", "similarity": 0.7}],
                    "fact_refs": ["artifact:data/ab_reports/fact.json#"],
                    "evidence_hashes": [{"artifact_ref": "artifact:data/ab_reports/fact.json#", "sha256": "deadbeef"}],
                },
            )
            save_json_with_sidecar(
                reasoning_memory_ledger_path(run_id),
                {"version": "reasoning_memory_ledger_v1", "run_id": run_id, "entries": [{"id": "e1"}]},
            )
            save_json_with_sidecar(
                historical_conformance_path(run_id),
                {"version": "historical_retrieval_conformance_v1", "run_id": run_id, "status": "PASS"},
            )
            save_json_with_sidecar(
                anti_goodhart_verdict_path(run_id),
                {
                    "version": "anti_goodhart_verdict_v1",
                    "run_id": run_id,
                    "status": "FAIL",
                    "error_code": "AB_ARTIFACT_REQUIRED",
                    "source_of_truth": "anti_goodhart_verdict_v1",
                    "anti_goodhart_triggered": True,
                    "occurred_at": now,
                },
            )
            save_json_with_sidecar(
                quality_invariants_path(run_id),
                {"version": "quality_invariants_v1", "run_id": run_id, "status": "PASS"},
            )
            save_json_with_sidecar(
                reasoning_policy_path(run_id),
                {
                    "version": "reasoning_score_policy_v2",
                    "run_id": run_id,
                    "status": "PASS",
                    "effective_real_llm_agents_count": 1,
                    "decision_ceiling": "HOLD_NEED_DATA",
                },
            )
            save_json_with_sidecar(
                governance_ceiling_path(run_id),
                {"version": "governance_ceiling_v1", "run_id": run_id, "status": "PASS"},
            )

            # Paired registry/context + ctrl audit
            ctrl_audit = ctrl_foundation_audit_path(ctrl_run_id)
            save_json_with_sidecar(
                ctrl_audit,
                {
                    "version": "ctrl_foundation_audit_v1",
                    "run_id": ctrl_run_id,
                    "status": "PASS",
                    "error_code": "NONE",
                    "executed_steps": [
                        "run_simulation",
                        "run_dq",
                        "make_metrics_snapshot_v1",
                        "run_ab_preflight",
                        "run_ab_analysis",
                    ],
                },
            )
            paired_context = paired_experiment_context_path(run_id)
            save_json_with_sidecar(
                paired_context,
                {
                    "version": "paired_experiment_v2",
                    "run_id": run_id,
                    "experiment_id": experiment_id,
                    "ctrl_run_id": ctrl_run_id,
                    "treatment_run_id": run_id,
                    "paired_status": "PARTIAL",
                    "partial_reason": "anti_goodhart_missing_ab_artifact",
                    "failed_step": "anti_goodhart_sot",
                    "decision_ceiling": "HOLD_NEED_DATA",
                    "generated_at": now,
                },
            )
            save_registry(
                {
                    "version": "paired_registry_v1",
                    "mode": "paired",
                    "experiment_id": experiment_id,
                    "parent_run_id": run_id,
                    "ctrl_run_id": ctrl_run_id,
                    "treatment_run_id": run_id,
                    "paired_status": "PARTIAL",
                    "error_code": "AB_ARTIFACT_REQUIRED",
                    "reason": "anti_goodhart_missing_ab_artifact",
                    "paired_context_ref": f"artifact:{paired_context}",
                    "audit_ref": f"artifact:{ctrl_audit}",
                    "status_history": [
                        {
                            "from": "COMPLETE",
                            "to": "PARTIAL",
                            "reason": "anti_goodhart_missing_ab_artifact",
                            "changed_at": now,
                        }
                    ],
                }
            )

            # Gate outputs
            self._write_required_gate_results(run_id)
            # Add meaningful details for experiment_duration gate used by dedicated check.
            duration_gate = gate_result_path(run_id, "experiment_duration_gate")
            duration_payload = json.loads(duration_gate.read_text(encoding="utf-8"))
            duration_payload["details"] = {"days_covered": 14, "min_experiment_days": 14}
            self._write_json(duration_gate, duration_payload, sidecar=True)

            # Required markdown outputs
            self._write_md(Path(f"reports/L1_ops/{run_id}/AGENT_VALUE_SCORECARD.md"), "# scorecard\n")
            self._write_md(Path(f"reports/L1_ops/{run_id}/DEMO_INDEX.md"), "# demo\n")
            self._write_md(Path(f"reports/L1_ops/{run_id}/CAUSAL_EXPLANATION.md"), "# causal\n")
            # Write decision card after AB report for freshness check.
            self._write_md(Path(f"reports/L1_ops/{run_id}/decision_card.md"), "# decision card\n")

            # Manifest for publish integrity checks.
            self._build_run_scope_manifest(run_id)

            with mock.patch.object(sys, "argv", ["verify_acceptance.py", "--run-id", run_id, "--experiment-id", experiment_id]):
                acceptance_mod.main()

            acceptance_json = Path(f"data/acceptance/{run_id}_acceptance.json")
            self.assertTrue(acceptance_json.exists())
            payload = json.loads(acceptance_json.read_text(encoding="utf-8"))
            self.assertEqual(payload.get("overall_status"), "PASS")
            self.assertEqual(int((payload.get("counts", {}) or {}).get("critical_fail", -1)), 0)

            checks = payload.get("checks", {})
            self.assertEqual(checks.get("paired_partial_anti_goodhart_expected_outcome", {}).get("status"), "PASS")
            self.assertEqual(checks.get("paired_partial_ceiling_enforced", {}).get("status"), "PASS")
            self.assertEqual(checks.get("paired_status_lifecycle_valid", {}).get("status"), "PASS")
            self.assertEqual(checks.get("v3_gate_order", {}).get("status"), "PASS")
            self.assertEqual(checks.get("artifact_manifest_scope", {}).get("status"), "PASS")


if __name__ == "__main__":
    unittest.main()
