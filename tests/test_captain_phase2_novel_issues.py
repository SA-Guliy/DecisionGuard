#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_captain_sanity_llm as captain_mod
from src.semantic_scoring import captain_semantic_score, drop_unproven_novel_issues


class CaptainPhase2NovelIssueTests(unittest.TestCase):
    def test_novel_issue_without_evidence_is_dropped(self) -> None:
        candidate = {
            "verdict": "WARN",
            "issues": [
                {
                    "check_name": "new_unseen_check",
                    "severity": "WARN",
                    "message": "New anomaly",
                    "hypotheses": ["unknown"],
                    "verification_steps": [
                        "SELECT * FROM step1.vw_valid_orders WHERE run_id = '<run_id>' LIMIT 10;",
                    ],
                }
            ],
            "recommendations": ["review"],
        }
        normalized, _ = captain_mod._normalize_captain_candidate(
            deepcopy(candidate),
            allowed_check_names={"known_check"},
            allow_novel_issues=True,
        )
        self.assertEqual(len(normalized["issues"]), 0)

    def test_novel_issue_with_mutating_sql_is_dropped(self) -> None:
        candidate = {
            "verdict": "WARN",
            "issues": [
                {
                    "check_name": "new_unseen_check",
                    "severity": "WARN",
                    "message": "New anomaly",
                    "hypotheses": ["unknown"],
                    "evidence_refs": ["artifact:data/dq_reports/t_run.json#/rows"],
                    "verification_steps": [
                        "UPDATE step1.step1_orders SET qty=0 WHERE run_id = '<run_id>';",
                    ],
                }
            ],
            "recommendations": ["review"],
        }
        normalized, _ = captain_mod._normalize_captain_candidate(
            deepcopy(candidate),
            allowed_check_names={"known_check"},
            allow_novel_issues=True,
        )
        self.assertEqual(len(normalized["issues"]), 0)

    def test_novel_issue_normalized_to_novel_slug(self) -> None:
        candidate = {
            "verdict": "WARN",
            "issues": [
                {
                    "check_name": "Unknown Drift Check",
                    "severity": "WARN",
                    "message": "Drift detected in edge segment",
                    "hypotheses": ["unknown"],
                    "evidence_refs": ["artifact:data/dq_reports/t_run.json#/rows"],
                    "verification_steps": [
                        "SELECT * FROM step1.vw_valid_orders WHERE run_id = '<run_id>' LIMIT 20;",
                    ],
                }
            ],
            "recommendations": ["review"],
        }
        normalized, _ = captain_mod._normalize_captain_candidate(
            deepcopy(candidate),
            allowed_check_names={"known_check"},
            allow_novel_issues=True,
        )
        self.assertEqual(len(normalized["issues"]), 1)
        check_name = normalized["issues"][0]["check_name"]
        self.assertTrue(check_name.startswith("novel::"))
        captain_mod._validate_issue_check_names(
            normalized,
            {"known_check"},
            allow_novel_issues=True,
        )
        captain_mod._validate_verification_steps(normalized)

    def test_semantic_scoring_drops_and_penalizes_unproven_novel(self) -> None:
        dq_report = {"rows": [{"check_name": "known_check", "message": "Known"}]}
        result = {
            "issues": [
                {
                    "check_name": "novel::drift_x",
                    "message": "Unproven issue",
                    "hypotheses": ["because unknown"],
                    "verification_steps": ["SELECT * FROM step1.vw_valid_orders LIMIT 5;"],
                    "evidence_refs": [],
                },
                {
                    "check_name": "known_check",
                    "message": "Known issue",
                    "hypotheses": ["because of known drift"],
                    "verification_steps": ["SELECT * FROM step1.vw_valid_orders LIMIT 5;"],
                    "evidence_refs": [],
                },
            ]
        }
        filtered, dropped = drop_unproven_novel_issues(result)
        self.assertEqual(dropped, 1)
        self.assertEqual(len(filtered.get("issues", [])), 1)
        score, breakdown = captain_semantic_score(dq_report, result)
        self.assertLessEqual(score, 0.3)
        self.assertEqual(int(breakdown.get("dropped_unproven_novel_issues", 0)), 1)

    def test_pipeline_order_penalty_persists_after_pre_drop(self) -> None:
        dq_report = {
            "rows": [
                {
                    "check_name": "known_check",
                    "status": "WARN",
                    "message": "Known issue in fill_rate_units",
                }
            ]
        }
        raw_result = {
            "verdict": "WARN",
            "issues": [
                {
                    "check_name": "known_check",
                    "severity": "WARN",
                    "message": "Known issue in fill_rate_units detected",
                    "hypotheses": ["because known issue"],
                    "verification_steps": ["SELECT * FROM step1.vw_valid_orders LIMIT 5;"],
                    "evidence_refs": [],
                },
                {
                    "check_name": "novel::drift_segment",
                    "severity": "WARN",
                    "message": "Novel drift without proof",
                    "hypotheses": ["because unknown"],
                    "verification_steps": ["SELECT * FROM step1.vw_valid_orders LIMIT 5;"],
                    "evidence_refs": [],
                },
            ],
            "recommendations": [],
        }
        persisted_result, dropped = drop_unproven_novel_issues(raw_result)
        self.assertEqual(dropped, 1)

        score_without_pipeline_penalty, _ = captain_semantic_score(dq_report, persisted_result)
        metrics = captain_mod._compute_eval_metrics(
            dq_report,
            persisted_result,
            allow_novel_issues=True,
            dropped_unproven_novel=dropped,
        )
        score_with_pipeline_penalty = float(metrics["semantic_score"])
        breakdown = metrics["semantic_breakdown"]

        self.assertLess(score_with_pipeline_penalty, score_without_pipeline_penalty)
        self.assertEqual(int(breakdown.get("dropped_unproven_novel_issues", 0)), 1)


if __name__ == "__main__":
    unittest.main()
