from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_public_claims_consistency.py"


class TestPublicClaimsConsistency(unittest.TestCase):
    def _write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _run(self, summary: Path, readme: Path, agent_eval: Path, eval_report: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--batch-summary",
                str(summary),
                "--readme",
                str(readme),
                "--agent-eval",
                str(agent_eval),
                "--evaluation-report",
                str(eval_report),
            ],
            capture_output=True,
            text=True,
        )

    def _base_summary(self) -> dict:
        return {
            "risky_cases": 10,
            "safe_cases": 10,
            "records": [
                {"expected_block": True, "predicted_block": False},  # FN=1
                {"expected_block": False, "predicted_block": True},  # FP=1
            ]
            + [{"expected_block": True, "predicted_block": True}] * 9
            + [{"expected_block": False, "predicted_block": False}] * 9,
        }

    def _canonical_agent_eval(self) -> str:
        return "\n".join(
            [
                "False Negative Rate: risky experiment approved when it should have been blocked.",
                "False Positive Rate: safe experiment blocked when it should have been approved.",
            ]
        )

    def test_pass_with_generic_batch_label(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary = root / "batch_summary.json"
            readme = root / "README.md"
            agent_eval = root / "AGENT_EVAL.md"
            eval_report = root / "EVALUATION_REPORT.md"
            summary.write_text(json.dumps(self._base_summary()), encoding="utf-8")
            self._write(
                readme,
                "\n".join(
                    [
                        "| FNR — risky approved (investor_demo_batch_v2) | **10%** | 1/10 risky experiments approved |",
                        "| FPR — safe blocked (investor_demo_batch_v2) | **10%** | 1/10 safe cases blocked |",
                    ]
                ),
            )
            self._write(agent_eval, self._canonical_agent_eval())
            self._write(
                eval_report,
                "\n".join(
                    [
                        "| FNR — risky approved (investor_demo_batch_v2) | **10%** | 1/10 risky experiments approved |",
                        "| FPR — safe blocked (investor_demo_batch_v2) | **10%** | 1/10 safe cases blocked |",
                    ]
                ),
            )

            proc = self._run(summary, readme, agent_eval, eval_report)
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("claim_consistency=PASS", proc.stdout)

    def test_missing_evaluation_report_is_skip_not_fail(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary = root / "batch_summary.json"
            readme = root / "README.md"
            agent_eval = root / "AGENT_EVAL.md"
            missing_report = root / "MISSING_EVALUATION_REPORT.md"
            summary.write_text(json.dumps(self._base_summary()), encoding="utf-8")
            self._write(
                readme,
                "\n".join(
                    [
                        "| FNR — risky approved (batch_label_any) | **10%** | 1/10 risky experiments approved |",
                        "| FPR — safe blocked (batch_label_any) | **10%** | 1/10 safe cases blocked |",
                    ]
                ),
            )
            self._write(agent_eval, self._canonical_agent_eval())

            proc = self._run(summary, readme, agent_eval, missing_report)
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("evaluation_report=SKIP source_missing:", proc.stdout)
            self.assertIn("claim_consistency=PASS", proc.stdout)

    def test_fail_on_readme_denominator_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary = root / "batch_summary.json"
            readme = root / "README.md"
            agent_eval = root / "AGENT_EVAL.md"
            eval_report = root / "EVALUATION_REPORT.md"
            summary.write_text(json.dumps(self._base_summary()), encoding="utf-8")
            self._write(
                readme,
                "\n".join(
                    [
                        "| FNR — risky approved (batch_label_any) | **10%** | 1/9 risky experiments approved |",
                        "| FPR — safe blocked (batch_label_any) | **10%** | 1/10 safe cases blocked |",
                    ]
                ),
            )
            self._write(agent_eval, self._canonical_agent_eval())
            self._write(
                eval_report,
                "\n".join(
                    [
                        "| FNR — risky approved (batch_label_any) | **10%** | 1/10 risky experiments approved |",
                        "| FPR — safe blocked (batch_label_any) | **10%** | 1/10 safe cases blocked |",
                    ]
                ),
            )

            proc = self._run(summary, readme, agent_eval, eval_report)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("ratio_mismatch:readme:fnr", proc.stdout)

    def test_fail_on_inverted_agent_eval_definitions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary = root / "batch_summary.json"
            readme = root / "README.md"
            agent_eval = root / "AGENT_EVAL.md"
            eval_report = root / "EVALUATION_REPORT.md"
            summary.write_text(json.dumps(self._base_summary()), encoding="utf-8")
            self._write(
                readme,
                "\n".join(
                    [
                        "| FNR — risky approved (batch_label_any) | **10%** | 1/10 risky experiments approved |",
                        "| FPR — safe blocked (batch_label_any) | **10%** | 1/10 safe cases blocked |",
                    ]
                ),
            )
            self._write(
                agent_eval,
                "\n".join(
                    [
                        "False Positive Rate: aggressive decision when risk was present.",
                        "False Negative Rate: HOLD decision when rollout was actually safe.",
                    ]
                ),
            )
            self._write(
                eval_report,
                "\n".join(
                    [
                        "| FNR — risky approved (batch_label_any) | **10%** | 1/10 risky experiments approved |",
                        "| FPR — safe blocked (batch_label_any) | **10%** | 1/10 safe cases blocked |",
                    ]
                ),
            )

            proc = self._run(summary, readme, agent_eval, eval_report)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("definition_inverted:agent_eval", proc.stdout)


if __name__ == "__main__":
    unittest.main()
