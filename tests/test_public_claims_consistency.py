from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_public_claims_consistency.py"
PRD_PATH = Path(__file__).resolve().parents[1] / "PRD.md"


def _write_sha256(path: Path) -> None:
    import hashlib

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_suffix(path.suffix + ".sha256").write_text(digest + "\n", encoding="utf-8")


class TestPublicClaimsConsistency(unittest.TestCase):
    def _write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _write_json_with_sidecar(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        _write_sha256(path)

    def test_as_of_mismatch_code_present_in_taxonomy(self) -> None:
        taxonomy_path = Path(__file__).resolve().parents[1] / "configs" / "contracts" / "error_taxonomy_v1.json"
        taxonomy = json.loads(taxonomy_path.read_text(encoding="utf-8"))
        codes = taxonomy.get("codes") if isinstance(taxonomy.get("codes"), list) else []
        normalized = {str(x).strip().upper() for x in codes if str(x).strip()}
        self.assertIn("PUBLIC_CLAIM_AS_OF_DATE_MISMATCH", normalized)

    def _mass_summary(self) -> dict:
        def _row(*, expected_block: bool, predicted_block: bool, decision: str) -> dict:
            return {
                "expected_block": expected_block,
                "predicted_block": predicted_block,
                "decision": decision,
                "methodology_state": "OBSERVABLE",
                "ab_status": "PASS",
                "blocked_by": ([] if decision == "GO" else ["RISK_BLOCK"]),
                "guardrail_breach_count": (1 if decision in {"STOP_ROLLOUT", "STOP"} else 0),
                "safe_case_block_evidence_issues": [],
                "counterfactual_go_check": {"status": "checked_for_non_go", "evidence_present": True, "note": ""},
            }

        return {
            "batch_id": "mass_test_003",
            "benchmark_origin": "fresh_runtime",
            "generated_by": "scripts/run_batch_eval.py",
            "legacy_upgraded": False,
            "records_quality_complete": True,
            "generated_at": "2026-03-10T12:00:00Z",
            "risky_cases": 10,
            "safe_cases": 10,
            "records": [_row(expected_block=True, predicted_block=False, decision="GO")]
            + [_row(expected_block=True, predicted_block=True, decision="HOLD_NEED_DATA")] * 9
            + [_row(expected_block=False, predicted_block=True, decision="HOLD_NEED_DATA")] * 4
            + [_row(expected_block=False, predicted_block=False, decision="GO")] * 6,
        }

    def _investor_summary(self) -> dict:
        return {
            "batch_id": "investor_demo_batch_v2",
            "generated_at": "2026-03-20T12:00:00Z",
            "risky_cases": 2,
            "safe_cases": 1,
            "records": [
                {"expected_block": True, "predicted_block": True, "decision": "HOLD_NEED_DATA"},
                {"expected_block": True, "predicted_block": True, "decision": "STOP_ROLLOUT"},
                {"expected_block": False, "predicted_block": False, "decision": "GO"},
            ],
        }

    def _adversarial_summary(self) -> dict:
        return {
            "generated_at": "2026-02-27T12:00:00Z",
            "scenarios": [
                {"scenario": "a", "status": "PASS"},
                {"scenario": "b", "status": "PASS"},
                {"scenario": "c", "status": "PASS"},
                {"scenario": "d", "status": "PASS"},
                {"scenario": "e", "status": "WARN"},
            ],
            "summary": {"fail_count": 0, "warn_count": 1, "status": "WARN"},
        }

    def _make_prd_sot(self, root: Path, mass_path: Path, investor_path: Path, adv_path: Path) -> Path:
        prd_sot = root / "prd_sot_v1.json"
        payload = {
            "version": "prd_sot_v1",
            "as_of_date": "2026-04-06",
            "benchmark_registry": [
                {
                    "benchmark_id": "mass_test_003",
                    "type": "mass",
                    "source_summary": str(mass_path),
                    "n_total": 20,
                    "n_safe": 10,
                    "n_risky": 10,
                },
                {
                    "benchmark_id": "investor_demo_batch_v2",
                    "type": "curated",
                    "source_summary": str(investor_path),
                    "n_total": 3,
                    "n_safe": 1,
                    "n_risky": 2,
                },
                {
                    "benchmark_id": "adversarial_suite_v1",
                    "type": "adversarial",
                    "source_summary": str(adv_path),
                    "n_total": 5,
                    "n_safe": 0,
                    "n_risky": 5,
                },
            ],
            "capability_status_registry": {
                "capabilities": [{"capability_id": "paired_experiment_mode", "status": "IMPLEMENTED"}]
            },
            "public_claim_policy": {"required_claim_fields": ["metric", "x_over_y", "benchmark_id", "as_of_date"]},
        }
        prd_sot.write_text(json.dumps(payload), encoding="utf-8")
        _write_sha256(prd_sot)
        return prd_sot

    def _run(
        self,
        *,
        prd_sot: Path,
        readme: Path,
        agent_eval: Path,
        evaluation_report: Path,
        scorecard: Path,
        strict_eval: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--prd",
                str(PRD_PATH),
                "--prd-sot",
                str(prd_sot),
                "--readme",
                str(readme),
                "--agent-eval",
                str(agent_eval),
                "--evaluation-report",
                str(evaluation_report),
                "--scorecard",
                str(scorecard),
                "--strict-evaluation-report",
                str(strict_eval),
            ],
            capture_output=True,
            text=True,
        )

    def _run_batch_override(
        self,
        *,
        batch_summary: Path,
        readme: Path,
        agent_eval: Path,
        evaluation_report: Path,
        scorecard: Path,
        strict_eval: int,
        prd: Path | None = None,
        policy: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [
            "python3",
            str(SCRIPT),
            "--batch-summary",
            str(batch_summary),
            "--readme",
            str(readme),
            "--agent-eval",
            str(agent_eval),
            "--evaluation-report",
            str(evaluation_report),
            "--scorecard",
            str(scorecard),
            "--strict-evaluation-report",
            str(strict_eval),
        ]
        if prd is not None:
            cmd.extend(["--prd", str(prd)])
        if policy is not None:
            cmd.extend(["--policy", str(policy)])
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

    def _write_docs(
        self,
        root: Path,
        *,
        include_adversarial_fpr: bool = True,
        broken_mass_ratio: bool = False,
        adversarial_as_of_date: str = "2026-02-27",
    ) -> tuple[Path, Path, Path, Path]:
        readme = root / "README.md"
        agent_eval = root / "AGENT_EVAL.md"
        evaluation_report = root / "EVALUATION_REPORT.md"
        scorecard = root / "executive_roi_scorecard.md"

        mass_fnr = "FNR risky approved = 10% (1/10), benchmark_id=mass_test_003, as_of_date=2026-03-10"
        mass_fpr = "FPR safe blocked = 40% (4/10), benchmark_id=mass_test_003, as_of_date=2026-03-10"
        if broken_mass_ratio:
            mass_fpr = "FPR safe blocked = 40% (5/10), benchmark_id=mass_test_003, as_of_date=2026-03-10"

        investor_fnr = "FNR risky approved = 0% (0/2), benchmark_id=investor_demo_batch_v2, as_of_date=2026-03-20"
        investor_fpr = "FPR safe blocked = 0% (0/1), benchmark_id=investor_demo_batch_v2, as_of_date=2026-03-20"
        adv_fnr = (
            f"FNR risky approved = 0% (0/5), benchmark_id=adversarial_suite_v1, "
            f"as_of_date={adversarial_as_of_date}"
        )
        adv_fpr = (
            f"FPR safe blocked = N/A, benchmark_id=adversarial_suite_v1, "
            f"as_of_date={adversarial_as_of_date}"
        )

        lines = [mass_fnr, mass_fpr, investor_fnr, investor_fpr, adv_fnr]
        if include_adversarial_fpr:
            lines.append(adv_fpr)

        self._write(readme, "\n".join(lines))
        self._write(
            agent_eval,
            "\n".join(
                [
                    "False Negative Rate: risky experiment approved when it should have been blocked.",
                    "False Positive Rate: safe experiment blocked when it should have been approved.",
                    *lines,
                ]
            ),
        )
        self._write(evaluation_report, "\n".join(lines))
        self._write(
            scorecard,
            "\n".join([investor_fnr, investor_fpr]),
        )
        return readme, agent_eval, evaluation_report, scorecard

    def test_multi_benchmark_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mass = root / "mass.json"
            investor = root / "investor.json"
            adv = root / "adv.json"
            self._write_json_with_sidecar(mass, self._mass_summary())
            self._write_json_with_sidecar(investor, self._investor_summary())
            self._write_json_with_sidecar(adv, self._adversarial_summary())

            prd_sot = self._make_prd_sot(root, mass, investor, adv)
            readme, agent_eval, evaluation_report, scorecard = self._write_docs(root)

            proc = self._run(
                prd_sot=prd_sot,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=evaluation_report,
                scorecard=scorecard,
                strict_eval=1,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("claim_consistency=PASS", proc.stdout)

    def test_mixed_markdown_row_parses_fnr_and_fpr_without_ratio_cross_talk(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            batch = root / "mass_test_003_summary.json"
            self._write_json_with_sidecar(batch, self._mass_summary())

            mixed_claims = "\n".join(
                [
                    "| benchmark | claims |",
                    "|---|---|",
                    "| mass_test_003 | FNR risky approved = 10% (1/10); FPR safe blocked = 40% (4/10), benchmark_id=mass_test_003, as_of_date=2026-03-10 |",
                ]
            )
            readme = root / "README.md"
            agent_eval = root / "AGENT_EVAL.md"
            evaluation_report = root / "EVALUATION_REPORT.md"
            scorecard = root / "executive_roi_scorecard.md"
            self._write(readme, mixed_claims)
            self._write(agent_eval, mixed_claims)
            self._write(evaluation_report, mixed_claims)
            self._write(scorecard, mixed_claims)

            proc = self._run_batch_override(
                batch_summary=batch,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=evaluation_report,
                scorecard=scorecard,
                strict_eval=1,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("claim_consistency=PASS", proc.stdout)
            self.assertNotIn("PUBLIC_CLAIM_RATIO_MISMATCH", proc.stdout)

    def test_multi_benchmark_coverage_fail(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mass = root / "mass.json"
            investor = root / "investor.json"
            adv = root / "adv.json"
            self._write_json_with_sidecar(mass, self._mass_summary())
            self._write_json_with_sidecar(investor, self._investor_summary())
            self._write_json_with_sidecar(adv, self._adversarial_summary())

            prd_sot = self._make_prd_sot(root, mass, investor, adv)
            readme, agent_eval, evaluation_report, scorecard = self._write_docs(root, include_adversarial_fpr=False)

            proc = self._run(
                prd_sot=prd_sot,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=evaluation_report,
                scorecard=scorecard,
                strict_eval=1,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("PUBLIC_CLAIM_COVERAGE_INCOMPLETE", proc.stdout)

    def test_strict_missing_evaluation_report_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mass = root / "mass.json"
            investor = root / "investor.json"
            adv = root / "adv.json"
            self._write_json_with_sidecar(mass, self._mass_summary())
            self._write_json_with_sidecar(investor, self._investor_summary())
            self._write_json_with_sidecar(adv, self._adversarial_summary())

            prd_sot = self._make_prd_sot(root, mass, investor, adv)
            readme, agent_eval, _, scorecard = self._write_docs(root)
            missing_eval = root / "MISSING_EVALUATION_REPORT.md"

            proc = self._run(
                prd_sot=prd_sot,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=missing_eval,
                scorecard=scorecard,
                strict_eval=1,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("PUBLIC_CLAIM_SOURCE_MISSING:evaluation_report", proc.stdout)

    def test_per_benchmark_ratio_mismatch_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mass = root / "mass.json"
            investor = root / "investor.json"
            adv = root / "adv.json"
            self._write_json_with_sidecar(mass, self._mass_summary())
            self._write_json_with_sidecar(investor, self._investor_summary())
            self._write_json_with_sidecar(adv, self._adversarial_summary())

            prd_sot = self._make_prd_sot(root, mass, investor, adv)
            readme, agent_eval, evaluation_report, scorecard = self._write_docs(root, broken_mass_ratio=True)

            proc = self._run(
                prd_sot=prd_sot,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=evaluation_report,
                scorecard=scorecard,
                strict_eval=1,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("PUBLIC_CLAIM_RATIO_MISMATCH", proc.stdout)

    def test_as_of_date_mismatch_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mass = root / "mass.json"
            investor = root / "investor.json"
            adv = root / "adv.json"
            self._write_json_with_sidecar(mass, self._mass_summary())
            self._write_json_with_sidecar(investor, self._investor_summary())
            self._write_json_with_sidecar(adv, self._adversarial_summary())

            prd_sot = self._make_prd_sot(root, mass, investor, adv)
            readme, agent_eval, evaluation_report, scorecard = self._write_docs(
                root, adversarial_as_of_date="2026-02-26"
            )

            proc = self._run(
                prd_sot=prd_sot,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=evaluation_report,
                scorecard=scorecard,
                strict_eval=1,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("PUBLIC_CLAIM_AS_OF_DATE_MISMATCH", proc.stdout)

    def test_batch_override_requires_freshness_and_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            batch = root / "batch_summary.json"
            payload = self._mass_summary()
            payload["legacy_upgraded"] = True
            payload["records_quality_complete"] = False
            batch.write_text(json.dumps(payload), encoding="utf-8")
            _write_sha256(batch)

            readme, agent_eval, evaluation_report, scorecard = self._write_docs(root)
            proc = self._run_batch_override(
                batch_summary=batch,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=evaluation_report,
                scorecard=scorecard,
                strict_eval=1,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("PUBLIC_CLAIM_SOURCE_NOT_FRESH_RUNTIME", proc.stdout)
            self.assertNotIn("PUBLIC_CLAIM_SOURCE_MISSING:expected_benchmarks_empty", proc.stdout)

    def test_batch_override_allows_other_benchmark_claims_in_scorecard(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            batch = root / "mass_test_003_summary.json"
            self._write_json_with_sidecar(batch, self._mass_summary())
            readme, agent_eval, evaluation_report, scorecard = self._write_docs(root)

            proc = self._run_batch_override(
                batch_summary=batch,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=evaluation_report,
                scorecard=scorecard,
                strict_eval=1,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("claim_consistency=PASS", proc.stdout)

    def test_batch_override_does_not_require_prd_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            batch = root / "mass_test_003_summary.json"
            self._write_json_with_sidecar(batch, self._mass_summary())
            readme, agent_eval, evaluation_report, scorecard = self._write_docs(root)
            missing_prd = root / "MISSING_PRD.md"

            proc = self._run_batch_override(
                batch_summary=batch,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=evaluation_report,
                scorecard=scorecard,
                strict_eval=1,
                prd=missing_prd,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("claim_consistency=PASS", proc.stdout)

    def test_batch_override_uses_builtin_strict_policy_when_policy_file_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            batch = root / "mass_test_003_summary.json"
            self._write_json_with_sidecar(batch, self._mass_summary())
            readme, agent_eval, evaluation_report, scorecard = self._write_docs(root)
            missing_policy = root / "MISSING_POLICY.json"

            proc = self._run_batch_override(
                batch_summary=batch,
                readme=readme,
                agent_eval=agent_eval,
                evaluation_report=evaluation_report,
                scorecard=scorecard,
                strict_eval=1,
                policy=missing_policy,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("policy_source=builtin_strict:policy_missing", proc.stdout)
            self.assertIn("claim_consistency=PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
