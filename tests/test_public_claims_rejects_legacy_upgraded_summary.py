from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_public_claims_consistency.py"


def _sha(path: Path) -> None:
    import hashlib

    path.with_suffix(path.suffix + ".sha256").write_text(hashlib.sha256(path.read_bytes()).hexdigest() + "\n", encoding="utf-8")


class PublicClaimsRejectLegacyUpgradedSummaryTests(unittest.TestCase):
    def test_checker_rejects_legacy_mass_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            mass = tmp / "mass.json"
            investor = tmp / "investor.json"
            adv = tmp / "adv.json"
            mass.write_text(
                json.dumps(
                    {
                        "batch_id": "mass_test_003",
                        "generated_at": "2026-03-10T12:00:00Z",
                        "benchmark_origin": "legacy_upgrade",
                        "generated_by": "legacy/migrate_summary.py",
                        "legacy_upgraded": True,
                        "records_quality_complete": False,
                        "risky_cases": 10,
                        "safe_cases": 10,
                        "records": [{"expected_block": False, "predicted_block": False, "decision": "GO"}] * 10,
                    }
                ),
                encoding="utf-8",
            )
            investor.write_text(json.dumps({"batch_id": "investor_demo_batch_v2", "generated_at": "2026-03-20T00:00:00Z", "records": []}), encoding="utf-8")
            adv.write_text(json.dumps({"generated_at": "2026-02-27T00:00:00Z", "scenarios": [], "summary": {"fail_count": 0}}), encoding="utf-8")
            _sha(mass)
            _sha(investor)
            _sha(adv)

            sot = tmp / "prd_sot_v1.json"
            sot.write_text(
                json.dumps(
                    {
                        "version": "prd_sot_v1",
                        "as_of_date": "2026-04-06",
                        "benchmark_registry": [
                            {"benchmark_id": "mass_test_003", "source_summary": str(mass), "n_risky": 10, "n_safe": 10},
                            {"benchmark_id": "investor_demo_batch_v2", "source_summary": str(investor), "n_risky": 0, "n_safe": 0},
                            {"benchmark_id": "adversarial_suite_v1", "source_summary": str(adv), "n_risky": 0, "n_safe": 0},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            _sha(sot)

            readme = tmp / "README.md"
            agent_eval = tmp / "AGENT_EVAL.md"
            report = tmp / "EVALUATION_REPORT.md"
            scorecard = tmp / "executive_roi_scorecard.md"
            line = "FNR risky approved = 0% (0/10), benchmark_id=mass_test_003, as_of_date=2026-03-10"
            for p in (readme, agent_eval, report, scorecard):
                p.write_text(line, encoding="utf-8")

            proc = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--prd-sot",
                    str(sot),
                    "--readme",
                    str(readme),
                    "--agent-eval",
                    str(agent_eval),
                    "--evaluation-report",
                    str(report),
                    "--scorecard",
                    str(scorecard),
                    "--strict-evaluation-report",
                    "1",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("PUBLIC_CLAIM_SOURCE_NOT_FRESH_RUNTIME", proc.stdout)


if __name__ == "__main__":
    unittest.main()
