from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AntiGoodhartRequiresAbTests(unittest.TestCase):
    def _cleanup(self, run_id: str) -> None:
        verdict = Path(f"data/agent_quality/{run_id}_anti_goodhart_verdict.json")
        gate = Path(f"data/gates/{run_id}_anti_goodhart_sot_gate_result.json")
        for p in (verdict, gate):
            sidecar = Path(f"{p}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if p.exists():
                p.unlink()

    def test_missing_ab_returns_ab_artifact_required(self) -> None:
        run_id = "ut_anti_goodhart_missing_ab"
        self._cleanup(run_id)
        try:
            proc = subprocess.run(
                ["python3", "scripts/run_anti_goodhart_verdict.py", "--run-id", run_id, "--experiment-id", "exp_missing_ab"],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(Path(f"data/agent_quality/{run_id}_anti_goodhart_verdict.json").read_text(encoding="utf-8"))
            self.assertEqual(payload.get("status"), "FAIL")
            self.assertEqual(payload.get("error_code"), "AB_ARTIFACT_REQUIRED")
        finally:
            self._cleanup(run_id)


if __name__ == "__main__":
    unittest.main()
