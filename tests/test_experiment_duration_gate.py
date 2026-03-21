from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

from src.security_utils import write_sha256_sidecar


ROOT = Path(__file__).resolve().parents[1]


class ExperimentDurationGateTests(unittest.TestCase):
    def _write_rows_with_sidecar(self, path: Path, rows: list[dict]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)

    def _cleanup(self, run_id: str, rows_path: Path) -> None:
        out_path = Path(f"data/agent_quality/{run_id}_experiment_duration_gate.json")
        gate_path = Path(f"data/gates/{run_id}_experiment_duration_gate_gate_result.json")
        for p in (out_path, gate_path, rows_path):
            sidecar = Path(f"{p}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if p.exists():
                p.unlink()

    def test_7_days_fails(self) -> None:
        run_id = "ut_duration_gate_fail"
        rows_path = Path(f"data/tmp/{run_id}_assignment_rows.json")
        self._cleanup(run_id, rows_path)
        try:
            self._write_rows_with_sidecar(
                rows_path,
                [
                    {
                        "experiment_id": "exp_duration_001",
                        "assigned_at": "2026-03-01",
                        "start_date": "2026-03-01",
                        "end_date": "2026-03-07",
                    }
                ],
            )
            proc = subprocess.run(
                [
                    "python3",
                    "scripts/run_experiment_duration_gate.py",
                    "--run-id",
                    run_id,
                    "--experiment-id",
                    "exp_duration_001",
                    "--assignment-log-path",
                    str(rows_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0, msg=proc.stderr)
            payload = json.loads(Path(f"data/agent_quality/{run_id}_experiment_duration_gate.json").read_text(encoding="utf-8"))
            self.assertEqual(payload.get("status"), "FAIL")
            self.assertEqual(payload.get("error_code"), "EXPERIMENT_DURATION_INSUFFICIENT")
            self.assertEqual(int(payload.get("days_covered", 0)), 7)
        finally:
            self._cleanup(run_id, rows_path)

    def test_14_days_passes(self) -> None:
        run_id = "ut_duration_gate_pass"
        rows_path = Path(f"data/tmp/{run_id}_assignment_rows.json")
        self._cleanup(run_id, rows_path)
        try:
            self._write_rows_with_sidecar(
                rows_path,
                [
                    {
                        "experiment_id": "exp_duration_002",
                        "assigned_at": "2026-03-01",
                        "start_date": "2026-03-01",
                        "end_date": "2026-03-14",
                    }
                ],
            )
            proc = subprocess.run(
                [
                    "python3",
                    "scripts/run_experiment_duration_gate.py",
                    "--run-id",
                    run_id,
                    "--experiment-id",
                    "exp_duration_002",
                    "--assignment-log-path",
                    str(rows_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            payload = json.loads(Path(f"data/agent_quality/{run_id}_experiment_duration_gate.json").read_text(encoding="utf-8"))
            self.assertEqual(payload.get("status"), "PASS")
            self.assertEqual(payload.get("error_code"), "NONE")
            self.assertGreaterEqual(int(payload.get("days_covered", 0)), 14)
        finally:
            self._cleanup(run_id, rows_path)


if __name__ == "__main__":
    unittest.main()
