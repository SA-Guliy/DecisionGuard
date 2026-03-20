from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

from src.security_utils import write_sha256_sidecar


ROOT = Path(__file__).resolve().parents[1]


class HistoricalRetrievalGateV32Tests(unittest.TestCase):
    def _write_json_sidecar(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)

    def _cleanup(self, run_ids: list[str]) -> None:
        for run_id in run_ids:
            for path in [
                Path(f"data/metrics_snapshots/{run_id}.json"),
                Path(f"data/ab_reports/{run_id}_exp1_ab.json"),
                Path(f"data/ab_reports/{run_id}_exp1_ab_v2.json"),
                Path(f"data/agent_context/{run_id}_historical_context_pack.json"),
                Path(f"data/agent_context/{run_id}_reasoning_memory_ledger.json"),
                Path(f"data/gates/{run_id}_historical_retrieval_gate_gate_result.json"),
            ]:
                sidecar = Path(f"{path}.sha256")
                if sidecar.exists():
                    sidecar.unlink()
                if path.exists():
                    path.unlink()

    def test_semantic_hybrid_pack_pass(self) -> None:
        run_id = "ut_v32_hist_current"
        base_run = "ut_v32_hist_base"
        self._cleanup([run_id, base_run])
        try:
            self._write_json_sidecar(
                Path(f"data/metrics_snapshots/{run_id}.json"),
                {
                    "run_id": run_id,
                    "run_config": {"experiment_id": "exp1"},
                    "metrics": {"gmv": 1200.0, "fill_rate_units": 0.95, "writeoff_cogs": 21.0},
                },
            )
            self._write_json_sidecar(
                Path(f"data/metrics_snapshots/{base_run}.json"),
                {
                    "run_id": base_run,
                    "run_config": {"experiment_id": "exp_prev"},
                    "metrics": {"gmv": 1180.0, "fill_rate_units": 0.94, "writeoff_cogs": 25.0},
                },
            )
            self._write_json_sidecar(
                Path(f"data/ab_reports/{base_run}_exp1_ab_v2.json"),
                {"status": "OK", "primary_metric": {"name": "gmv", "uplift": 0.02}},
            )
            proc = subprocess.run(
                ["python3", "scripts/run_historical_retrieval_gate.py", "--run-id", run_id, "--top-k", "3"],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
            pack = json.loads(Path(f"data/agent_context/{run_id}_historical_context_pack.json").read_text(encoding="utf-8"))
            self.assertEqual(pack.get("status"), "PASS")
            self.assertEqual(pack.get("retrieval_mode"), "semantic_hybrid_mvp")
            self.assertTrue(isinstance(pack.get("fact_refs"), list) and len(pack.get("fact_refs")) > 0)
            self.assertTrue(isinstance(pack.get("evidence_hashes"), list) and len(pack.get("evidence_hashes")) > 0)
        finally:
            self._cleanup([run_id, base_run])


if __name__ == "__main__":
    unittest.main()
