from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts import run_all as run_all_mod
from src.security_utils import write_sha256_sidecar


class PairedPartialAntiGoodhartPolicyTests(unittest.TestCase):
    def _write_json(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)

    def _cleanup(self, run_id: str) -> None:
        targets = [
            Path(f"data/agent_reports/{run_id}_commander_priority.json"),
            Path(f"data/agent_reports/{run_id}_orchestrator_safe_decision.json"),
        ]
        for path in targets:
            sidecar = Path(f"{path}.sha256")
            if sidecar.exists():
                sidecar.unlink()
            if path.exists():
                path.unlink()

    def test_partial_aggressive_decision_is_blocked(self) -> None:
        run_id = "ut_paired_partial_block"
        self._cleanup(run_id)
        try:
            self._write_json(
                Path(f"data/agent_reports/{run_id}_commander_priority.json"),
                {"run_id": run_id, "normalized_decision": "GO"},
            )
            with self.assertRaises(SystemExit):
                run_all_mod._enforce_paired_partial_ceiling_or_exit(
                    run_id=run_id,
                    paired_mode=True,
                    paired_registry_payload={"paired_status": "PARTIAL"},
                )
        finally:
            self._cleanup(run_id)

    def test_partial_safe_decision_passes(self) -> None:
        run_id = "ut_paired_partial_pass"
        self._cleanup(run_id)
        try:
            self._write_json(
                Path(f"data/agent_reports/{run_id}_commander_priority.json"),
                {"run_id": run_id, "normalized_decision": "HOLD_NEED_DATA"},
            )
            run_all_mod._enforce_paired_partial_ceiling_or_exit(
                run_id=run_id,
                paired_mode=True,
                paired_registry_payload={"paired_status": "TREATMENT_FAILED"},
            )
        finally:
            self._cleanup(run_id)

    def test_treatment_failed_aggressive_decision_is_blocked(self) -> None:
        run_id = "ut_paired_treatment_failed_block"
        self._cleanup(run_id)
        try:
            self._write_json(
                Path(f"data/agent_reports/{run_id}_commander_priority.json"),
                {"run_id": run_id, "normalized_decision": "RUN_AB"},
            )
            with self.assertRaises(SystemExit):
                run_all_mod._enforce_paired_partial_ceiling_or_exit(
                    run_id=run_id,
                    paired_mode=True,
                    paired_registry_payload={"paired_status": "TREATMENT_FAILED"},
                )
        finally:
            self._cleanup(run_id)


if __name__ == "__main__":
    unittest.main()
