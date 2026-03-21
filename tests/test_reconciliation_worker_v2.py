#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_reconciliation_worker as worker_mod
from src.architecture_v3 import context_frame_path, decision_outcomes_ledger_path
from src.security_utils import verify_sha256_sidecar, write_sha256_sidecar


class ReconciliationWorkerV2Tests(unittest.TestCase):
    def _write_json(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)

    def _cleanup_run(self, run_id: str) -> None:
        paths = [
            Path(f"data/reconciliation/{run_id}_reconciliation_job.json"),
            Path(f"data/reconciliation/{run_id}_reconciliation_result.json"),
            Path(f"data/reconciliation/{run_id}_reconciliation_worker.json"),
            Path(f"data/llm_reports/{run_id}_captain.json"),
            Path(f"data/agent_reports/{run_id}_doctor_variance.json"),
            Path(f"data/agent_reports/{run_id}_commander_priority.json"),
            context_frame_path(run_id),
            decision_outcomes_ledger_path(run_id),
        ]
        for path in paths:
            side = Path(f"{path}.sha256")
            if side.exists():
                side.unlink()
            if path.exists():
                path.unlink()

    def _seed_required_artifacts(self, run_id: str, *, job_status: str = "PENDING", generated_at: str | None = None) -> None:
        now_iso = generated_at or datetime.now(timezone.utc).isoformat()
        self._write_json(
            Path(f"data/reconciliation/{run_id}_reconciliation_job.json"),
            {
                "version": "reconciliation_job_v1",
                "run_id": run_id,
                "batch_id": run_id,
                "generated_at": now_iso,
                "status": job_status,
                "needs_cloud_reconciliation": True,
                "fallback_agents": ["doctor", "commander"],
            },
        )
        self._write_json(context_frame_path(run_id), {"run_id": run_id, "status": "PASS"})
        self._write_json(Path(f"data/llm_reports/{run_id}_captain.json"), {"run_id": run_id, "verdict": "PASS"})
        self._write_json(Path(f"data/agent_reports/{run_id}_doctor_variance.json"), {"run_id": run_id, "normalized_decision": "HOLD_NEED_DATA"})
        self._write_json(
            Path(f"data/agent_reports/{run_id}_commander_priority.json"),
            {"run_id": run_id, "normalized_decision": "HOLD_NEED_DATA", "provisional_local_fallback": False},
        )
        self._write_json(
            decision_outcomes_ledger_path(run_id),
            {"version": "decision_outcomes_ledger_v1", "run_id": run_id, "outcomes": []},
        )

    def test_reconciliation_worker_requires_selector(self) -> None:
        with mock.patch.object(sys, "argv", ["run_reconciliation_worker.py"]):
            with self.assertRaises(SystemExit):
                worker_mod.main()

    def test_reconciliation_worker_backend_must_be_groq(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "reconciliation_backend_not_allowed"):
            worker_mod._run_cloud_reconciliation(run_id="x", backend="ollama", dry_run=True)

    def test_reconciliation_worker_find_pending_runs_filters_by_age(self) -> None:
        run_recent = "ut_recon_recent"
        run_old = "ut_recon_old"
        self._cleanup_run(run_recent)
        self._cleanup_run(run_old)
        try:
            self._seed_required_artifacts(run_recent, generated_at=datetime.now(timezone.utc).isoformat())
            self._seed_required_artifacts(
                run_old,
                generated_at=(datetime.now(timezone.utc) - timedelta(hours=72)).isoformat(),
            )
            found = worker_mod._find_pending_runs(run_id="", batch_id="ut_recon_", max_pending_hours=24)
            found_names = sorted(p.name for p in found)
            self.assertIn(f"{run_recent}_reconciliation_job.json", found_names)
            self.assertNotIn(f"{run_old}_reconciliation_job.json", found_names)
        finally:
            self._cleanup_run(run_recent)
            self._cleanup_run(run_old)

    def test_reconciliation_worker_handles_missing_directory(self) -> None:
        with mock.patch.object(worker_mod.Path, "exists", return_value=False):
            found = worker_mod._find_pending_runs(run_id="", batch_id="", max_pending_hours=24)
        self.assertEqual(found, [])

    def test_reconciliation_worker_load_run_context_fail_closed(self) -> None:
        run_id = "ut_recon_missing_ctx"
        self._cleanup_run(run_id)
        try:
            self._write_json(
                Path(f"data/reconciliation/{run_id}_reconciliation_job.json"),
                {
                    "version": "reconciliation_job_v1",
                    "run_id": run_id,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "status": "PENDING",
                    "needs_cloud_reconciliation": True,
                    "fallback_agents": ["doctor"],
                },
            )
            with self.assertRaises(RuntimeError):
                worker_mod._load_run_context(run_id, Path(f"data/reconciliation/{run_id}_reconciliation_job.json"))
        finally:
            self._cleanup_run(run_id)

    def test_reconciliation_worker_dry_run_compare_and_seal(self) -> None:
        run_id = "ut_recon_dry_run"
        self._cleanup_run(run_id)
        try:
            self._seed_required_artifacts(run_id)
            job_path = Path(f"data/reconciliation/{run_id}_reconciliation_job.json")
            job_payload = json.loads(job_path.read_text(encoding="utf-8"))
            cloud = worker_mod._run_cloud_reconciliation(run_id=run_id, backend="groq", dry_run=True)
            with mock.patch.object(worker_mod, "_append_audit_event", return_value=None):
                sealed = worker_mod._compare_and_seal(
                    run_id=run_id,
                    job_path=job_path,
                    job_payload=job_payload,
                    provisional_decision="HOLD_NEED_DATA",
                    cloud_result=cloud,
                )
            self.assertEqual(sealed.get("status"), "accepted")
            result_path = Path(f"data/reconciliation/{run_id}_reconciliation_result.json")
            self.assertTrue(result_path.exists())
            self.assertTrue(Path(f"{result_path}.sha256").exists())
        finally:
            self._cleanup_run(run_id)

    def test_reconciliation_worker_updated_when_decisions_differ_with_valid_sidecar(self) -> None:
        run_id = "ut_recon_updated"
        self._cleanup_run(run_id)
        try:
            self._seed_required_artifacts(run_id)
            result_path = Path(f"data/reconciliation/{run_id}_reconciliation_result.json")
            # Pre-existing result should be overwritten and sidecar refreshed.
            self._write_json(
                result_path,
                {
                    "version": "reconciliation_worker_result_v2",
                    "run_id": run_id,
                    "status": "accepted",
                    "reconciliation": {"provisional_decision": "HOLD_NEED_DATA", "cloud_decision": "HOLD_NEED_DATA"},
                },
            )
            job_path = Path(f"data/reconciliation/{run_id}_reconciliation_job.json")
            job_payload = json.loads(job_path.read_text(encoding="utf-8"))
            cloud_result = {
                "mode": "dry_run",
                "cloud_decision": "GO",
                "doctor_ref": f"artifact:data/agent_reports/{run_id}_doctor_variance.json#",
                "commander_ref": f"artifact:data/agent_reports/{run_id}_commander_priority.json#",
            }
            with mock.patch.object(worker_mod, "_append_audit_event", return_value=None):
                sealed = worker_mod._compare_and_seal(
                    run_id=run_id,
                    job_path=job_path,
                    job_payload=job_payload,
                    provisional_decision="HOLD_NEED_DATA",
                    cloud_result=cloud_result,
                )

            self.assertEqual(sealed.get("status"), "updated")
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(str(payload.get("status")), "updated")
            self.assertEqual(
                ((payload.get("reconciliation") or {}).get("delta") or {}).get("decision_changed"),
                True,
            )
            ok, reason = verify_sha256_sidecar(result_path, required=True)
            self.assertTrue(ok, msg=reason)
        finally:
            self._cleanup_run(run_id)


if __name__ == "__main__":
    unittest.main()
