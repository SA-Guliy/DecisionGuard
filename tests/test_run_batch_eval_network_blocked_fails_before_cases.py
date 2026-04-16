from __future__ import annotations

import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import requests

from scripts import run_batch_eval as mod


class RunBatchEvalNetworkBlockedBeforeCasesTests(unittest.TestCase):
    def _cleanup(self, batch_id: str) -> None:
        for p in (
            Path(f"data/agent_quality/{batch_id}_cloud_preflight.json"),
            Path(f"data/agent_quality/{batch_id}_cloud_preflight.json.sha256"),
            Path(f"data/batch_eval/{batch_id}_run_attempts.json"),
            Path(f"data/batch_eval/{batch_id}_run_attempts.json.sha256"),
            Path(f"data/batch_eval/{batch_id}_summary.json"),
            Path(f"data/batch_eval/{batch_id}_summary.json.sha256"),
        ):
            p.unlink(missing_ok=True)

    def test_release_candidate_network_blocked_stops_before_cases(self) -> None:
        batch_id = f"ut_preflight_block_{uuid.uuid4().hex[:8]}"
        with tempfile.TemporaryDirectory() as td:
            secrets = Path(td) / ".groq_secrets"
            secrets.write_text("GROQ_API_KEY=test_key_for_unit_only\n", encoding="utf-8")

            with mock.patch.object(sys, "argv", [
                "run_batch_eval.py",
                "--batch-id",
                batch_id,
                "--release-candidate",
                "1",
                "--max-cases",
                "1",
                "--sleep-seconds",
                "0",
            ]), mock.patch.object(mod, "_ensure_groq_secrets", return_value=secrets), mock.patch.object(
                mod.requests, "post", side_effect=requests.exceptions.ConnectionError("network down")
            ), mock.patch.object(
                mod, "build_batch_eval_cases"
            ) as cases_mock:
                with self.assertRaises(SystemExit) as exc:
                    mod.main()
            self.assertIn("RUNTIME_ENV_NETWORK_BLOCKED", str(exc.exception))
            cases_mock.assert_not_called()

        preflight_path = Path(f"data/agent_quality/{batch_id}_cloud_preflight.json")
        self.assertTrue(preflight_path.exists())
        payload = json.loads(preflight_path.read_text(encoding="utf-8"))
        self.assertEqual(payload.get("status"), "fail")
        self.assertEqual(payload.get("error_code"), "RUNTIME_ENV_NETWORK_BLOCKED")
        self.assertTrue(Path(f"{preflight_path}.sha256").exists())
        self._cleanup(batch_id)


if __name__ == "__main__":
    unittest.main()
