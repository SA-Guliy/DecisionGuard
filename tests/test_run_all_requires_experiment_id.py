from __future__ import annotations

import argparse
import os
import unittest

from src.run_all_cli import resolve_run_all_runtime_config


class RunAllRequiresExperimentIdTests(unittest.TestCase):
    def test_missing_experiment_id_is_fail_closed(self) -> None:
        args = argparse.Namespace(
            run_id="ut_missing_expid",
            experiment_id="",
            domain_template="domain_templates/darkstore_fresh_v1.json",
            reload_raw=False,
            raw_dir="",
            allow_overwrite_run=0,
            overwrite_reason="",
            verify_acceptance=1,
            lightweight_profile=0,
            backend="auto",
            allow_remote_llm=-1,
        )
        with self.assertRaises(SystemExit) as ctx:
            resolve_run_all_runtime_config(args)
        self.assertIn("EXPERIMENT_CONTEXT_REQUIRED", str(ctx.exception))

    def test_present_experiment_id_allows_runtime_config(self) -> None:
        args = argparse.Namespace(
            run_id="ut_with_expid",
            experiment_id="exp_aov_001",
            domain_template="domain_templates/darkstore_fresh_v1.json",
            reload_raw=False,
            raw_dir="",
            allow_overwrite_run=0,
            overwrite_reason="",
            verify_acceptance=1,
            lightweight_profile=0,
            backend="auto",
            allow_remote_llm=-1,
        )
        prev = os.getenv("DS_STRICT_RUNTIME")
        os.environ["DS_STRICT_RUNTIME"] = "0"
        try:
            runtime = resolve_run_all_runtime_config(args)
        finally:
            if prev is None:
                os.environ.pop("DS_STRICT_RUNTIME", None)
            else:
                os.environ["DS_STRICT_RUNTIME"] = prev
        self.assertEqual(runtime.exp_id, "exp_aov_001")


if __name__ == "__main__":
    unittest.main()
