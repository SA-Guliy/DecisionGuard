from __future__ import annotations

import unittest
from pathlib import Path

from src.run_all_cli import build_run_all_parser, resolve_run_all_runtime_config


class TestSingleModeNoPairedArtifactsRequired(unittest.TestCase):
    def test_single_mode_resolve_without_paired_registry(self) -> None:
        template_path = Path("domain_templates/darkstore_fresh_v1.json")
        self.assertTrue(template_path.exists())
        parser = build_run_all_parser()
        args = parser.parse_args(
            [
                "--run-id",
                "single_regression_001",
                "--mode",
                "single",
                "--experiment-id",
                "exp_single_001",
                "--domain-template",
                str(template_path),
            ]
        )
        cfg = resolve_run_all_runtime_config(args)
        self.assertEqual(cfg.mode, "single")
        self.assertEqual(cfg.exp_id, "exp_single_001")


if __name__ == "__main__":
    unittest.main()

