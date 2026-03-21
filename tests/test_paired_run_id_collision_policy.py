from __future__ import annotations

import unittest
from pathlib import Path

from src.run_all_cli import build_run_all_parser, resolve_run_all_runtime_config


class PairedRunIdCollisionPolicyTests(unittest.TestCase):
    def _touch(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")

    def test_collision_requires_allow_overwrite(self) -> None:
        parent_hit = Path("data/tmp/paired_collision_parent.json")
        self._touch(parent_hit)
        try:
            parser = build_run_all_parser()
            args = parser.parse_args(
                [
                    "--run-id",
                    "paired_collision_parent",
                    "--mode",
                    "paired",
                    "--run-id-ctrl",
                    "paired_collision_ctrl",
                    "--experiment-id",
                    "exp_collision_001",
                    "--domain-template",
                    "domain_templates/darkstore_fresh_v1.json",
                ]
            )
            with self.assertRaises(SystemExit) as ctx:
                resolve_run_all_runtime_config(args)
            self.assertIn("PAIRED_RUN_ID_COLLISION", str(ctx.exception))
        finally:
            if parent_hit.exists():
                parent_hit.unlink()

    def test_partial_overwrite_is_forbidden(self) -> None:
        parent_hit = Path("data/tmp/paired_partial_overwrite_parent.json")
        self._touch(parent_hit)
        try:
            parser = build_run_all_parser()
            args = parser.parse_args(
                [
                    "--run-id",
                    "paired_partial_overwrite_parent",
                    "--mode",
                    "paired",
                    "--run-id-ctrl",
                    "paired_partial_overwrite_ctrl",
                    "--experiment-id",
                    "exp_collision_002",
                    "--domain-template",
                    "domain_templates/darkstore_fresh_v1.json",
                    "--allow-overwrite-run",
                    "1",
                    "--overwrite-reason",
                    "unit_test_atomic_overwrite",
                ]
            )
            with self.assertRaises(SystemExit) as ctx:
                resolve_run_all_runtime_config(args)
            self.assertIn("partial overwrite forbidden", str(ctx.exception))
        finally:
            if parent_hit.exists():
                parent_hit.unlink()

    def test_collision_scan_ignores_neighbor_prefix_run_id(self) -> None:
        # Neighbor run_id should not trigger collision for token-aware matching.
        neighbor_hit = Path("data/tmp/paired_collision_parent_extra.json")
        self._touch(neighbor_hit)
        try:
            parser = build_run_all_parser()
            args = parser.parse_args(
                [
                    "--run-id",
                    "paired_collision_parent",
                    "--mode",
                    "paired",
                    "--run-id-ctrl",
                    "paired_collision_ctrl",
                    "--experiment-id",
                    "exp_collision_003",
                    "--domain-template",
                    "domain_templates/darkstore_fresh_v1.json",
                ]
            )
            cfg = resolve_run_all_runtime_config(args)
            self.assertEqual(cfg.mode, "paired")
        finally:
            if neighbor_hit.exists():
                neighbor_hit.unlink()


if __name__ == "__main__":
    unittest.main()
