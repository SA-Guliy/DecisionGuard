from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src import paired_registry as pr


class PairedRegistryPathNormalizationTests(unittest.TestCase):
    def test_normalize_rejects_forbidden_tokens(self) -> None:
        bad_values = ("../x", "a/b", "a\\b", ".hidden", "ab\x01cd")
        for raw in bad_values:
            with self.assertRaises(RuntimeError):
                pr.normalize_registry_key(raw)

    def test_registry_path_stays_inside_registry_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "paired_registry"
            with mock.patch.object(pr, "PAIRED_REGISTRY_DIR", root):
                out = pr.paired_registry_path("exp_001", "run_001")
                self.assertTrue(str(out).endswith("exp_001__run_001.json"))
                self.assertEqual(out.parent.resolve(strict=False), root.resolve(strict=False))


if __name__ == "__main__":
    unittest.main()

