from __future__ import annotations

import json
import unittest
from pathlib import Path

from src.paired_registry import PAIRED_RUN_STATUS_VALUES
from src.run_all_cli import PAIRED_RUN_STATUS


class PairedStatusEnumCanonicalTests(unittest.TestCase):
    def test_status_enum_matches_expected_values(self) -> None:
        expected = ("COMPLETE", "CTRL_FAILED", "TREATMENT_FAILED", "PARTIAL")
        self.assertEqual(tuple(PAIRED_RUN_STATUS_VALUES), expected)
        self.assertEqual(tuple(PAIRED_RUN_STATUS), expected)

    def test_contract_enums_match_runtime_enum(self) -> None:
        expected = list(PAIRED_RUN_STATUS_VALUES)
        registry_contract = json.loads(Path("configs/contracts/paired_registry_v1.json").read_text(encoding="utf-8"))
        context_contract = json.loads(Path("configs/contracts/paired_experiment_v2.json").read_text(encoding="utf-8"))
        self.assertEqual(registry_contract["properties"]["paired_status"]["enum"], expected)
        self.assertEqual(context_contract["properties"]["paired_status"]["enum"], expected)


if __name__ == "__main__":
    unittest.main()

