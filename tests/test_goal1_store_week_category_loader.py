#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import build_ab_report as build_ab_report_mod
from scripts import build_reports as build_reports_mod


class Goal1StoreWeekCategoryLoaderTests(unittest.TestCase):
    def _write_payload(self, tmpdir: str, name: str, payload: object) -> Path:
        path = Path(tmpdir) / name
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def test_build_ab_report_loader_supports_list_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            fact_path = self._write_payload(
                tmpdir,
                "fact_list.json",
                [{"store_id": "s1"}, {"store_id": "s2"}, "noise"],
            )
            rows = build_ab_report_mod._load_goal1_store_week_category_rows(
                {"goal1_store_week_category_ref": str(fact_path)}
            )
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(isinstance(r, dict) for r in rows))

    def test_build_ab_report_loader_supports_dict_rows_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            fact_path = self._write_payload(
                tmpdir,
                "fact_dict_rows.json",
                {
                    "run_id": "r1",
                    "generated_at": "2026-03-03T00:00:00Z",
                    "data_source_type": "synthetic",
                    "rows": [{"store_id": "s1"}, {"store_id": "s2"}, 123],
                },
            )
            rows = build_ab_report_mod._load_goal1_store_week_category_rows(
                {"goal1_store_week_category_ref": str(fact_path)}
            )
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(isinstance(r, dict) for r in rows))

    def test_build_reports_loader_supports_list_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            fact_path = self._write_payload(
                tmpdir,
                "fact_list.json",
                [{"store_id": "s1"}, {"store_id": "s2"}, None],
            )
            rows = build_reports_mod._load_goal1_store_week_category_rows(
                {"goal1_store_week_category_ref": str(fact_path)}
            )
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(isinstance(r, dict) for r in rows))

    def test_build_reports_loader_supports_dict_rows_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            fact_path = self._write_payload(
                tmpdir,
                "fact_dict_rows.json",
                {
                    "run_id": "r1",
                    "generated_at": "2026-03-03T00:00:00Z",
                    "data_source_type": "synthetic",
                    "rows": [{"store_id": "s1"}, {"store_id": "s2"}, "bad"],
                },
            )
            rows = build_reports_mod._load_goal1_store_week_category_rows(
                {"goal1_store_week_category_ref": str(fact_path)}
            )
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(isinstance(r, dict) for r in rows))


if __name__ == "__main__":
    unittest.main()
