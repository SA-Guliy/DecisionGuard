from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import run_publish_release_audit as audit_mod


ROOT = Path(__file__).resolve().parents[1]


class PublishCorpusLockTests(unittest.TestCase):
    def test_existing_corpus_passes_lock(self) -> None:
        ok, details = audit_mod._check_historical_corpus_lock(  # pylint: disable=protected-access
            ROOT / "not_delete_historical_patterns/metrics_snapshots",
            denylist_globs=[],
            min_pairs=2,
        )
        self.assertTrue(ok, msg=str(details))

    def test_missing_corpus_fails_lock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "missing_corpus"
            ok, details = audit_mod._check_historical_corpus_lock(  # pylint: disable=protected-access
                missing,
                denylist_globs=[],
                min_pairs=1,
            )
        self.assertFalse(ok)
        self.assertEqual(details.get("reason"), "corpus_root_missing")

    def test_denylist_hit_fails_lock(self) -> None:
        ok, details = audit_mod._check_historical_corpus_lock(  # pylint: disable=protected-access
            ROOT / "not_delete_historical_patterns/metrics_snapshots",
            denylist_globs=["not_delete_historical_patterns/**"],
            min_pairs=1,
        )
        self.assertFalse(ok)
        self.assertEqual(details.get("reason"), "corpus_path_denied_by_publish_policy")


if __name__ == "__main__":
    unittest.main()
