from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import run_publish_release_audit as audit_mod
from src.security_utils import write_sha256_sidecar


ROOT = Path(__file__).resolve().parents[1]


class PublishCorpusLockTests(unittest.TestCase):
    def _make_temp_corpus(self, td: str, *, pairs: int = 2) -> Path:
        corpus = Path(td) / "metrics_snapshots"
        corpus.mkdir(parents=True, exist_ok=True)
        for i in range(pairs):
            payload = corpus / f"sample_{i}.json"
            payload.write_text('{"run_id":"sample"}\n', encoding="utf-8")
            write_sha256_sidecar(payload)
        return corpus

    def test_existing_corpus_passes_lock(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            corpus = self._make_temp_corpus(td, pairs=2)
            rel = corpus.relative_to(ROOT).as_posix()
            ok, details = audit_mod._check_historical_corpus_lock(  # pylint: disable=protected-access
                corpus,
                denylist_globs=[f"{rel}/**"],
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

    def test_corpus_not_in_denylist_fails_lock(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            corpus = self._make_temp_corpus(td, pairs=1)
            rel = corpus.relative_to(ROOT).as_posix()
            ok, details = audit_mod._check_historical_corpus_lock(  # pylint: disable=protected-access
                corpus,
                denylist_globs=[],
                min_pairs=1,
            )
        self.assertFalse(ok)
        self.assertEqual(details.get("reason"), "corpus_path_not_denied_by_publish_policy")

    def test_missing_private_corpus_is_non_blocking_when_denylisted(self) -> None:
        missing = ROOT / "not_delete_historical_patterns/missing_corpus"
        ok, details = audit_mod._check_historical_corpus_lock(  # pylint: disable=protected-access
            missing,
            denylist_globs=["not_delete_historical_patterns/**"],
            min_pairs=1,
        )
        self.assertTrue(ok)
        self.assertEqual(details.get("reason"), "corpus_root_missing_private_denied_by_publish_policy")

    def test_missing_non_private_corpus_stays_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "missing_corpus"
            ok, details = audit_mod._check_historical_corpus_lock(  # pylint: disable=protected-access
                missing,
                denylist_globs=["not_delete_historical_patterns/**"],
                min_pairs=1,
            )
            self.assertFalse(ok)
            self.assertEqual(details.get("reason"), "corpus_root_missing")


if __name__ == "__main__":
    unittest.main()
