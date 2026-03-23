import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts import build_investor_demo_staging as staging


class BuildInvestorDemoStagingTests(unittest.TestCase):
    def test_synthetic_sample_prefers_reports_and_fallbacks_to_experiments(self) -> None:
        from_reports = staging._build_synthetic_sample(
            {"reports": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}]},
            "examples/investor_demo/src/history_sot_v1.json",
        )
        self.assertEqual(from_reports["sample_count"], 3)
        self.assertEqual(len(from_reports["sample"]), 3)
        self.assertEqual(from_reports["sample"][0]["id"], 1)

        from_experiments = staging._build_synthetic_sample(
            {"experiments": [{"id": "a"}, {"id": "b"}]},
            "examples/investor_demo/src/history_sot_v1.json",
        )
        self.assertEqual(from_experiments["sample_count"], 2)
        self.assertEqual(from_experiments["sample"][0]["id"], "a")

    def test_resolve_demo_sources_prefers_repo_tracked_demo_sources(self) -> None:
        sources, profile = staging._resolve_demo_sources()
        self.assertEqual(profile, "examples_src")
        required = {
            "batch_summary",
            "decision_card",
            "agent_run_sample",
            "batch_consolidated_report",
            "executive_roi_scorecard",
            "history_sot",
        }
        self.assertEqual(set(sources.keys()), required)
        for key in required:
            self.assertTrue(sources[key].exists(), f"missing source for {key}: {sources[key]}")

    def test_sanitize_obj_keeps_safe_token_metrics_and_redacts_real_secrets(self) -> None:
        payload = {
            "prompt_tokens": "1234",
            "token_count": "99",
            "cache_ttl": "3600",
            "api_key": "REAL_SECRET_VALUE",
            "client_secret": ["AAA", "BBB"],
        }
        cleaned = staging._sanitize_obj(payload)
        self.assertEqual(cleaned["prompt_tokens"], "1234")
        self.assertEqual(cleaned["token_count"], "99")
        self.assertEqual(cleaned["cache_ttl"], "3600")
        self.assertEqual(cleaned["api_key"], staging.REDACTED_TOKEN)
        self.assertEqual(cleaned["client_secret"], [staging.REDACTED_TOKEN, staging.REDACTED_TOKEN])

    def test_write_text_creates_sha256_sidecar(self) -> None:
        with TemporaryDirectory() as td:
            path = Path(td) / "demo.md"
            staging._write_text(path, "hello", apply=True)
            self.assertTrue(path.exists())
            self.assertTrue(path.with_suffix(path.suffix + ".sha256").exists())


if __name__ == "__main__":
    unittest.main()
