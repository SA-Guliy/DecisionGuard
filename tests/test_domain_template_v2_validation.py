from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.domain_template import ConfigurationError, load_domain_template
from src.security_utils import write_sha256_sidecar


class DomainTemplateV2ValidationTests(unittest.TestCase):
    @staticmethod
    def _base_template() -> dict:
        src = Path("domain_templates/darkstore_fresh_v1.json")
        return json.loads(src.read_text(encoding="utf-8"))

    def _write_with_sidecar(self, root: Path, payload: dict, name: str) -> Path:
        path = root / name
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_sha256_sidecar(path)
        return path

    def test_missing_scale_fails_closed(self) -> None:
        payload = self._base_template()
        payload["metrics_dictionary"]["aov"].pop("scale", None)
        with tempfile.TemporaryDirectory() as td:
            path = self._write_with_sidecar(Path(td), payload, "missing_scale.json")
            with self.assertRaises(ConfigurationError):
                load_domain_template(str(path))

    def test_invalid_breach_action_fails_closed(self) -> None:
        payload = self._base_template()
        payload["metrics_dictionary"]["fill_rate_units"]["breach_action"] = "STOP_ROLLOUT"
        with tempfile.TemporaryDirectory() as td:
            path = self._write_with_sidecar(Path(td), payload, "bad_breach_action.json")
            with self.assertRaises(ConfigurationError):
                load_domain_template(str(path))


if __name__ == "__main__":
    unittest.main()
