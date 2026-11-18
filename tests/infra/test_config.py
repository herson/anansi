import unittest
from pathlib import Path

import yaml

from unittest.mock import patch

from modules.intelligence import DEFAULT_MODEL, IntelligentAnalyzer

CONFIG = Path(__file__).resolve().parents[2] / "config.yaml"


class TestDefaultConfig(unittest.TestCase):

    def setUp(self):
        self.default = yaml.safe_load(CONFIG.read_text())["default"]

    def test_default_scan_does_not_hide_any_ports(self):
        self.assertEqual(self.default["exclude_ports"], [])

    def test_has_no_settings_the_code_ignores(self):
        for unused in ("scan_type", "logging_level", "metasploit_enabled"):
            with self.subTest(unused):
                self.assertNotIn(unused, self.default)

    def test_ai_model_is_the_same_default_the_code_falls_back_to(self):
        self.assertEqual(self.default["ai_model"], DEFAULT_MODEL)

    def test_shipped_ai_settings_are_valid(self):
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}):
            IntelligentAnalyzer(self.default)


if __name__ == "__main__":
    unittest.main()
