import unittest
from pathlib import Path

import yaml

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


if __name__ == "__main__":
    unittest.main()
