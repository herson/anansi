import tempfile
import unittest
from pathlib import Path

from modules.config import ConfigError, load_config


class TestLoadConfig(unittest.TestCase):

    def _load(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.yaml'
            path.write_text(text)
            return load_config(path)

    def test_returns_the_parsed_file(self):
        config = self._load('default:\n  max_threads: 5\n')
        self.assertEqual(config, {'default': {'max_threads': 5}})

    def test_missing_file_is_a_config_error_naming_the_path(self):
        with self.assertRaisesRegex(ConfigError, 'nowhere.yaml'):
            load_config('/nonexistent/nowhere.yaml')

    def test_invalid_yaml_is_a_config_error(self):
        with self.assertRaises(ConfigError):
            self._load('default: [unclosed\n')

    def test_file_without_a_default_section_is_a_config_error(self):
        for text in ('other: {}\n', '', '- a list\n', 'default: 3\n'):
            with self.subTest(text=text), self.assertRaisesRegex(ConfigError, "default"):
                self._load(text)


if __name__ == '__main__':
    unittest.main()
