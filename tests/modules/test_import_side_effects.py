import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MODULES = [
    'modules.cloud', 'modules.compliance', 'modules.database', 'modules.dns_enum', 'modules.enumerator',
    'modules.exploiter', 'modules.intelligence', 'modules.reporter', 'modules.reporting_pdf',
    'modules.scanner', 'modules.targets', 'modules.vuln_lookup', 'main',
]
PROBE = """
import importlib, logging, sys
for name in sys.argv[1:]:
    importlib.import_module(name)
print(len(logging.getLogger().handlers))
"""


class TestImportingHasNoSideEffects(unittest.TestCase):
    """Importing a module (as tests, the web app and tools do) must not touch the filesystem or logging."""

    def test_imports_create_no_files_and_configure_no_logging(self):
        with tempfile.TemporaryDirectory() as cwd:
            env = {**os.environ, 'PYTHONPATH': str(REPO), 'ANANSI_DB_PATH': ':memory:'}
            result = subprocess.run([sys.executable, '-c', PROBE, *MODULES], cwd=cwd, env=env,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(os.listdir(cwd), [])
            self.assertEqual(result.stdout.strip(), '0')


class TestConfigureLogging(unittest.TestCase):

    def test_writes_to_a_rotating_file_in_the_log_directory(self):
        import logging
        from logging.handlers import RotatingFileHandler

        from modules.app_logging import configure_logging
        root = logging.getLogger()
        saved = root.handlers[:], root.level
        root.handlers = []
        try:
            with tempfile.TemporaryDirectory() as tmp:
                configure_logging(Path(tmp) / 'logs')
                logging.getLogger('anansi.test').info('hello')
                for handler in root.handlers:
                    handler.flush()
                self.assertTrue(any(isinstance(h, RotatingFileHandler) for h in root.handlers))
                self.assertIn('hello', (Path(tmp) / 'logs' / 'anansi.log').read_text())
                for handler in root.handlers:
                    handler.close()
        finally:
            root.handlers, level = saved
            root.setLevel(level)


if __name__ == '__main__':
    unittest.main()
