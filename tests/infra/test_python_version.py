import configparser
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MINIMUM = (3, 11)  # ADR-0011


def _version(text):
    return tuple(int(part) for part in str(text).split('.'))


def _lock_minimum():
    script = (ROOT / 'scripts' / 'lock-requirements.sh').read_text()
    return _version(re.search(r'^PYTHON_MIN="([\d.]+)"$', script, re.MULTILINE).group(1))


def _ci_versions():
    workflow = yaml.safe_load((ROOT / '.github' / 'workflows' / 'ci.yml').read_text())
    return sorted(_version(v) for v in workflow['jobs']['build']['strategy']['matrix']['python-version'])


def _mypy_target():
    config = configparser.ConfigParser()
    config.read(ROOT / 'mypy.ini')
    return _version(config['mypy']['python_version'])


class TestMinimumPythonVersion(unittest.TestCase):
    """The lockfiles, CI and mypy must all target the supported minimum."""

    def test_lockfiles_are_compiled_for_the_minimum(self):
        self.assertEqual(_lock_minimum(), MINIMUM)

    def test_ci_tests_the_minimum_and_nothing_older(self):
        self.assertEqual(_ci_versions()[0], MINIMUM)

    def test_mypy_checks_against_the_minimum(self):
        self.assertEqual(_mypy_target(), MINIMUM)

    def test_no_lockfile_pins_a_package_for_an_unsupported_python(self):
        older = f"python_full_version < '{MINIMUM[0]}.{MINIMUM[1]}'"
        for lock in sorted(ROOT.glob('requirements*.txt')):
            with self.subTest(lock=lock.name):
                self.assertNotIn(older, lock.read_text())


if __name__ == '__main__':
    unittest.main()
