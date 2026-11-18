import importlib
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / 'docs'
PAGES = sorted(p for p in DOCS.rglob('*.md') if DOCS / 'adr' not in p.parents)

CODE_BLOCK = re.compile(r'```(\w*)\n(.*?)```', re.DOTALL)
IMPORT = re.compile(r'^from ([\w.]+) import ([\w, ]+)$', re.MULTILINE)
LINK = re.compile(r'\]\(([^)\s]+)\)')
FLAG = re.compile(r'(?<![\w-])--[a-z][\w-]*')


def _code_blocks(page, language):
    return [body for lang, body in CODE_BLOCK.findall(page.read_text()) if lang == language]


def _cli_flags():
    result = subprocess.run([sys.executable, 'main.py', '--help'], cwd=ROOT,
                            capture_output=True, text=True, timeout=60, check=True)
    return set(FLAG.findall(result.stdout))


class TestDocsMatchTheCode(unittest.TestCase):
    """The mkdocs pages (docs/, without the ADRs) must describe code that exists."""

    def test_there_are_pages_to_check(self):
        self.assertTrue(PAGES)

    def test_every_documented_flag_exists(self):
        flags = _cli_flags()
        for page in PAGES:
            for block in _code_blocks(page, 'bash'):
                for line in block.splitlines():
                    if 'main.py' not in line:
                        continue
                    for flag in FLAG.findall(line):
                        with self.subTest(page=page.relative_to(ROOT).as_posix(), flag=flag):
                            self.assertIn(flag, flags)

    def test_every_documented_import_exists(self):
        for page in PAGES:
            for block in _code_blocks(page, 'python'):
                for module, names in IMPORT.findall(block):
                    for name in (n.strip() for n in names.split(',')):
                        with self.subTest(page=page.relative_to(ROOT).as_posix(), name=f'{module}.{name}'):
                            self.assertTrue(hasattr(importlib.import_module(module), name))

    def test_every_relative_link_points_to_a_page_in_the_site(self):
        for page in PAGES:
            for target in LINK.findall(page.read_text()):
                if re.match(r'^[a-z]+:', target) or target.startswith('#'):
                    continue
                path = (page.parent / target.partition('#')[0]).resolve()
                with self.subTest(page=page.relative_to(ROOT).as_posix(), link=target):
                    self.assertTrue(path.is_file(), 'missing')
                    self.assertIn(DOCS, path.parents, 'outside docs/, so mkdocs cannot build it')


if __name__ == '__main__':
    unittest.main()
