import ast
import re
import sys
import unittest
from importlib.metadata import packages_distributions
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_SOURCES = [
    ROOT / "main.py",
    *(ROOT / "domain").glob("*.py"),
    *(ROOT / "modules").glob("*.py"),
    *(ROOT / "web").glob("*.py"),
]
LOCAL_PACKAGES = {"domain", "modules", "web"}


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _third_party_imports() -> set[str]:
    names = set()
    for path in RUNTIME_SOURCES:
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names - set(sys.stdlib_module_names) - LOCAL_PACKAGES


def _declared_requirements() -> set[str]:
    declared = set()
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            declared.add(_normalize(re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0]))
    return declared


class TestRequirementsCoverRuntimeImports(unittest.TestCase):
    def test_every_runtime_import_is_declared_in_requirements(self):
        distributions = packages_distributions()
        declared = _declared_requirements()

        undeclared = {}
        for module in sorted(_third_party_imports()):
            providers = {_normalize(d) for d in distributions.get(module, [])}
            if not providers & declared:
                undeclared[module] = sorted(providers) or ["<not installed>"]

        self.assertEqual(undeclared, {}, "imported by runtime code but missing from requirements.txt")


if __name__ == "__main__":
    unittest.main()
