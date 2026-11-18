import ast
import re
import sys
import unittest
from importlib.metadata import distributions
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


def _module_providers() -> dict[str, set[str]]:
    """Top-level module name -> installed distributions that provide it.

    importlib.metadata.packages_distributions() only reads top_level.txt on
    Python 3.10, which many current wheels no longer ship, so the installed
    file list is read as well, as Python 3.11+ does.
    """
    providers: dict[str, set[str]] = {}
    for dist in distributions():
        names = set((dist.read_text("top_level.txt") or "").split())
        for file in dist.files or []:
            top = file.parts[0]
            if top.endswith((".dist-info", ".data")) or top in ("..", "__pycache__"):
                continue
            names.add(top[:-3] if top.endswith(".py") else top)
        for name in names:
            providers.setdefault(name, set()).add(_normalize(dist.metadata["Name"]))
    return providers


def _third_party_imports() -> set[str]:
    names = set()
    for path in RUNTIME_SOURCES:
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names - set(sys.stdlib_module_names) - LOCAL_PACKAGES


def _declared_requirements(name: str = "requirements.in") -> set[str]:
    """Packages listed directly in a requirements file (ADR-0010: requirements.in, not the lock)."""
    declared = set()
    for line in (ROOT / name).read_text().splitlines():
        line = line.split("#")[0].strip()
        if line and not line.startswith(("-", "--hash")):
            declared.add(_normalize(re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0]))
    return declared


class TestRequirementsCoverRuntimeImports(unittest.TestCase):
    def test_every_runtime_import_is_declared_in_requirements(self):
        providers_of = _module_providers()
        declared = _declared_requirements()

        undeclared = {}
        for module in sorted(_third_party_imports()):
            providers = providers_of.get(module, set())
            if not providers & declared:
                undeclared[module] = sorted(providers) or ["<not installed>"]

        self.assertEqual(undeclared, {}, "imported by runtime code but missing from requirements.in")


class TestRuntimeLockShipsOnlyRuntimePackages(unittest.TestCase):
    def test_documentation_tools_are_not_in_the_runtime_lock(self):
        self.assertEqual(_declared_requirements("requirements.txt") & {"mkdocs", "pygments", "markdown"}, set())

    def test_every_locked_package_is_pinned_with_a_hash(self):
        for name in ("requirements.txt", "requirements-dev.txt", "requirements-docs.txt"):
            text = (ROOT / name).read_text()
            pins = re.findall(r"^[A-Za-z0-9][^\n]*==", text, re.M)
            with self.subTest(name):
                self.assertTrue(pins)
                self.assertEqual(len(pins), len(re.findall(r"^[A-Za-z0-9][^\n]*==[^\n]*\\\n\s+--hash=", text, re.M)))


if __name__ == "__main__":
    unittest.main()
