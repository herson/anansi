import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'ci.yml'


def _steps(workflow):
    for job in workflow['jobs'].values():
        yield from job['steps']


class TestCIWorkflow(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load(WORKFLOW.read_text())

    def test_lint_findings_fail_the_build(self):
        lint_runs = [step['run'] for step in _steps(self.workflow)
                     if 'flake8' in step.get('run', '')]
        self.assertTrue(lint_runs, 'no step runs flake8')
        for run in lint_runs:
            self.assertNotIn('--exit-zero', run)


if __name__ == '__main__':
    unittest.main()
