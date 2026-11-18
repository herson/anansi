import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'ci.yml'
COMMIT_SHA = re.compile(r'^[0-9a-f]{40}$')


def _steps(workflow):
    for job in workflow['jobs'].values():
        yield from job['steps']


class TestCIWorkflow(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load(WORKFLOW.read_text())

    def test_every_action_is_pinned_to_a_commit_sha(self):
        for step in _steps(self.workflow):
            if 'uses' not in step:
                continue
            ref = step['uses'].partition('@')[2]
            with self.subTest(action=step['uses']):
                self.assertRegex(ref, COMMIT_SHA)

    def test_the_token_can_only_read_the_repository(self):
        self.assertEqual(self.workflow.get('permissions'), {'contents': 'read'})
        for name, job in self.workflow['jobs'].items():
            with self.subTest(job=name):
                self.assertNotIn('permissions', job)

    def test_lint_findings_fail_the_build(self):
        lint_runs = [step['run'] for step in _steps(self.workflow)
                     if 'flake8' in step.get('run', '')]
        self.assertTrue(lint_runs, 'no step runs flake8')
        for run in lint_runs:
            self.assertNotIn('--exit-zero', run)


if __name__ == '__main__':
    unittest.main()
