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

    def test_dependencies_are_audited_weekly_without_a_push(self):
        # PyYAML reads the bare key `on` as the boolean True.
        triggers = self.workflow.get('on', self.workflow.get(True))
        crons = [entry['cron'] for entry in triggers.get('schedule') or []]
        self.assertTrue(crons, 'no scheduled run')
        for cron in crons:
            with self.subTest(cron=cron):
                minute, hour, day_of_month, month, day_of_week = cron.split()
                self.assertEqual((day_of_month, month), ('*', '*'))
                self.assertRegex(day_of_week, r'^[0-6]$', 'should run once a week')
        audits = [step['run'] for step in _steps(self.workflow) if 'pip-audit' in step.get('run', '')]
        self.assertTrue(any('-r requirements.txt' in run for run in audits), 'no step audits the runtime lock')

    def test_lint_findings_fail_the_build(self):
        lint_runs = [step['run'] for step in _steps(self.workflow)
                     if 'flake8' in step.get('run', '')]
        self.assertTrue(lint_runs, 'no step runs flake8')
        for run in lint_runs:
            self.assertNotIn('--exit-zero', run)


if __name__ == '__main__':
    unittest.main()
