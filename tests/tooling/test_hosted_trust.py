"""Rules: none (a missing trusted ref must never fall back to PR execution)."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
import yaml
import json
import shutil
from test_vm_selection import VMFixture, SCRIPT


class HostedTrust(unittest.TestCase):
    def test_failed_decision_cannot_reach_checkout_or_malicious_classifier(self):
        workflow = (Path(__file__).resolve().parents[2]/
                    '.github/workflows/vm-selection-trial.yml').read_text()
        final = workflow.split('  trial-result:\n', 1)[1]
        before_checkout = final.split('      - uses: actions/checkout@', 1)[0]
        self.assertIn('DECIDE_RESULT: ${{ needs.decide.result }}', before_checkout)
        self.assertIn('BASE_SHA: ${{ needs.decide.outputs.base }}', before_checkout)
        guard = textwrap.dedent(before_checkout.split('        run: |\n', 1)[1])
        with tempfile.TemporaryDirectory() as folder:
            reached = Path(folder)/'malicious-pr-classifier-executed'
            for status in ('success', 'failure', 'cancelled', 'skipped', ''):
                for base in ('a'*40, '', 'main', 'refs/pull/1/merge'):
                    with self.subTest(status=status, base=base):
                        reached.unlink(missing_ok=True)
                        run = subprocess.run(['bash', '-e', '-c', guard+
                                              '\nprintf reached > "$MARKER"\n'],
                                             env={**os.environ, 'DECIDE_RESULT': status,
                                                  'BASE_SHA': base, 'MARKER': str(reached)},
                                             capture_output=True)
                        allowed = status == 'success' and base == 'a'*40
                        self.assertEqual(run.returncode == 0, allowed)
                        self.assertEqual(reached.exists(), allowed)


if __name__ == '__main__':
    unittest.main()


class WorkflowContract(VMFixture):
    def workflow(self):
        path = Path(__file__).resolve().parents[2]/'.github/workflows/vm-selection-trial.yml'
        return yaml.safe_load(path.read_text())

    def step(self, job, name):
        return next(s for s in self.workflow()['jobs'][job]['steps'] if s.get('name') == name)

    def shell(self, code, **values):
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', code],
                              cwd=self.repo, env={**os.environ, **values},
                              text=True, capture_output=True)

    def test_required_workflow_dependencies_and_shell_cannot_silently_skip(self):
        jobs = self.workflow()['jobs']
        self.assertEqual(jobs['trial-result']['needs'], ['unit', 'decide', 'simulated_vm'])
        self.assertEqual(jobs['trial-result'].get('if'), '${{ always() }}')
        self.assertEqual(jobs['simulated_vm']['needs'], 'decide')
        self.assertEqual(jobs['simulated_vm']['if'], "${{ needs.decide.outputs.action == 'run' }}")
        for name, job in jobs.items():
            self.assertFalse(job.get('continue-on-error', False))
            self.assertLessEqual(job['timeout-minutes'], 8)
            if name != 'simulated_vm' and name != 'trial-result':
                self.assertNotIn('if', job)
            for step in job['steps']:
                self.assertNotIn('if', step)
                self.assertFalse(step.get('continue-on-error', False))
                if 'run' in step:
                    self.assertIn(step.get('shell', 'bash'), ('bash',))
        checkout = next(s for s in jobs['decide']['steps'] if 'uses' in s)
        self.assertEqual(checkout['with']['ref'], 'refs/heads/main')
        self.assertFalse(checkout['with']['persist-credentials'])
        unit = '\n'.join(s.get('run', '') for s in jobs['unit']['steps'])
        self.assertIn('unittest discover -s tests/tooling', unit)

    def test_actual_final_shell_state_matrix_bootstrap_and_trusted_main(self):
        step = self.step('trial-result', 'Require actual decision and workload results')
        for trusted in (False, True):
            if trusted:
                destination = self.repo/'.github/vm_selection.py'
                destination.parent.mkdir(exist_ok=True)
                shutil.copyfile(SCRIPT, destination)
            decision = dict(version=1, head=self.base, base=self.base,
                            consumer_fingerprint='0'*64, action='run', paths=[], reason='bootstrap')
            for unit in ('success', 'failure', 'cancelled', 'skipped', ''):
                for decide in ('success', 'failure', 'cancelled', 'skipped', ''):
                    for verify in ('success', 'failure', 'cancelled', 'skipped', ''):
                        run = self.shell(step['run'], UNIT_RESULT=unit, DECIDE_RESULT=decide,
                                         VERIFY_RESULT=verify, BASE_SHA=self.base, HEAD_SHA=self.base,
                                         DECISION=json.dumps(decision))
                        self.assertEqual(run.returncode == 0, unit == decide == verify == 'success',
                                         (trusted, unit, decide, verify, run.stderr))

    def test_actual_choose_shell_refuses_fork_and_behind_main_and_uses_main(self):
        step = self.step('decide', 'Trusted main selection, bootstrap runs full')
        self.git('remote', 'add', 'origin', str(self.repo))
        output = self.repo/'job-output'
        summary = self.repo/'job-summary'
        env = dict(HEAD_SHA=self.base, HEAD_REPO='owner/repo', REPOSITORY='owner/repo',
                   GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary))
        run = self.shell(step['run'], **env)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('"reason":"bootstrap"', output.read_text())
        self.assertNotEqual(self.shell(step['run'], **{**env, 'HEAD_REPO':'fork/repo'}).returncode, 0)
        original = self.base
        self.write('scripts/verify.sh', 'later\n')
        self.base = self.commit()
        self.assertNotEqual(self.shell(step['run'], **{**env, 'HEAD_SHA':original}).returncode, 0)
        # Candidate classifier must not be used by main's decision shell.
        self.write('.github/vm_selection.py', 'raise SystemExit("PR classifier reached")\n')
        head = self.commit()
        self.git('checkout', '--detach', self.base)
        run = self.shell(step['run'], **{**env, 'HEAD_SHA':head})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn('PR classifier reached', run.stderr)
