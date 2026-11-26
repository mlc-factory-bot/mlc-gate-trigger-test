"""Rules: none (trusted-main VM selection and required result contract)."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / '.github/vm_selection.py'


class VMSelection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.write('docs/corpus-analysis/catalogue-gap.md', 'old\n')
        self.write('scripts/verify.sh', 'true\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True).strip()

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '-qm', 'change')
        return self.git('rev-parse', 'HEAD')

    def invoke(self, *args):
        return subprocess.run(['python3', '-I', str(SCRIPT), *args], text=True,
                              capture_output=True)

    def policy(self):
        run = self.invoke('fingerprint', '--repo', str(self.repo), '--ref', self.base)
        self.assertEqual(run.returncode, 0, run.stderr)
        path = self.repo / 'policy.json'
        path.write_text(json.dumps({'version': 1, 'consumer_fingerprint': run.stdout.strip()}))
        return path

    def decide(self, target, policy=None, **changes):
        args = {'repo': str(self.repo), 'base': self.base, 'head': target,
                'head-repo': 'owner/repo', 'repository': 'owner/repo',
                'policy': str(policy or self.policy())}
        args.update(changes)
        return self.invoke('decide', *[part for k, v in args.items() for part in ('--'+k, v)])

    def test_existing_regular_allowlisted_modification_can_skip(self):
        self.write('docs/corpus-analysis/catalogue-gap.md', 'new\n')
        run = self.decide(self.commit())
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)['action'], 'skip')

    def test_unknown_mixed_and_protected_markdown_run(self):
        for name in ('scripts/verify.sh', 'docs/decisions/README.md',
                     '.github/workflows/vm-verify.yml', 'missions/x/SPEC.md'):
            with self.subTest(path=name):
                self.git('reset', '--hard', self.base)
                self.write(name, 'new\n')
                run = self.decide(self.commit())
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(run.stdout)['action'], 'run')

    def test_add_delete_rename_and_executable_modes_run(self):
        name = 'docs/corpus-analysis/catalogue-gap.md'
        for kind in ('add', 'delete', 'rename', 'mode'):
            with self.subTest(kind=kind):
                self.git('reset', '--hard', self.base)
                if kind == 'add':
                    self.write('docs/corpus-analysis/model-fit.md', 'new\n')
                elif kind == 'delete':
                    (self.repo/name).unlink()
                elif kind == 'rename':
                    (self.repo/name).rename(self.repo/'docs/corpus-analysis/model-fit.md')
                else:
                    (self.repo/name).chmod(0o755)
                run = self.decide(self.commit())
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(run.stdout)['action'], 'run')

    def test_new_main_consumer_invalidates_policy(self):
        policy = self.policy()
        self.write('scripts/consumer.py', "open('docs/corpus-analysis/catalogue-gap.md')\n")
        self.base = self.commit()
        self.write('docs/corpus-analysis/catalogue-gap.md', 'new\n')
        run = self.decide(self.commit(), policy)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)['action'], 'run')

    def test_symlink_and_nonallowlisted_rename_run(self):
        name = self.repo/'docs/corpus-analysis/catalogue-gap.md'
        name.unlink()
        name.symlink_to('../../scripts/verify.sh')
        run = self.decide(self.commit())
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)['action'], 'run')

    def test_behind_main_and_bad_policy_refused(self):
        original = self.base
        self.write('scripts/verify.sh', 'new\n')
        self.base = self.commit()
        self.assertNotEqual(self.decide(original).returncode, 0)
        policy = self.repo/'bad-policy.json'
        policy.write_text('{')
        self.assertNotEqual(self.decide(self.base, policy).returncode, 0)

    def test_mixed_allowlisted_and_code_runs(self):
        self.write('docs/corpus-analysis/catalogue-gap.md', 'new\n')
        self.write('scripts/verify.sh', 'false\n')
        run = self.decide(self.commit())
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)['action'], 'run')

    def test_invalid_identity_and_objects_fail(self):
        for changes in ({'head-repo': 'attacker/fork'}, {'head': 'a'*40},
                        {'base': 'not-a-commit'}):
            run = self.decide(self.base, **changes)
            self.assertNotEqual(run.returncode, 0)

    def test_actual_result_entrypoint_fails_closed(self):
        self.write('docs/corpus-analysis/catalogue-gap.md', 'new\n')
        head = self.commit()
        decision = self.decide(head)
        self.assertEqual(decision.returncode, 0, decision.stderr)
        for decide in ('success', 'failure', 'cancelled', 'skipped', ''):
            for verify in ('success', 'failure', 'cancelled', 'skipped', ''):
                run = self.invoke('result', '--decision', decision.stdout,
                                  '--decide-result', decide, '--verify-result', verify,
                                  '--head', head, '--base', self.base)
                self.assertEqual(run.returncode == 0,
                                 decide == 'success' and verify == 'skipped')

    def test_run_result_and_tampered_decision_fail_closed(self):
        decision = self.decide(self.base)
        self.assertEqual(decision.returncode, 0, decision.stderr)
        data = json.loads(decision.stdout)
        for state in ('success', 'failure', 'cancelled', 'skipped', ''):
            run = self.invoke('result', '--decision', decision.stdout,
                              '--decide-result', 'success', '--verify-result', state,
                              '--head', self.base, '--base', self.base)
            self.assertEqual(run.returncode == 0, state == 'success')
        for change in ({'head': 'a'*40}, {'paths': [] , 'action': 'skip'},
                       {'action': 'skip', 'reason': 'known-non-inputs',
                        'paths': ['scripts/verify.sh']}, {'version': 2}):
            run = self.invoke('result', '--decision', json.dumps({**data, **change}),
                              '--decide-result', 'success', '--verify-result',
                              'success' if change.get('action', data['action']) == 'run' else 'skipped',
                              '--head', self.base, '--base', self.base)
            self.assertNotEqual(run.returncode, 0)


if __name__ == '__main__':
    unittest.main()
