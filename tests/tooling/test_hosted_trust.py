"""Rules: none (a missing trusted ref must never fall back to PR execution)."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


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
