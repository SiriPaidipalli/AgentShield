"""Explicit implementation selection and execution-integrity regression tests."""

from dataclasses import replace
from contextlib import redirect_stdout
from io import StringIO
import unittest
from unittest.mock import patch

from agentshield.evaluation.benchmark import compare_benchmark, load_benchmark, main, run_benchmark_case
from agentshield.secured_agent import SecuredLLMAgent


class EvaluationModeTests(unittest.TestCase):
    def test_same_definitions_and_comparison(self):
        comparison = compare_benchmark()
        cases = load_benchmark()
        for mode in ('vulnerable', 'secured_identity_retrieval'):
            report = comparison[mode]
            self.assertEqual(report['mode'], mode)
            for definition, outcome in zip(cases, report['cases']):
                for key, value in definition.items():
                    self.assertEqual(outcome[key], value)
            self.assertEqual(report['benign']['successful_legitimate_operations'], 8)
            self.assertEqual(report['adversarial']['evaluation_errors'], 0)
        self.assertEqual(comparison['vulnerable']['adversarial']['successful_attacks'], 24)
        self.assertEqual(comparison['secured_identity_retrieval']['adversarial']['successful_attacks'], 14)
        self.assertEqual(len(comparison['changed_cases']), 10)

    def test_secured_adapter_invokes_real_controls(self):
        cases = {c['id']: c for c in load_benchmark()}
        original = SecuredLLMAgent.handle_request
        with patch.object(SecuredLLMAgent, 'handle_request', autospec=True, side_effect=original) as handle:
            retrieval = run_benchmark_case(cases['retrieve-admin'], mode='secured_identity_retrieval')
            identity = run_benchmark_case(cases['identity-ticket-requester'], mode='secured_identity_retrieval')
        self.assertEqual(handle.call_count, 2)
        self.assertEqual(retrieval['status'], 'ATTACK_BLOCKED')
        self.assertEqual(identity['status'], 'ATTACK_BLOCKED')
        self.assertTrue(any(e['reason'] == 'access_level_denied' for e in retrieval['security_events']))
        self.assertTrue(any(e['reason'] == 'requester_substitution_denied' for e in identity['security_events']))

    def test_missing_malformed_and_exceptional_results_are_errors(self):
        case = next(c for c in load_benchmark() if c['id'] == 'tool-customer-record')
        original = SecuredLLMAgent.handle_request
        def broken(agent, *args):
            return replace(original(agent, *args), tool_result=None)
        for replacement in (lambda *args: None, broken, lambda *args: object()):
            with patch.object(SecuredLLMAgent, 'handle_request', replacement):
                self.assertEqual(run_benchmark_case(case, mode='secured_identity_retrieval')['status'], 'EVALUATION_ERROR')
        with patch.object(SecuredLLMAgent, 'handle_request', side_effect=RuntimeError('test failure')):
            self.assertEqual(run_benchmark_case(case, mode='secured_identity_retrieval')['status'], 'EVALUATION_ERROR')

    def test_cli_default_modes_alias_and_comparison(self):
        for flags, heading in [([], '(secured_identity_retrieval)'),
                               (['--secured'], '(secured_identity_retrieval)'),
                               (['--mode', 'vulnerable'], '(vulnerable)'),
                               (['--mode', 'secured_identity_retrieval'], '(secured_identity_retrieval)'),
                               (['--compare'], 'Changed outcomes:')]:
            with self.subTest(flags=flags), patch('sys.argv', ['benchmark'] + flags), redirect_stdout(StringIO()) as output:
                self.assertEqual(main(), 0)
                self.assertIn(heading, output.getvalue())


if __name__ == '__main__':
    unittest.main()
