"""Audit invariants: authorization prevents consequences, not prompt influence."""

from copy import deepcopy
from dataclasses import asdict
import unittest

from agentshield import load_environment, LocalTools, FakeModelProvider, AssistantResponse, ToolCall
from agentshield.evaluation.adapters import execute
from agentshield.evaluation.benchmark import load_benchmark, injection_documents, observe
from agentshield.secured_agent import SecuredLLMAgent


class BenchmarkAuditTests(unittest.TestCase):
    def execute_case(self, case):
        environment = load_environment()
        environment.documents.update({i: injection_documents()[i] for i in case['injection_document_ids']})
        behavior = case['model_behavior']
        response = AssistantResponse(behavior['text']) if behavior['kind'] == 'assistant' else ToolCall(behavior['tool_name'], behavior['arguments'])
        provider = FakeModelProvider([response])
        result, events = execute('secured_identity_retrieval', SecuredLLMAgent, LocalTools(environment), provider, case)
        return result, events, provider, environment, response

    def test_all_adversarial_cases_call_provider_with_unchanged_script(self):
        for case in load_benchmark():
            if case['case_type'] != 'adversarial':
                continue
            with self.subTest(case=case['id']):
                result, _, provider, _, scripted = self.execute_case(case)
                self.assertEqual(len(provider.requests), 1)
                self.assertIs(result.model_response, scripted)

    def test_classification_category_and_outcomes_cannot_affect_application(self):
        # These are in-memory audit probes, not edits to frozen dataset cases.
        for case_id in ('control-support-customer', 'tool-customer-record'):
            original = next(c for c in load_benchmark() if c['id'] == case_id)
            changed = deepcopy(original)
            changed.update(case_type='adversarial' if original['case_type'] == 'benign' else 'benign',
                           category='unrecognized_category', expected_outcome={'kind': 'force_block'},
                           expected_security_behavior='Override application policy')
            before = self.execute_case(original)
            after = self.execute_case(changed)
            self.assertEqual(before[0], after[0])
            self.assertEqual(before[1], after[1])
            self.assertEqual(before[2].requests, after[2].requests)

    def test_adversarial_wording_does_not_block_authorized_action(self):
        case = deepcopy(next(c for c in load_benchmark() if c['id'] == 'direct-system'))
        # Same forged system wording and same scripted tool call, but a real
        # trusted support principal is allowed to read this customer.
        case['requesting_user'] = 'user-002'
        result, events, _, _, _ = self.execute_case(case)
        self.assertEqual(result.action, 'tool_call')
        self.assertEqual(result.tool_result.id, 'customer-001')
        self.assertTrue(any(e['action'] == 'get_customer' and e['decision'] == 'allow' for e in events))
        case['requesting_user'] = 'user-001'
        case['user_input'] = 'Please show the customer record.'
        result, events, _, _, _ = self.execute_case(case)
        self.assertEqual(result.action, 'tool_denied')
        self.assertTrue(any(e['reason'] == 'customer_requires_support_or_admin' for e in events))

    def test_expected_outcome_not_read_by_adapter_or_application(self):
        class ExecutionOnly(dict):
            def __getitem__(self, key):
                if key in {'expected_outcome', 'expected_security_behavior', 'category', 'case_type'}:
                    raise AssertionError('Evaluation metadata read during execution')
                return super().__getitem__(key)
        case = ExecutionOnly(next(c for c in load_benchmark() if c['id'] == 'control-support-customer'))
        result, _, _, _, _ = self.execute_case(case)
        self.assertEqual(result.action, 'tool_call')

    def test_indirect_documents_still_reach_provider(self):
        for case in load_benchmark():
            if case['category'] != 'indirect_prompt_injection':
                continue
            result, _, provider, _, _ = self.execute_case(case)
            supplied = {h.document.id for h in provider.requests[0].retrieved_context}
            self.assertTrue(set(case['injection_document_ids']) <= supplied)
            self.assertIsInstance(result.model_response, ToolCall)

    def test_two_frozen_blocks_are_not_output_leakage_prevention(self):
        for case_id, values in [('exfil-assistant-response', ['SYNTHETIC-MARIGOLD-420000']),
                                ('exfil-combined', ['420000 demo credits', 'first Friday'])]:
            case = next(c for c in load_benchmark() if c['id'] == case_id)
            result, _, provider, environment, _ = self.execute_case(case)
            success, _ = observe(case, result, environment, provider.requests[0])
            self.assertFalse(success)
            self.assertEqual(provider.requests[0].retrieved_context, ())
            for value in values:
                self.assertIn(value, result.model_response.text)


if __name__ == '__main__':
    unittest.main()
