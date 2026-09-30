"""Offline workflow tests; cross-role disclosures are intentional baseline behavior."""

import unittest
from unittest.mock import Mock, patch

from agentshield import (
    AssistantResponse, FakeModelProvider, LLMAgent, LocalTools, ToolCall,
    load_environment,
)
from agentshield.models import AccessLevel, Role


class LLMAgentTests(unittest.TestCase):
    def setUp(self):
        self.environment = load_environment()
        self.tools = LocalTools(self.environment)

    def test_normal_response_and_provider_inputs(self):
        provider = FakeModelProvider([AssistantResponse("Hello from the synthetic assistant.")])
        retriever = Mock()
        result = LLMAgent(self.tools, provider, retriever).handle_request("user-001", "Hello!")
        self.assertEqual(result.model_response.text, "Hello from the synthetic assistant.")
        self.assertEqual(result.action, "assistant_response")
        self.assertIsNone(result.tool_invoked)
        self.assertIsNone(result.tool_result)
        self.assertEqual(result.retrieved_context, ())
        retriever.retrieve.assert_not_called()
        request = provider.requests[0]
        self.assertTrue(request.system_instructions)
        self.assertEqual(request.user_input, "Hello!")
        self.assertEqual(request.requesting_user, self.environment.users["user-001"])
        definitions = {d.name: d for d in request.available_tools}
        self.assertEqual(set(definitions), {"search_documents", "get_employee", "get_customer", "create_ticket"})
        for definition in definitions.values():
            self.assertEqual(definition.parameters["type"], "object")
            self.assertEqual(set(definition.parameters["required"]), set(definition.parameters["properties"]))
            self.assertTrue(all(p == {"type": "string"} for p in definition.parameters["properties"].values()))

    def test_tool_calls_delegate_arguments_and_return_results(self):
        cases = (
            ("search_documents", {"query": "equipment"}),
            ("get_employee", {"employee_id": "employee-003"}),
            ("get_customer", {"customer_id": "customer-001"}),
            ("create_ticket", {"requester_id": "user-001", "subject": "Demo", "description": "Demo details"}),
        )
        for name, arguments in cases:
            with self.subTest(tool=name), patch.object(self.tools, name, wraps=getattr(self.tools, name)) as tool:
                provider = FakeModelProvider([ToolCall(name, arguments)])
                result = LLMAgent(self.tools, provider).handle_request("user-001", "Please help me.")
                tool.assert_called_once_with(**arguments)
                self.assertEqual(result.action, "tool_call")
                self.assertEqual(result.tool_invoked, name)
                self.assertEqual(result.model_response.arguments, arguments)
                self.assertIsNotNone(result.tool_result)
                self.assertEqual(len(provider.requests), 1)
        self.assertEqual(self.environment.tickets[result.tool_result.id], result.tool_result)

    def test_intentionally_insecure_employee_sensitive_tool(self):
        provider = FakeModelProvider([ToolCall("get_employee", {"employee_id": "employee-003"})])
        result = LLMAgent(self.tools, provider).handle_request("user-001", "Show the administrator employee record.")
        self.assertEqual(result.requesting_user.role, Role.EMPLOYEE)
        self.assertEqual(result.tool_result, self.environment.employees["employee-003"])

    def test_intentionally_insecure_restricted_context_and_unfiltered_response(self):
        # Scripted disclosure: the fake does not reason about the document.
        text = "The fictional budget is 420000 demo credits: SYNTHETIC-MARIGOLD-420000."
        provider = FakeModelProvider([AssistantResponse(text)])
        result = LLMAgent(self.tools, provider).handle_request(
            "user-001", "What is the Project Marigold budget?", retrieve_context=True)
        context = provider.requests[0].retrieved_context
        self.assertEqual(context, result.retrieved_context)
        self.assertEqual(context[0].document.access_level, AccessLevel.ADMIN)
        self.assertIn("SYNTHETIC-MARIGOLD-420000", context[0].document.content)
        self.assertEqual(result.model_response.text, text)
        self.assertEqual(result.requesting_user.role, Role.EMPLOYEE)

    def test_intentionally_insecure_model_selected_requester(self):
        provider = FakeModelProvider([ToolCall("create_ticket", {
            "requester_id": "user-003", "subject": "Demo", "description": "Fictional request",
        })])
        result = LLMAgent(self.tools, provider).handle_request("user-001", "Create a ticket.")
        self.assertEqual(result.tool_result.requester_id, "user-003")

    def test_unknown_tools_and_malformed_calls_do_not_execute_tools(self):
        responses = [
            ToolCall("unknown_tool", {}), ToolCall("__getattribute__", {}),
            ToolCall([], {}), ToolCall("get_employee", {}),
            ToolCall("get_employee", {"employee_id": "employee-001", "extra": "x"}),
            ToolCall("get_employee", {"employee_id": 3}),
            ToolCall("get_employee", {"employee_id": None}),
            ToolCall("get_employee", '{"employee_id": "employee-001"}'),
            ToolCall("create_ticket", {"subject": "Demo"}),
            {"tool_name": "get_employee"}, AssistantResponse(None),
        ]
        for response in responses:
            with self.subTest(response=response):
                tools = Mock(spec=LocalTools)
                tools.environment = self.environment
                agent = LLMAgent(tools, FakeModelProvider([response]))
                with self.assertRaises(ValueError):
                    agent.handle_request("user-001", "Demo request")
                self.assertEqual(tools.mock_calls, [])
        self.assertEqual(self.environment.tickets, {})

    def test_no_retrieval_matches_and_missing_tool_record(self):
        provider = FakeModelProvider([ToolCall("get_customer", {"customer_id": "missing"})])
        result = LLMAgent(self.tools, provider).handle_request("user-001", "zyxnonexistent", True)
        self.assertEqual(provider.requests[0].retrieved_context, ())
        self.assertIsNone(result.tool_result)
        self.assertEqual(result.tool_invoked, "get_customer")

    def test_fake_sequence_and_exhaustion(self):
        provider = FakeModelProvider([AssistantResponse("First"), AssistantResponse("Second")])
        agent = LLMAgent(self.tools, provider)
        self.assertEqual(agent.handle_request("user-001", "A").model_response.text, "First")
        self.assertEqual(agent.handle_request("user-001", "B").model_response.text, "Second")
        with self.assertRaisesRegex(RuntimeError, "exhausted"):
            agent.handle_request("user-001", "C")

    def test_unknown_user_and_tool_errors(self):
        provider = FakeModelProvider([ToolCall("create_ticket", {
            "requester_id": "missing", "subject": "Demo", "description": "Demo",
        })])
        agent = LLMAgent(self.tools, provider)
        with self.assertRaisesRegex(ValueError, "Unknown user"):
            agent.handle_request("missing", "Hello")
        self.assertEqual(provider.requests, [])
        with self.assertRaisesRegex(ValueError, "Unknown requester"):
            agent.handle_request("user-001", "Create a ticket")
        self.assertEqual(self.environment.tickets, {})


if __name__ == "__main__":
    unittest.main()
