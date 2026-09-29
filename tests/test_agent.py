"""Normal behavior and intentional insecure baseline regression tests."""

import unittest
from unittest.mock import patch

from agentshield import LocalTools, VulnerableAgent, load_environment
from agentshield.agent import interpret_request
from agentshield.models import AccessLevel, Role


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.environment = load_environment()
        self.tools = LocalTools(self.environment)
        self.agent = VulnerableAgent(self.tools)

    def test_employee_search_and_structured_result(self):
        result = self.agent.handle_request("user-001", "search documents Employee Handbook")
        self.assertEqual(result.requesting_user, self.environment.users["user-001"])
        self.assertEqual(result.requesting_user.role, Role.EMPLOYEE)
        self.assertEqual(result.action, "search_documents")
        self.assertEqual(result.tool_invoked, "search_documents")
        self.assertEqual([doc.id for doc in result.tool_result], ["document-001"])
        self.assertEqual(result.tool_result[0].access_level, AccessLevel.EMPLOYEE)

    def test_intentionally_insecure_employee_reads_restricted_documents(self):
        # These disclosures are required baseline behavior, not accidental bugs.
        for query, document_id, level in (
            ("Support Triage", "document-003", AccessLevel.SUPPORT),
            ("Admin Maintenance", "document-005", AccessLevel.ADMIN),
        ):
            with self.subTest(level=level):
                result = self.agent.handle_request("user-001", "search documents " + query)
                self.assertEqual(result.tool_result, [self.environment.documents[document_id]])
                self.assertEqual(result.tool_result[0].access_level, level)

    def test_intentionally_insecure_employee_uses_sensitive_record_tools(self):
        # Record retrieval is a future privilege boundary; none is enforced now.
        # An employee can read another employee (the admin) and customer details.
        for request, tool_name, expected in (
            ("get employee employee-003", "get_employee", self.environment.employees["employee-003"]),
            ("get customer customer-001", "get_customer", self.environment.customers["customer-001"]),
        ):
            with self.subTest(tool=tool_name):
                result = self.agent.handle_request("user-001", request)
                self.assertEqual(result.tool_invoked, tool_name)
                self.assertEqual(result.tool_result, expected)

    def test_ticket_creation_uses_requesting_user_and_existing_state(self):
        result = self.agent.handle_request("user-001", "create ticket Demo monitor | Needs replacement")
        self.assertEqual(result.action, "create_ticket")
        self.assertEqual(result.tool_invoked, "create_ticket")
        ticket = result.tool_result
        self.assertEqual(ticket.requester_id, "user-001")
        self.assertEqual(ticket.subject, "Demo monitor")
        self.assertEqual(ticket.description, "Needs replacement")
        self.assertEqual(ticket.status, "open")
        self.assertEqual(self.environment.tickets[ticket.id], ticket)

    def test_all_roles_can_use_all_tools_intentionally(self):
        for user_id in self.environment.users:
            for request in ("search documents Admin", "get employee employee-003",
                            "get customer customer-001", "create ticket Demo | Details"):
                with self.subTest(user=user_id, request=request):
                    self.assertIsNotNone(self.agent.handle_request(user_id, request).tool_result)

    def test_dispatch_delegates_to_existing_tools(self):
        for request, name, arguments in (
            ("search documents Admin", "search_documents", {"query": "Admin"}),
            ("get employee employee-003", "get_employee", {"employee_id": "employee-003"}),
            ("get customer customer-001", "get_customer", {"customer_id": "customer-001"}),
            ("create ticket Demo | Details", "create_ticket",
             {"requester_id": "user-001", "subject": "Demo", "description": "Details"}),
        ):
            with self.subTest(tool=name), patch.object(self.tools, name, wraps=getattr(self.tools, name)) as tool:
                result = self.agent.handle_request("user-001", request)
                tool.assert_called_once_with(**arguments)
                self.assertEqual(result.tool_invoked, name)

    def test_no_matches_and_unknown_records_preserve_tool_behavior(self):
        self.assertEqual(self.agent.handle_request("user-001", "search documents nonexistent-term").tool_result, [])
        for kind in ("employee", "customer"):
            self.assertIsNone(self.agent.handle_request("user-001", f"get {kind} missing").tool_result)

    def test_routing_case_whitespace_and_ticket_separator(self):
        parsed = interpret_request("  SEARCH   Documents Admin Maintenance  ")
        self.assertEqual(parsed.arguments, {"query": "Admin Maintenance"})
        parsed = interpret_request("CREATE ticket Demo | Details | extra")
        self.assertEqual(parsed.arguments, {"subject": "Demo", "description": "Details | extra"})

    def test_malformed_requests_and_unknown_identity(self):
        for request in ("", "do something", "search documents", "get employee",
                        "get customer customer-001 extra", "create ticket Demo",
                        "create ticket | Details", "create ticket Demo | "):
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.agent.handle_request("user-001", request)
        with self.assertRaisesRegex(ValueError, "Unknown user"):
            self.agent.handle_request("missing", "create ticket Demo | Details")
        self.assertEqual(self.environment.tickets, {})


if __name__ == "__main__":
    unittest.main()
