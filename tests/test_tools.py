import unittest

from agentshield import LocalTools, load_environment
from agentshield.models import AccessLevel


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.environment = load_environment()
        self.tools = LocalTools(self.environment)

    def test_search_title_and_content_case_insensitive(self):
        self.assertEqual([doc.id for doc in self.tools.search_documents("  EMPLOYEE HANDBOOK  ")], ["document-001"])
        self.assertEqual([doc.id for doc in self.tools.search_documents("fictional workstations")], ["document-006"])
        self.assertEqual([doc.id for doc in self.tools.search_documents("queue")], ["document-004"])

    def test_search_empty_and_missing(self):
        for query in ("", "   ", "nonexistent-term"):
            with self.subTest(query=query):
                self.assertEqual(self.tools.search_documents(query), [])

    def test_access_labels_are_metadata_only(self):
        self.assertEqual(self.tools.search_documents("triage")[0].access_level, AccessLevel.SUPPORT)
        self.assertEqual(self.tools.search_documents("maintenance")[0].access_level, AccessLevel.ADMIN)

    def test_record_lookups(self):
        self.assertEqual(self.tools.get_employee("employee-001").name, "Demo Employee One")
        self.assertEqual(self.tools.get_customer("customer-001").company, "Synthetic Orchard Labs")
        self.assertIsNone(self.tools.get_employee("missing"))
        self.assertIsNone(self.tools.get_customer("missing"))

    def test_create_tickets_and_share_environment(self):
        first = self.tools.create_ticket("user-001", " Equipment ", " Demo monitor ")
        second = LocalTools(self.environment).create_ticket("customer-001", "Demo issue", "Demo details")
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(first.status, "open")
        self.assertEqual(first.subject, "Equipment")
        self.assertEqual(first.description, "Demo monitor")
        self.assertEqual(second.requester_id, "customer-001")
        self.assertEqual(self.environment.tickets, {first.id: first, second.id: second})
        self.assertEqual(load_environment().tickets, {})

    def test_invalid_ticket_leaves_state_unchanged(self):
        for args in (("missing", "Demo", "Demo"), ("user-001", " ", "Demo"), ("customer-001", "Demo", "")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.tools.create_ticket(*args)
        self.assertEqual(self.environment.tickets, {})


if __name__ == "__main__":
    unittest.main()
