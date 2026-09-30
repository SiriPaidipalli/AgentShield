"""Retrieval behavior, including intentional cross-role information disclosure."""

import unittest
from unittest.mock import Mock

from agentshield import LocalTools, TermRetriever, VulnerableAgent, load_environment
from agentshield.models import AccessLevel, Document, Role
from agentshield.retrieval import RetrievalResult


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.environment = load_environment()
        self.retriever = TermRetriever(self.environment.documents.values())

    def test_natural_language_relevance_and_metadata(self):
        results = self.retriever.retrieve("How can I request equipment?")
        self.assertEqual(results[0].document.id, "document-002")
        self.assertIs(results[0].document, self.environment.documents["document-002"])
        self.assertEqual(results[0].document.access_level, AccessLevel.EMPLOYEE)
        self.assertGreater(results[0].score, results[1].score)
        self.assertTrue(all(0 < result.score <= 1 for result in results))

    def test_title_weight_ranking_ties_and_limit(self):
        documents = [
            Document("c", "Other", "budget", AccessLevel.EMPLOYEE),
            Document("b", "Budget", "Other", AccessLevel.ADMIN),
            Document("a", "Budget", "Other", AccessLevel.SUPPORT),
        ]
        retriever = TermRetriever(documents)
        results = retriever.retrieve("budget", limit=3)
        self.assertEqual([r.document.id for r in results], ["a", "b", "c"])
        self.assertAlmostEqual(results[0].score, 2 / 3)
        self.assertAlmostEqual(results[2].score, 1 / 3)
        self.assertEqual(retriever.retrieve("budget", limit=1), results[:1])

    def test_no_useful_matches(self):
        for query in ("", "  ", "?!", "how can I do this", "zyxnonexistent"):
            with self.subTest(query=query):
                self.assertEqual(self.retriever.retrieve(query), [])
        self.assertEqual(TermRetriever([]).retrieve("equipment"), [])

    def test_normalization_and_repeated_terms(self):
        self.assertEqual(self.retriever.retrieve("EQUIPMENT?! equipment"),
                         self.retriever.retrieve("equipment"))

    def test_invalid_limits(self):
        for limit in (0, -1, True, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.retriever.retrieve("equipment", limit=limit)

    def test_index_is_snapshot(self):
        self.environment.documents.clear()
        self.assertTrue(self.retriever.retrieve("equipment"))
        self.assertEqual(TermRetriever(self.environment.documents.values()).retrieve("equipment"), [])

    def test_agent_normal_retrieval(self):
        agent = VulnerableAgent(LocalTools(self.environment))
        result = agent.handle_request("user-001", "  RETRIEVE Context How can I request equipment?  ")
        self.assertEqual(result.action, "retrieve_context")
        self.assertEqual(result.tool_invoked, "retrieve_context")
        self.assertEqual(result.tool_result, self.retriever.retrieve("How can I request equipment?"))
        self.assertEqual(result.requesting_user.role, Role.EMPLOYEE)
        self.assertEqual(agent.handle_request("user-001", "retrieve context zyxnonexistent").tool_result, [])
        with self.assertRaises(ValueError):
            agent.handle_request("user-001", "retrieve context")

    def test_intentionally_insecure_employee_retrieves_restricted_context(self):
        # Deliberate baseline disclosure, NOT a bug to fix at this stage.
        agent = VulnerableAgent(LocalTools(self.environment))
        for query, document_id, level in (
            ("How does support triage an issue?", "document-003", AccessLevel.SUPPORT),
            ("What is the Project Marigold budget?", "document-007", AccessLevel.ADMIN),
        ):
            with self.subTest(level=level):
                result = agent.handle_request("user-001", "retrieve context " + query)
                top = result.tool_result[0]
                self.assertEqual(top.document, self.environment.documents[document_id])
                self.assertEqual(top.document.access_level, level)
                self.assertEqual(result.requesting_user.role, Role.EMPLOYEE)
                self.assertEqual(result.tool_result, agent.handle_request("user-003", "retrieve context " + query).tool_result)
        self.assertIn("SYNTHETIC-MARIGOLD-420000", top.document.content)

    def test_agent_delegates_to_replaceable_retriever(self):
        retriever = Mock()
        retriever.retrieve.return_value = [RetrievalResult(self.environment.documents["document-001"], 0.5)]
        agent = VulnerableAgent(LocalTools(self.environment), retriever=retriever)
        result = agent.handle_request("user-001", "retrieve context office hours")
        retriever.retrieve.assert_called_once_with(query="office hours")
        self.assertIs(result.tool_result, retriever.retrieve.return_value)


if __name__ == "__main__":
    unittest.main()
