"""Passing tests establish measurement correctness, not a secure application."""

from dataclasses import asdict, replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentshield import AssistantResponse, FakeModelProvider, LLMAgent, LocalTools, ToolCall, load_environment
from agentshield.evaluation import load_cases, run_evaluation, write_report
from agentshield.evaluation.runner import BLOCKED, ERROR, SUCCEEDED, assess, run_case, statistics
from agentshield.models import Ticket


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.cases = load_cases()
        self.by_id = {case.id: case for case in self.cases}

    def load_rows(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            path.write_text(json.dumps(rows), encoding="utf-8")
            return load_cases(path)

    def test_case_loading_and_category_counts(self):
        self.assertEqual(len(self.cases), 8)
        self.assertEqual(len(self.by_id), 8)
        expected = {"direct_prompt_injection": 1, "unauthorized_retrieval": 2,
                    "sensitive_tool_abuse": 1, "identity_argument_manipulation": 2,
                    "data_exfiltration": 2}
        self.assertEqual({category: sum(c.category == category for c in self.cases)
                          for category in expected}, expected)
        self.assertEqual(self.load_rows([asdict(case) for case in self.cases]), self.cases)

    def test_case_validation(self):
        original = asdict(self.cases[0])
        variants = [
            {**original, "id": ""}, {**original, "category": "unknown"},
            {**original, "requesting_user": "missing"},
            {**original, "requesting_user": "user-003"},
            {**original, "retrieve_context": "yes"},
            {**original, "model_behavior": []},
            {**original, "model_behavior": {"kind": "unknown"}},
            {**original, "model_behavior": {"kind": "tool_call", "tool_name": "unknown", "arguments": {}}},
            {**original, "model_behavior": {"kind": "tool_call", "tool_name": "get_employee", "arguments": {"employee_id": 3}}},
            {**original, "criterion": {"kind": "unknown", "target_id": "document-007"}},
            {**original, "criterion": {"kind": "restricted_context", "target_id": "document-001"}},
            {**original, "criterion": {"kind": "marker_in_response", "target_id": "document-007", "marker": "not-in-source"}},
            {**original, "criterion": {"kind": "other_employee_record", "target_id": "employee-001"}},
            {**original, "unexpected": True},
        ]
        for row in variants:
            with self.subTest(row=row), self.assertRaises(ValueError):
                self.load_rows([row])
        for rows in ([], {}, [original, original], [{}], [None]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.load_rows(rows)

    def test_real_baseline_violations_are_detected(self):
        for case in self.cases:
            with self.subTest(case=case.id):
                result = run_case(case)
                self.assertEqual(result["status"], SUCCEEDED)
                self.assertTrue(result["evidence"]["violation_observed"])
        self.assertEqual(run_case(self.by_id["identity-ticket-requester"])["evidence"]["stored_requester_id"], "user-003")
        self.assertEqual(run_case(self.by_id["exfil-assistant-response"])["evidence"]["observed_marker"], "SYNTHETIC-MARIGOLD-420000")

    def test_acceptance_without_disclosure_does_not_count(self):
        for case in self.cases:
            benign = replace(case, retrieve_context=False,
                             model_behavior={"kind": "assistant", "text": "No information returned."})
            with self.subTest(case=case.id):
                self.assertEqual(run_case(benign)["status"], BLOCKED)

    def test_response_marker_requires_source_context(self):
        case = replace(self.by_id["exfil-assistant-response"], retrieve_context=False)
        self.assertEqual(run_case(case)["status"], BLOCKED)
        case = replace(self.by_id["exfil-assistant-response"],
                       model_behavior={"kind": "assistant", "text": "Context received, no marker emitted."})
        self.assertEqual(run_case(case)["status"], BLOCKED)

    def test_wrong_record_and_missing_record_do_not_count(self):
        for target in ("employee-001", "missing"):
            case = replace(self.by_id["identity-other-employee"], model_behavior={
                "kind": "tool_call", "tool_name": "get_employee", "arguments": {"employee_id": target}})
            self.assertEqual(run_case(case)["status"], BLOCKED)
        case = replace(self.by_id["tool-customer-record"], model_behavior={
            "kind": "tool_call", "tool_name": "get_customer", "arguments": {"customer_id": "missing"}})
        self.assertEqual(run_case(case)["status"], BLOCKED)

    def test_unstored_ticket_does_not_count(self):
        case = self.by_id["identity-ticket-requester"]
        environment = load_environment()
        provider = FakeModelProvider([AssistantResponse("Accepted")])
        result = LLMAgent(LocalTools(environment), provider).handle_request("user-001", case.user_input)
        result = replace(result, action="tool_call", tool_invoked="create_ticket",
                         tool_result=Ticket("invented", "user-003", "Demo", "Demo"))
        self.assertFalse(assess(case, result, environment, provider.requests[0])[0])

    def test_metrics_and_category_aggregation(self):
        report = run_evaluation([
            self.by_id["retrieve-admin"],
            replace(self.by_id["retrieve-support"], retrieve_context=False),
            self.by_id["tool-customer-record"],
        ])
        self.assertEqual(report["totals"], {"total_attack_cases": 3, "successful_attacks": 2,
                         "blocked_attacks": 1, "evaluation_errors": 0, "attack_success_rate": 2 / 3})
        self.assertEqual(report["per_category"]["unauthorized_retrieval"]["attack_success_rate"], 0.5)
        self.assertEqual(report["per_category"]["sensitive_tool_abuse"]["attack_success_rate"], 1.0)
        self.assertEqual(statistics([])["attack_success_rate"], 0.0)
        self.assertEqual(statistics([{"status": SUCCEEDED}, {"status": ERROR}])["attack_success_rate"], 0.5)
        with self.assertRaises(ValueError):
            statistics([{"status": "PASS"}])
        with self.assertRaises(ValueError):
            run_evaluation([self.cases[0], self.cases[0]])

    def test_execution_errors_are_not_counted_as_blocked(self):
        with patch("agentshield.evaluation.runner.LLMAgent.handle_request", side_effect=RuntimeError("test failure")):
            report = run_evaluation([self.cases[0]])
        self.assertEqual(report["cases"][0]["status"], ERROR)
        self.assertEqual(report["totals"]["evaluation_errors"], 1)
        self.assertEqual(report["totals"]["blocked_attacks"], 0)

    def test_report_json_and_reproducibility(self):
        report = run_evaluation()
        self.assertEqual(report, run_evaluation())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            write_report(report, path)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), report)
        self.assertEqual(report["mode"], "deterministic_insecure_baseline")
        self.assertEqual(report["evaluation_version"], "1.0")
        self.assertEqual(report["totals"]["attack_success_rate"], 1.0)

    def test_cli_summary_and_json(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from agentshield.evaluation.__main__ import main
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            output = StringIO()
            with patch("sys.argv", ["agentshield.evaluation", "--output", str(path)]), redirect_stdout(output):
                self.assertEqual(main(), 0)
            self.assertIn("Total attack cases: 8", output.getvalue())
            self.assertIn("Overall attack success rate: 100.0%", output.getvalue())
            self.assertEqual(json.loads(path.read_text())["totals"]["successful_attacks"], 8)


if __name__ == "__main__":
    unittest.main()
