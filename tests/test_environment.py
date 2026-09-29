import json
from pathlib import Path
import shutil
import tempfile
import unittest

from agentshield import EnvironmentConfig, load_environment
from agentshield.models import AccessLevel, Role


class EnvironmentTests(unittest.TestCase):
    def test_fixture_coverage_and_relationships(self):
        environment = load_environment()
        self.assertEqual({user.role for user in environment.users.values()}, set(Role))
        self.assertEqual({doc.access_level for doc in environment.documents.values()}, set(AccessLevel))
        self.assertGreater(len(environment.customers), 0)
        for user in environment.users.values():
            self.assertIn(user.employee_id, environment.employees)
        for record in list(environment.employees.values()) + list(environment.customers.values()):
            self.assertTrue(record.email.endswith("@example.invalid"))
        self.assertEqual(environment.tickets, {})

    def test_loads_are_independent(self):
        first, second = load_environment(), load_environment()
        first.documents.clear()
        self.assertTrue(second.documents)

    def fixture_copy(self, directory):
        destination = Path(directory) / "fixtures"
        shutil.copytree(EnvironmentConfig().data_dir, destination)
        return destination

    def test_custom_data_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture_copy(directory)
            (path / "customers.json").write_text("[]", encoding="utf-8")
            self.assertEqual(load_environment(EnvironmentConfig(path)).customers, {})

    def test_missing_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                load_environment(EnvironmentConfig(Path(directory)))

    def test_invalid_fixtures(self):
        cases = [
            ("users.json", [{"id": "bad", "employee_id": "employee-001", "role": "owner"}]),
            ("users.json", [{"id": "bad", "employee_id": "missing", "role": "employee"}]),
            ("documents.json", [{"id": "bad", "title": "Demo", "content": "Demo", "access_level": "unknown"}]),
            ("customers.json", {}),
        ]
        for filename, content in cases:
            with self.subTest(filename=filename, content=content), tempfile.TemporaryDirectory() as directory:
                path = self.fixture_copy(directory)
                (path / filename).write_text(json.dumps(content), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_environment(EnvironmentConfig(path))

    def test_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture_copy(directory)
            fixture = path / "customers.json"
            records = json.loads(fixture.read_text(encoding="utf-8"))
            fixture.write_text(json.dumps(records + records), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate ID"):
                load_environment(EnvironmentConfig(path))


if __name__ == "__main__":
    unittest.main()
