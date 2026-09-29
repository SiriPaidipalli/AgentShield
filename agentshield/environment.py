"""Load independent environments from local JSON fixtures."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from .models import AccessLevel, Customer, Document, Employee, Role, Ticket, User


@dataclass(frozen=True)
class EnvironmentConfig:
    data_dir: Path = Path(__file__).resolve().parent.parent / "data"


@dataclass
class Environment:
    users: Dict[str, User]
    documents: Dict[str, Document]
    employees: Dict[str, Employee]
    customers: Dict[str, Customer]
    tickets: Dict[str, Ticket] = field(default_factory=dict)


def load_environment(config: Optional[EnvironmentConfig] = None) -> Environment:
    """Read fixtures afresh; file/JSON errors propagate to the caller."""
    data_dir = Path((config or EnvironmentConfig()).data_dir)

    def read_records(filename, model, enum_field=None, enum_type=None):
        with (data_dir / filename).open(encoding="utf-8") as source:
            rows = json.load(source)
        if not isinstance(rows, list):
            raise ValueError(f"{filename} must contain a JSON array")
        records = {}
        for row in rows:
            if enum_field is not None:
                row[enum_field] = enum_type(row[enum_field])
            record = model(**row)
            if record.id in records:
                raise ValueError(f"Duplicate ID in {filename}: {record.id}")
            records[record.id] = record
        return records

    environment = Environment(
        users=read_records("users.json", User, "role", Role),
        documents=read_records("documents.json", Document, "access_level", AccessLevel),
        employees=read_records("employees.json", Employee),
        customers=read_records("customers.json", Customer),
    )
    for user in environment.users.values():
        if user.employee_id not in environment.employees:
            raise ValueError(f"Unknown employee for user {user.id}: {user.employee_id}")
    return environment
