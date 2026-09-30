"""Strict scenario loading; security expectations are evaluator-only assertions."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from ..environment import Environment, load_environment
from ..llm_agent import tool_definitions
from ..models import AccessLevel, Role


CATEGORIES = (
    "direct_prompt_injection", "unauthorized_retrieval", "sensitive_tool_abuse",
    "identity_argument_manipulation", "data_exfiltration",
)
DOCUMENT_CRITERIA = {
    "restricted_tool_document", "restricted_context", "marker_in_response",
    "marker_in_tool_result",
}
CRITERIA = DOCUMENT_CRITERIA | {"customer_record", "other_employee_record", "other_ticket_requester"}


@dataclass(frozen=True)
class AttackCase:
    id: str
    category: str
    description: str
    requesting_user: str
    user_input: str
    expected_security_property: str
    expected_insecure_outcome: str
    retrieve_context: bool
    model_behavior: Dict[str, object]
    criterion: Dict[str, str]


def validate_case(case: AttackCase, environment: Environment) -> None:
    for field in ("id", "category", "description", "requesting_user", "user_input",
                  "expected_security_property", "expected_insecure_outcome"):
        value = getattr(case, field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a nonblank string")
    if case.category not in CATEGORIES or type(case.retrieve_context) is not bool:
        raise ValueError("Invalid category or retrieval flag")
    user = environment.users.get(case.requesting_user)
    if user is None or user.role != Role.EMPLOYEE:
        raise ValueError("Baseline cases require an existing employee user")
    behavior = case.model_behavior
    if not isinstance(behavior, dict):
        raise ValueError("model_behavior must be an object")
    if behavior.get("kind") == "assistant":
        if set(behavior) != {"kind", "text"} or not isinstance(behavior["text"], str):
            raise ValueError("Invalid scripted assistant response")
    elif behavior.get("kind") == "tool_call":
        if set(behavior) != {"kind", "tool_name", "arguments"}:
            raise ValueError("Invalid scripted tool response")
        definitions = {d.name: d for d in tool_definitions()}
        name, args = behavior["tool_name"], behavior["arguments"]
        if not isinstance(name, str) or name not in definitions:
            raise ValueError("Unknown scripted tool")
        if (not isinstance(args, dict) or set(args) != set(definitions[name].parameters["required"])
                or not all(isinstance(value, str) for value in args.values())):
            raise ValueError("Invalid scripted arguments")
    else:
        raise ValueError("Unknown model behavior kind")
    criterion = case.criterion
    if not isinstance(criterion, dict) or not all(isinstance(v, str) for v in criterion.values()):
        raise ValueError("criterion must contain strings")
    kind = criterion.get("kind")
    expected_keys = {"kind", "target_id", "marker"} if kind in {"marker_in_response", "marker_in_tool_result"} else {"kind", "target_id"}
    if kind not in CRITERIA or set(criterion) != expected_keys:
        raise ValueError("Unknown or malformed success criterion")
    target = criterion["target_id"]
    if kind in DOCUMENT_CRITERIA:
        document = environment.documents.get(target)
        if document is None or document.access_level == AccessLevel.EMPLOYEE:
            raise ValueError("Document criterion requires a restricted source document")
        if "marker" in criterion and (not criterion["marker"] or criterion["marker"] not in document.content):
            raise ValueError("Marker must occur in the restricted source")
    elif kind == "customer_record" and target not in environment.customers:
        raise ValueError("Unknown customer target")
    elif kind == "other_employee_record" and (target not in environment.employees or target == user.employee_id):
        raise ValueError("Target must be another employee")
    elif kind == "other_ticket_requester" and (target not in environment.users or target == user.id):
        raise ValueError("Target must be another user")


def load_cases(path: Optional[Path] = None, environment: Optional[Environment] = None) -> List[AttackCase]:
    environment = environment if environment is not None else load_environment()
    with (Path(path) if path is not None else Path(__file__).with_name("cases.json")).open(encoding="utf-8") as source:
        rows = json.load(source)
    if not isinstance(rows, list) or not rows:
        raise ValueError("Cases must be a nonempty JSON array")
    cases = []
    seen = set()
    for row in rows:
        try:
            case = AttackCase(**row)
        except TypeError as error:
            raise ValueError("Invalid attack-case fields") from error
        validate_case(case, environment)
        if case.id in seen:
            raise ValueError(f"Duplicate case ID: {case.id}")
        seen.add(case.id)
        cases.append(case)
    return cases
