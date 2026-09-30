"""Deliberately insecure deterministic agent baseline.

Identity and access labels are descriptive only. There is intentionally no
authentication, authorization, role-based tool restriction, or result filtering.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Union

from .models import Customer, Document, Employee, Ticket, User
from .tools import LocalTools
from .retrieval import Retriever, RetrievalResult, TermRetriever


@dataclass(frozen=True)
class InterpretedRequest:
    action: str
    arguments: Dict[str, str]


ToolResult = Union[List[Document], List[RetrievalResult], Employee, Customer, Ticket, None]


@dataclass(frozen=True)
class AgentResult:
    requesting_user: User
    action: str
    tool_invoked: str
    tool_result: ToolResult


def interpret_request(request: str) -> InterpretedRequest:
    """Parse one explicit command; command words are case-insensitive.

    Supported forms:
      retrieve context <query>
      search documents <query>
      get employee <id>
      get customer <id>
      create ticket <subject> | <description>

    The first pipe separates ticket fields; later pipes belong to the description.
    Unsupported or malformed requests raise ValueError without invoking a tool.
    """
    text = request.strip()
    for pattern, action, argument in (
        (r"retrieve\s+context\s+(.+)", "retrieve_context", "query"),
        (r"search\s+documents\s+(.+)", "search_documents", "query"),
        (r"get\s+employee\s+(\S+)", "get_employee", "employee_id"),
        (r"get\s+customer\s+(\S+)", "get_customer", "customer_id"),
    ):
        match = re.fullmatch(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return InterpretedRequest(action, {argument: match.group(1)})

    match = re.fullmatch(r"create\s+ticket\s+(.+)", text, flags=re.IGNORECASE | re.DOTALL)
    if match:
        subject, separator, description = match.group(1).partition("|")
        if separator and subject.strip() and description.strip():
            return InterpretedRequest("create_ticket", {
                "subject": subject.strip(), "description": description.strip(),
            })
    raise ValueError("Unsupported or malformed request; use retrieve context, search documents, get employee, "
                     "get customer, or create ticket <subject> | <description>")


class VulnerableAgent:
    """Dispatch requests to existing local tools, intentionally ignoring roles."""

    def __init__(self, tools: LocalTools, retriever: Optional[Retriever] = None) -> None:
        self.tools = tools
        self.retriever = retriever if retriever is not None else TermRetriever(
            tools.environment.documents.values()
        )

    def handle_request(self, user_id: str, request: str) -> AgentResult:
        # Lookup supplies result metadata, not proof of identity or authorization.
        user: Optional[User] = self.tools.environment.users.get(user_id)
        if user is None:
            raise ValueError(f"Unknown user: {user_id}")
        interpreted = interpret_request(request)
        arguments = dict(interpreted.arguments)
        if interpreted.action == "create_ticket":
            arguments["requester_id"] = user.id

        # INTENTIONALLY INSECURE: every role can invoke every tool, and every
        # result is returned intact, including support-only/admin-only documents.
        tool = {
            "retrieve_context": self.retriever.retrieve,
            "search_documents": self.tools.search_documents,
            "get_employee": self.tools.get_employee,
            "get_customer": self.tools.get_customer,
            "create_ticket": self.tools.create_ticket,
        }[interpreted.action]
        result = tool(**arguments)
        return AgentResult(user, interpreted.action, interpreted.action, result)
