"""Deterministic tool validation and resource authorization for the secured path."""

from dataclasses import dataclass
from typing import Optional

from .llm_agent import LLMAgentResult, tool_definitions
from .models import Role


@dataclass(frozen=True)
class ToolDecision:
    allowed: bool
    reason: str
    resource: str
    arguments: Optional[dict] = None


@dataclass(frozen=True)
class ToolDeniedResult(LLMAgentResult):
    denial_reason: str = ''


class ToolPolicy:
    def __init__(self, identity_policy):
        self.identity_policy = identity_policy
        self.environment = identity_policy.environment

    def decide(self, user, name, arguments):
        definitions = {d.name: d for d in tool_definitions()}
        # Do not put unvalidated model strings or argument bodies into events.
        event_tool = name if isinstance(name, str) and name in definitions else 'unknown_tool'
        resource = 'unresolved'

        def decision(allowed, reason, bound=None):
            self.identity_policy.event(user.id, event_tool, resource, allowed, reason)
            return ToolDecision(allowed, reason, resource, bound)

        if event_tool == 'unknown_tool':
            return decision(False, 'unknown_tool')
        if (not isinstance(arguments, dict)
                or set(arguments) != set(definitions[name].parameters['required'])
                or not all(isinstance(v, str) for v in arguments.values())):
            return decision(False, 'invalid_argument_schema')
        args = dict(arguments)
        if name == 'search_documents':
            resource = 'document_corpus'
            return decision(True, 'authorized_document_search', args)
        key, records = {
            'get_employee': ('employee_id', self.environment.employees),
            'get_customer': ('customer_id', self.environment.customers),
            'create_ticket': ('requester_id', {**self.environment.users, **self.environment.customers}),
        }[name]
        if args[key] not in records:
            return decision(False, 'unknown_resource')
        resource = args[key]
        if name == 'get_employee':
            if user.role != Role.ADMIN and resource != user.employee_id:
                return decision(False, 'employee_record_not_self_or_admin')
        elif name == 'get_customer':
            if user.role not in {Role.SUPPORT, Role.ADMIN}:
                return decision(False, 'customer_requires_support_or_admin')
        else:
            if not args['subject'].strip() or not args['description'].strip():
                return decision(False, 'blank_ticket_fields')
            # Layer 1 normalization is preserved: no delegation; attribute to caller.
            args = self.identity_policy.bind_arguments(user, name, args)
            resource = user.id
        return decision(True, 'role_and_resource_grant', args)
