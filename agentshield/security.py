"""Application-side identity and document policy; no model-based decisions."""

from dataclasses import dataclass
from typing import List

from .environment import Environment
from .models import AccessLevel, Role, User
from .retrieval import RetrievalResult, Retriever


@dataclass(frozen=True)
class RequesterContext:
    """Supplied by trusted application code, never constructed from model output.

    This local context is not an authentication service. A future authenticated
    entry point must construct it from its verified principal, not request text.
    """
    user_id: str


@dataclass(frozen=True)
class SecurityEvent:
    event_type: str
    requesting_user: str
    action: str
    resource: str
    decision: str
    reason: str


class AccessDenied(ValueError):
    pass


class AuthorizationPolicy:
    def __init__(self, environment: Environment) -> None:
        self.environment = environment
        self.events: List[SecurityEvent] = []

    def event(self, user_id, action, resource, allowed, reason):
        self.events.append(SecurityEvent('security_decision', user_id, action, resource,
                                         'allow' if allowed else 'deny', reason))

    def resolve(self, context: RequesterContext) -> User:
        user = self.environment.users.get(context.user_id)
        if (user is None or user.id != context.user_id or not isinstance(user.role, Role)
                or user.employee_id not in self.environment.employees):
            self.event(context.user_id, 'resolve_identity', context.user_id, False, 'unknown_or_invalid_identity')
            raise AccessDenied('Unknown or invalid trusted requester')
        self.event(user.id, 'resolve_identity', user.id, True, 'trusted_application_context')
        return user

    def document_allowed(self, user: User, document, action='retrieve_document') -> bool:
        # Check authoritative current metadata, not retriever-supplied labels.
        source = self.environment.documents.get(document.id)
        grants = {
            Role.EMPLOYEE: {AccessLevel.EMPLOYEE},
            Role.SUPPORT: {AccessLevel.EMPLOYEE, AccessLevel.SUPPORT},
            Role.ADMIN: set(AccessLevel),
        }
        valid = (source is not None and source == document
                 and isinstance(source.access_level, AccessLevel) and isinstance(user.role, Role))
        allowed = bool(valid and source.access_level in grants[user.role])
        self.event(user.id, action, document.id, allowed,
                   'role_grant' if allowed else ('access_level_denied' if valid else 'unknown_or_invalid_document'))
        return allowed

    def bind_arguments(self, user: User, tool_name: str, arguments: dict) -> dict:
        bound = dict(arguments)
        if tool_name == 'create_ticket':
            if bound['requester_id'] != user.id:
                self.event(user.id, 'bind_ticket_requester', bound['requester_id'], False, 'requester_substitution_denied')
            bound['requester_id'] = user.id
            self.event(user.id, 'bind_ticket_requester', user.id, True, 'trusted_requester_bound')
        return bound


class AuthorizedRetriever:
    """Filter ranked candidates before context construction; ranking is unchanged."""
    def __init__(self, retriever: Retriever, policy: AuthorizationPolicy, context: RequesterContext):
        self.retriever = retriever
        self.policy = policy
        self.context = context

    def retrieve(self, query: str, limit: int = 3) -> List[RetrievalResult]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError('limit must be a positive integer')
        user = self.policy.resolve(self.context)
        try:
            # Request the local corpus so inaccessible top hits do not starve
            # authorized matches. Filter outside the ranker, then apply limit.
            candidates = self.retriever.retrieve(query, limit=max(limit, len(self.policy.environment.documents)))
            authorized = [hit for hit in candidates if self.policy.document_allowed(user, hit.document)]
            return authorized[:limit]
        except Exception:
            self.policy.event(user.id, 'retrieve_context', 'document_corpus', False, 'retrieval_decision_failed')
            raise  # Fail closed; infrastructure errors remain evaluation errors.
