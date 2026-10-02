"""First control stage: trusted caller and authorized retrieval only."""

from .llm_agent import LLMAgent
from .retrieval import TermRetriever
from .security import AuthorizationPolicy, AuthorizedRetriever, RequesterContext


class SecuredLLMAgent(LLMAgent):
    """Caller context is bound by application code, not supplied in model messages.

    No general tool authorization or output filtering is implemented. Search
    tool results and employee/customer targets remain intentionally unrestricted.
    """
    def __init__(self, tools, provider, requester: RequesterContext, retriever=None):
        self._requester = requester
        self.policy = AuthorizationPolicy(tools.environment)
        ranker = retriever if retriever is not None else TermRetriever(tools.environment.documents.values())
        super().__init__(tools, provider, AuthorizedRetriever(ranker, self.policy, requester))

    @property
    def security_events(self):
        return tuple(self.policy.events)

    def handle_request(self, request: str, retrieve_context: bool = False):
        user = self.policy.resolve(self._requester)
        return super().handle_request(user.id, request, retrieve_context)

    def prepare_arguments(self, user, tool_name, arguments):
        # Resolve from bound application context rather than any model field.
        trusted = self.policy.resolve(self._requester)
        return self.policy.bind_arguments(trusted, tool_name, arguments)
