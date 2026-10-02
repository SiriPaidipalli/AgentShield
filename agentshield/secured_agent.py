"""Trusted identity, authorized retrieval, and secure tool invocation."""

from .llm_agent import LLMAgent, LLMAgentResult, SYSTEM_INSTRUCTIONS, tool_definitions
from .providers import AssistantResponse, ModelRequest, ToolCall
from .retrieval import TermRetriever
from .security import AuthorizationPolicy, AuthorizedRetriever, RequesterContext
from .tool_security import ToolDeniedResult, ToolPolicy


class SecuredLLMAgent(LLMAgent):
    """Model calls are requests, never authorization. No output DLP is applied."""
    def __init__(self, tools, provider, requester: RequesterContext, retriever=None):
        self._requester = requester
        self.policy = AuthorizationPolicy(tools.environment)
        self.tool_policy = ToolPolicy(self.policy)
        ranker = retriever if retriever is not None else TermRetriever(tools.environment.documents.values())
        super().__init__(tools, provider, AuthorizedRetriever(ranker, self.policy, requester))

    @property
    def security_events(self):
        return tuple(self.policy.events)

    def handle_request(self, request: str, retrieve_context: bool = False):
        user = self.policy.resolve(self._requester)
        context = tuple(self.retriever.retrieve(request)) if retrieve_context else ()
        response = self.provider.respond(ModelRequest(
            SYSTEM_INSTRUCTIONS, request, user, context, tool_definitions()))
        if isinstance(response, AssistantResponse):
            if not isinstance(response.text, str):
                raise ValueError('Assistant response text must be a string')
            return LLMAgentResult(user, request, context, response, 'assistant_response')
        if not isinstance(response, ToolCall):
            raise ValueError('Provider must return AssistantResponse or ToolCall')
        # Resolve again immediately before validating and authorizing execution.
        trusted = self.policy.resolve(self._requester)
        decision = self.tool_policy.decide(trusted, response.tool_name, response.arguments)
        if not decision.allowed:
            return ToolDeniedResult(trusted, request, context, response, 'tool_denied',
                                    denial_reason=decision.reason)
        dispatch = {
            'search_documents': self.tools.search_documents,
            'get_employee': self.tools.get_employee,
            'get_customer': self.tools.get_customer,
            'create_ticket': self.tools.create_ticket,
        }
        result = dispatch[response.tool_name](**decision.arguments)
        if response.tool_name == 'search_documents':
            # Resource-level authorization for search results, not generic output DLP.
            result = [document for document in result if self.policy.document_allowed(trusted, document, action='search_documents')]
        return LLMAgentResult(trusted, request, context, response, 'tool_call', response.tool_name, result)
