"""Execution adapters only; no benchmark definitions or security verdicts."""

from dataclasses import asdict

from ..llm_agent import LLMAgentResult
from ..models import Customer, Document, Employee, Ticket
from ..providers import AssistantResponse, ModelRequest, ToolCall
from ..retrieval import RetrievalResult
from ..security import RequesterContext
from ..tool_security import ToolDeniedResult


MODES = ('vulnerable', 'secured_identity_retrieval')


def execute(mode, agent_class, tools, provider, case):
    if mode == 'vulnerable':
        agent = agent_class(tools, provider)
        result = agent.handle_request(case['requesting_user'], case['user_input'], case['retrieve_context'])
        events = []
    elif mode == 'secured_identity_retrieval':
        agent = agent_class(tools, provider, RequesterContext(case['requesting_user']))
        result = agent.handle_request(case['user_input'], case['retrieve_context'])
        events = [asdict(event) for event in agent.security_events]
    else:
        raise ValueError('Unknown execution mode')
    validate_execution(result, provider.requests, tools.environment, case)
    if isinstance(result, ToolDeniedResult):
        if not any(e['decision'] == 'deny' and e['reason'] == result.denial_reason
                   and e['requesting_user'] == case['requesting_user'] for e in events):
            raise ValueError('Tool denial has no application decision evidence')
    return result, events


def validate_execution(result, requests, environment, case):
    """Reject broken executions before applying frozen outcome predicates.

    Empty retrieval lists are valid policy outcomes. Missing result objects,
    mismatched identity, and absent tool outputs are execution failures.
    """
    if not isinstance(result, LLMAgentResult) or len(requests) != 1 or not isinstance(requests[0], ModelRequest):
        raise ValueError('Missing or malformed agent/provider execution')
    request = requests[0]
    user = environment.users[case['requesting_user']]
    if result.requesting_user != user or request.requesting_user != user or result.user_input != case['user_input']:
        raise ValueError('Execution identity/input mismatch')
    for context in (result.retrieved_context, request.retrieved_context):
        if not isinstance(context, tuple) or any(not isinstance(hit, RetrievalResult) for hit in context):
            raise ValueError('Malformed retrieval output')
    response = result.model_response
    if isinstance(response, AssistantResponse):
        if not isinstance(response.text, str) or result.action != 'assistant_response' or result.tool_invoked is not None or result.tool_result is not None:
            raise ValueError('Malformed assistant execution')
    elif isinstance(response, ToolCall):
        if isinstance(result, ToolDeniedResult):
            if (result.action != 'tool_denied' or result.tool_invoked is not None
                    or result.tool_result is not None or not result.denial_reason):
                raise ValueError('Malformed tool denial')
            return
        if result.action != 'tool_call' or result.tool_invoked != response.tool_name:
            raise ValueError('Malformed tool execution')
        value = result.tool_result
        valid = {
            'search_documents': isinstance(value, list) and all(isinstance(d, Document) for d in value),
            'get_employee': isinstance(value, Employee),
            'get_customer': isinstance(value, Customer),
            'create_ticket': isinstance(value, Ticket),
        }.get(result.tool_invoked, False)
        if not valid:
            raise ValueError('Missing or malformed tool output')
    else:
        raise ValueError('Missing or malformed model response')
